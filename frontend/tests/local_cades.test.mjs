import test from "node:test";
import assert from "node:assert/strict";

import {
  authenticateLocalBrowserCades,
  detectBrowserCades,
  enumerateBrowserCertificates,
} from "../src/local_cades.ts";

function installPlugin(log) {
  const certificate = {
    Thumbprint: "AA BB CC",
    SubjectName: "CN=Test, INN=1234567890",
    ValidToDate: "2027-01-01T00:00:00Z",
  };
  const certificates = {
    Count: 1,
    async Item(index) {
      assert.equal(index, 1);
      return certificate;
    },
  };
  const store = {
    Certificates: certificates,
    async Open(...args) {
      log.push(["Open", ...args]);
    },
    async Close() {
      log.push(["Close"]);
    },
  };
  const signer = {
    async propset_Certificate(value) {
      assert.equal(value, certificate);
      log.push(["Certificate"]);
    },
    async propset_CheckCertificate(value) {
      log.push(["CheckCertificate", value]);
    },
  };
  const signedData = {
    async propset_ContentEncoding(value) {
      log.push(["ContentEncoding", value]);
    },
    async propset_Content(value) {
      log.push(["Content", value]);
    },
    async SignCades(...args) {
      log.push(["SignCades", ...args.slice(1)]);
      return "ATTACHED-CADES-BES";
    },
  };

  globalThis.cadesplugin = {
    CAPICOM_CURRENT_USER_STORE: 2,
    CAPICOM_MY_STORE: "My",
    CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED: 2,
    CADESCOM_BASE64_TO_BINARY: 1,
    CADESCOM_CADES_BES: 1,
    async CreateObjectAsync(name) {
      log.push(["CreateObjectAsync", name]);
      if (name === "CAPICOM.Store") return store;
      if (name === "CAdESCOM.CPSigner") return signer;
      if (name === "CAdESCOM.CadesSignedData") return signedData;
      throw new Error("unexpected object " + name);
    },
  };
}

test("Browser CAdES plugin detection and certificate enumeration use CurrentUser/My", async () => {
  const log = [];
  installPlugin(log);

  assert.equal(await detectBrowserCades(), true);
  const certs = await enumerateBrowserCertificates();

  assert.equal(certs.length, 1);
  assert.equal(certs[0].thumbprint, "AABBCC");
  assert.equal(certs[0].subject, "CN=Test, INN=1234567890");
  assert.ok(log.some((entry) => entry[0] === "Open" && entry[1] === 2 && entry[2] === "My"));
});

test("typed Browser auth signs only prepared challenge and immediately completes it", async (t) => {
  const log = [];
  installPlugin(log);
  const challengeBase64 = "IEVYQUNULURBVEEK0K7QvdC40LrQvtC0IA==";
  const fetchCalls = [];
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async (url, init = {}) => {
    fetchCalls.push([String(url), init]);
    if (url === "/api/auth/csrf") {
      return { ok: true, status: 200, json: async () => ({ csrf_token: "csrf-browser-cades" }) };
    }
    if (url === "/api/local/auth/prepare") {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          attempt_id: "attempt-typed-123456",
          challenge_base64: challengeBase64,
          participant_inn: "1234567890",
          expires_at: "2026-09-27T20:00:00+00:00",
          read_only: true,
        }),
      };
    }
    if (url === "/api/local/auth/complete") {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          authenticated: true,
          expire_date: "2026-09-27T21:00:00+00:00",
          read_only: true,
          business_write_enabled: false,
        }),
      };
    }
    throw new Error("unexpected fetch " + url);
  };
  t.after(() => { globalThis.fetch = originalFetch; });

  const result = await authenticateLocalBrowserCades("AA BB CC");

  assert.equal(result.authenticated, true);
  const encodingIndex = log.findIndex((entry) => entry[0] === "ContentEncoding");
  const contentIndex = log.findIndex((entry) => entry[0] === "Content");
  assert.ok(encodingIndex >= 0);
  assert.ok(contentIndex > encodingIndex);
  assert.deepEqual(log[encodingIndex], ["ContentEncoding", 1]);
  assert.deepEqual(log[contentIndex], ["Content", challengeBase64]);

  const sign = log.find((entry) => entry[0] === "SignCades");
  assert.deepEqual(sign, ["SignCades", 1, false]);
  assert.ok(log.some((entry) => entry[0] === "CheckCertificate" && entry[1] === true));

  const complete = fetchCalls.find(([url]) => url === "/api/local/auth/complete");
  assert.ok(complete);
  const completeBody = JSON.parse(complete[1].body);
  assert.deepEqual(completeBody, {
    attempt_id: "attempt-typed-123456",
    signature_base64: "ATTACHED-CADES-BES",
    selected_certificate_thumbprint: "AA BB CC",
  });
  assert.equal("participant_inn" in completeBody, false);
  assert.equal("challenge_base64" in completeBody, false);
});

test("Browser auth exposes no public arbitrary-content signer primitive", async () => {
  const source = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../src/local_cades.ts", import.meta.url), "utf8"),
  );
  assert.equal(source.includes("export async function signBrowserAuthChallenge"), false);
  assert.equal(source.includes("signBrowserAuthChallenge("), false);
  assert.equal(/export\s+(?:async\s+)?function\s+sign/i.test(source), false);
  assert.equal(source.includes("signBytes"), false);
  assert.equal(source.includes("signFile"), false);
  assert.equal(source.includes("CachePin"), false);
  assert.equal(source.includes("function signPreparedAuthAttempt"), true);
  assert.equal(source.includes("export async function authenticateLocalBrowserCades"), true);

  const mainSource = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../src/main.ts", import.meta.url), "utf8"),
  );
  assert.equal(mainSource.includes("prepareLocalBrowserAuth"), false);
  assert.equal(mainSource.includes("completeLocalBrowserAuth"), false);
  assert.equal(mainSource.includes("authenticateLocalBrowserCades"), true);
});

test("local Browser auth never persists token/signature state in web storage", async () => {
  const fs = await import("node:fs/promises");
  const apiSource = await fs.readFile(new URL("../src/api.ts", import.meta.url), "utf8");
  const mainSource = await fs.readFile(new URL("../src/main.ts", import.meta.url), "utf8");
  const cadesSource = await fs.readFile(new URL("../src/local_cades.ts", import.meta.url), "utf8");
  const authSource = apiSource + "\n" + mainSource + "\n" + cadesSource;
  assert.equal(authSource.includes("localStorage"), false);
  assert.equal(authSource.includes("sessionStorage"), false);
  assert.equal(apiSource.includes("uuidToken"), false);
  assert.equal(apiSource.includes("uuid_token"), false);
});
