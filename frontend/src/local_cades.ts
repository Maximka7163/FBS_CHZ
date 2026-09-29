import { completeLocalBrowserAuth, prepareLocalBrowserAuth } from "./api.ts";
import type { LocalBrowserAuthComplete, LocalBrowserAuthPrepare } from "./types.ts";

export interface BrowserCadesCertificate {
  thumbprint: string;
  subject: string;
  validTo: string | null;
}

type AsyncCadesObject = Record<string, any>;
type CadesPlugin = AsyncCadesObject & {
  CreateObjectAsync(name: string): Promise<AsyncCadesObject>;
  CAPICOM_CURRENT_USER_STORE?: number;
  CAPICOM_MY_STORE?: string;
  CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED?: number;
  CADESCOM_BASE64_TO_BINARY?: number;
  CADESCOM_CADES_BES?: number;
};

type CadesPluginGlobal = CadesPlugin & {
  then?: (
    onfulfilled?: ((value?: unknown) => unknown) | null,
    onrejected?: ((reason?: unknown) => unknown) | null,
  ) => unknown;
};

function nonThenableFacade(raw: CadesPluginGlobal): CadesPlugin {
  // Never let the official Promise-like cadesplugin escape from an async
  // function. Promise resolution would assimilate raw.then and the resolved
  // value may be undefined. Keep CreateObjectAsync bound to the actual global
  // object because the CryptoPro wrapper may depend on its receiver.
  return {
    CreateObjectAsync: raw.CreateObjectAsync.bind(raw),
    CAPICOM_CURRENT_USER_STORE: raw.CAPICOM_CURRENT_USER_STORE,
    CAPICOM_MY_STORE: raw.CAPICOM_MY_STORE,
    CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED: raw.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED,
    CADESCOM_BASE64_TO_BINARY: raw.CADESCOM_BASE64_TO_BINARY,
    CADESCOM_CADES_BES: raw.CADESCOM_CADES_BES,
  };
}

export type BrowserCadesErrorCode =
  | "SCRIPT_NOT_LOADED"
  | "PLUGIN_INIT_FAILED"
  | "CREATE_OBJECT_UNAVAILABLE";

export class BrowserCadesError extends Error {
  readonly code: BrowserCadesErrorCode;

  constructor(code: BrowserCadesErrorCode, message: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "BrowserCadesError";
    this.code = code;
  }
}

export interface BrowserCadesDiagnostics {
  globalPresent: boolean;
  globalType: string;
  activationScriptState:
    | "NO_DOCUMENT"
    | "NOT_IN_DOM"
    | "LOADING"
    | "LOADED"
    | "ERROR"
    | "GLOBAL_PRESENT";
  createObjectAsyncType: string;
  lastErrorCode: BrowserCadesErrorCode | null;
  lastErrorMessage: string | null;
  lastErrorStack: string | null;
}

export interface BrowserCadesProbe {
  ready: boolean;
  errorCode: BrowserCadesErrorCode | null;
  message: string | null;
  diagnostics: BrowserCadesDiagnostics;
}

const PLUGIN_INIT_TIMEOUT_MS = 20000;
const CREATE_OBJECT_RETRY_MS = 1500;
let activationScriptPromise: Promise<void> | null = null;
let lastBrowserCadesError: BrowserCadesError | null = null;

function activationScriptState(): BrowserCadesDiagnostics["activationScriptState"] {
  const target = globalThis as typeof globalThis & { cadesplugin?: unknown };
  if (typeof document === "undefined") return "NO_DOCUMENT";
  const script = document.querySelector<HTMLScriptElement>(
    'script[data-sellari-cadesplugin="true"]',
  );
  if (!script) return target.cadesplugin ? "GLOBAL_PRESENT" : "NOT_IN_DOM";
  const state = script.dataset.sellariCadespluginState;
  if (state === "loaded") return "LOADED";
  if (state === "error") return "ERROR";
  return target.cadesplugin ? "GLOBAL_PRESENT" : "LOADING";
}

export function getBrowserCadesDiagnostics(): BrowserCadesDiagnostics {
  const raw = (globalThis as typeof globalThis & { cadesplugin?: unknown }).cadesplugin;
  const createObjectAsync = raw && (typeof raw === "object" || typeof raw === "function")
    ? (raw as Record<string, unknown>).CreateObjectAsync
    : undefined;
  return {
    globalPresent: raw !== undefined && raw !== null,
    globalType: typeof raw,
    activationScriptState: activationScriptState(),
    createObjectAsyncType: typeof createObjectAsync,
    lastErrorCode: lastBrowserCadesError?.code ?? null,
    lastErrorMessage: lastBrowserCadesError?.message ?? null,
    lastErrorStack: lastBrowserCadesError?.stack ?? null,
  };
}

function withTimeout<T>(
  promise: Promise<T>,
  code: BrowserCadesErrorCode,
  message: string,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = globalThis.setTimeout(
      () => reject(new BrowserCadesError(code, message)),
      PLUGIN_INIT_TIMEOUT_MS,
    );
    promise.then(
      (value) => {
        globalThis.clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        globalThis.clearTimeout(timer);
        reject(error);
      },
    );
  });
}

async function ensureActivationScript(): Promise<void> {
  const target = globalThis as typeof globalThis & { cadesplugin?: unknown };
  if (target.cadesplugin) return;
  if (typeof document === "undefined") {
    throw new BrowserCadesError(
      "SCRIPT_NOT_LOADED",
      "CryptoPro cadesplugin_api.js недоступен",
    );
  }
  if (!activationScriptPromise) {
    activationScriptPromise = new Promise<void>((resolve, reject) => {
      const existing = document.querySelector<HTMLScriptElement>(
        'script[data-sellari-cadesplugin="true"]',
      );
      const onLoad = () => {
        if (existing) existing.dataset.sellariCadespluginState = "loaded";
        if (target.cadesplugin) resolve();
        else reject(
          new BrowserCadesError(
            "PLUGIN_INIT_FAILED",
            "cadesplugin_api.js загружен, но globalThis.cadesplugin не создан",
          ),
        );
      };
      const onError = () => {
        if (existing) existing.dataset.sellariCadespluginState = "error";
        reject(
          new BrowserCadesError(
            "SCRIPT_NOT_LOADED",
            "Не удалось загрузить cadesplugin_api.js",
          ),
        );
      };
      if (existing) {
        existing.addEventListener("load", onLoad, { once: true });
        existing.addEventListener("error", onError, { once: true });
        return;
      }
      const script = document.createElement("script");
      script.src = "/cadesplugin_api.js";
      script.async = true;
      script.dataset.sellariCadesplugin = "true";
      script.dataset.sellariCadespluginState = "loading";
      script.addEventListener("load", () => {
        script.dataset.sellariCadespluginState = "loaded";
        onLoad();
      }, { once: true });
      script.addEventListener("error", () => {
        script.dataset.sellariCadespluginState = "error";
        onError();
      }, { once: true });
      document.head.appendChild(script);
    });
  }
  try {
    await withTimeout(
      activationScriptPromise,
      "SCRIPT_NOT_LOADED",
      "Таймаут загрузки cadesplugin_api.js",
    );
  } catch (error) {
    activationScriptPromise = null;
    if (error instanceof BrowserCadesError) throw error;
    throw new BrowserCadesError(
      "SCRIPT_NOT_LOADED",
      "Не удалось загрузить cadesplugin_api.js",
      error,
    );
  }
}

async function plugin(): Promise<CadesPlugin> {
  await ensureActivationScript();
  const raw = (globalThis as typeof globalThis & { cadesplugin?: unknown })
    .cadesplugin as CadesPluginGlobal | undefined;
  if (!raw) {
    throw new BrowserCadesError(
      "PLUGIN_INIT_FAILED",
      "CryptoPro Browser plug-in не обнаружен",
    );
  }

  // Official cadesplugin_api.js exposes window.cadesplugin as a thenable whose
  // methods remain on the global object. Ignore the resolved value entirely:
  // it may be undefined and is not the API object.
  if (typeof raw.then === "function") {
    try {
      await withTimeout(
        new Promise<void>((resolve, reject) => {
          raw.then?.(() => resolve(), (reason) => reject(reason));
        }),
        "PLUGIN_INIT_FAILED",
        "Таймаут инициализации CryptoPro Browser plug-in",
      );
    } catch (error) {
      if (error instanceof BrowserCadesError) throw error;
      throw new BrowserCadesError(
        "PLUGIN_INIT_FAILED",
        "CryptoPro Browser plug-in не инициализирован",
        error,
      );
    }
  }

  if (typeof raw.CreateObjectAsync !== "function") {
    throw new BrowserCadesError(
      "CREATE_OBJECT_UNAVAILABLE",
      "CryptoPro CreateObjectAsync недоступен",
    );
  }

  // Method presence alone is insufficient: in Chromium/Yandex the wrapper can
  // exist while its internal native extension object is still being attached.
  // Retry an inert About object for a bounded interval; this closes the
  // pluginObject handshake race without signing or touching private keys.
  const deadline = Date.now() + CREATE_OBJECT_RETRY_MS;
  let lastCreateError: unknown = null;
  while (Date.now() < deadline) {
    try {
      await Promise.resolve(raw.CreateObjectAsync("CAdESCOM.About"));
      return nonThenableFacade(raw);
    } catch (error) {
      lastCreateError = error;
      await new Promise<void>((resolve) => globalThis.setTimeout(resolve, 100));
    }
  }
  throw new BrowserCadesError(
    "CREATE_OBJECT_UNAVAILABLE",
    "CryptoPro native object недоступен для CreateObjectAsync",
    lastCreateError,
  );
}

export async function probeBrowserCades(): Promise<BrowserCadesProbe> {
  try {
    await plugin();
    lastBrowserCadesError = null;
    return {
      ready: true,
      errorCode: null,
      message: null,
      diagnostics: getBrowserCadesDiagnostics(),
    };
  } catch (error) {
    lastBrowserCadesError = error instanceof BrowserCadesError
      ? error
      : new BrowserCadesError(
          "PLUGIN_INIT_FAILED",
          error instanceof Error ? error.message : String(error),
          error,
        );
    return {
      ready: false,
      errorCode: lastBrowserCadesError.code,
      message: lastBrowserCadesError.message,
      diagnostics: getBrowserCadesDiagnostics(),
    };
  }
}

export async function detectBrowserCades(): Promise<boolean> {
  return (await probeBrowserCades()).ready;
}

// Test seam only: not used by application code and does not expose signing.
// It proves the async initializer returns a real non-thenable API facade.
export async function __testBrowserCadesApi(): Promise<CadesPlugin> {
  return plugin();
}

function normalizedThumbprint(value: unknown): string {
  return String(value ?? "").replace(/\s+/g, "").toUpperCase();
}

export async function enumerateBrowserCertificates(): Promise<BrowserCadesCertificate[]> {
  const cades = await plugin();
  const store = await cades.CreateObjectAsync("CAPICOM.Store");
  await store.Open(
    cades.CAPICOM_CURRENT_USER_STORE ?? 2,
    cades.CAPICOM_MY_STORE ?? "My",
    cades.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED ?? 2,
  );
  try {
    const certificates = await store.Certificates;
    const count = Number(await certificates.Count);
    const result: BrowserCadesCertificate[] = [];
    for (let index = 1; index <= count; index += 1) {
      const certificate = await certificates.Item(index);
      const thumbprint = normalizedThumbprint(await certificate.Thumbprint);
      if (!thumbprint) continue;
      const validToRaw = await certificate.ValidToDate;
      result.push({
        thumbprint,
        subject: String((await certificate.SubjectName) ?? ""),
        validTo: validToRaw ? new Date(validToRaw).toISOString() : null,
      });
    }
    return result;
  } finally {
    await store.Close();
  }
}

async function certificateByThumbprint(
  cades: CadesPlugin,
  thumbprint: string,
): Promise<AsyncCadesObject> {
  const store = await cades.CreateObjectAsync("CAPICOM.Store");
  await store.Open(
    cades.CAPICOM_CURRENT_USER_STORE ?? 2,
    cades.CAPICOM_MY_STORE ?? "My",
    cades.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED ?? 2,
  );
  try {
    const certificates = await store.Certificates;
    const count = Number(await certificates.Count);
    const wanted = normalizedThumbprint(thumbprint);
    for (let index = 1; index <= count; index += 1) {
      const certificate = await certificates.Item(index);
      if (normalizedThumbprint(await certificate.Thumbprint) === wanted) {
        return certificate;
      }
    }
  } finally {
    await store.Close();
  }
  throw new Error("Выбранный сертификат не найден в CurrentUser/My");
}

function validatePreparedAttempt(prepared: LocalBrowserAuthPrepare): void {
  if (
    !prepared
    || prepared.read_only !== true
    || !prepared.attempt_id
    || !prepared.challenge_base64
    || !prepared.participant_inn
    || !prepared.expires_at
  ) {
    throw new Error("Некорректная typed auth-попытка Честного знака");
  }
}

async function signPreparedAuthAttempt(
  prepared: LocalBrowserAuthPrepare,
  certificateThumbprint: string,
): Promise<string> {
  validatePreparedAttempt(prepared);
  const cades = await plugin();
  const certificate = await certificateByThumbprint(cades, certificateThumbprint);

  const signer = await cades.CreateObjectAsync("CAdESCOM.CPSigner");
  await signer.propset_Certificate(certificate);
  await signer.propset_CheckCertificate(true);

  const signedData = await cades.CreateObjectAsync("CAdESCOM.CadesSignedData");
  // Typed auth only: prepared.challenge_base64 is Base64(UTF8(exact CRPT data)).
  // ContentEncoding must be configured before assigning Content.
  await signedData.propset_ContentEncoding(cades.CADESCOM_BASE64_TO_BINARY ?? 1);
  await signedData.propset_Content(prepared.challenge_base64);
  return String(
    await signedData.SignCades(
      signer,
      cades.CADESCOM_CADES_BES ?? 1,
      false,
    ),
  );
}

export async function authenticateLocalBrowserCades(
  certificateThumbprint: string,
): Promise<LocalBrowserAuthComplete> {
  // There is intentionally no exported sign(bytes/base64, certificate) API.
  // Signing is reachable only from this prepare -> sign -> immediate complete
  // orchestration for one typed backend auth attempt.
  const prepared = await prepareLocalBrowserAuth();
  validatePreparedAttempt(prepared);
  const signatureBase64 = await signPreparedAuthAttempt(
    prepared,
    certificateThumbprint,
  );
  return completeLocalBrowserAuth(
    prepared.attempt_id,
    signatureBase64,
    certificateThumbprint,
  );
}
