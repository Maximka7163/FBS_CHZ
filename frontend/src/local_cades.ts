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

let activationScriptPromise: Promise<void> | null = null;

async function ensureActivationScript(): Promise<void> {
  const target = globalThis as typeof globalThis & { cadesplugin?: unknown };
  if (target.cadesplugin) return;
  if (typeof document === "undefined") {
    throw new Error("CryptoPro Browser activation script недоступен");
  }
  if (!activationScriptPromise) {
    activationScriptPromise = new Promise<void>((resolve, reject) => {
      const existing = document.querySelector<HTMLScriptElement>(
        'script[data-sellari-cadesplugin="true"]',
      );
      if (existing) {
        existing.addEventListener("load", () => resolve(), { once: true });
        existing.addEventListener(
          "error",
          () => reject(new Error("Не удалось загрузить cadesplugin_api.js")),
          { once: true },
        );
        return;
      }
      const script = document.createElement("script");
      script.src = "/cadesplugin_api.js";
      script.async = true;
      script.dataset.sellariCadesplugin = "true";
      script.addEventListener("load", () => resolve(), { once: true });
      script.addEventListener(
        "error",
        () => reject(new Error("Не удалось загрузить cadesplugin_api.js")),
        { once: true },
      );
      document.head.appendChild(script);
    });
  }
  await activationScriptPromise;
}

async function plugin(): Promise<CadesPlugin> {
  await ensureActivationScript();
  const raw = (globalThis as typeof globalThis & { cadesplugin?: unknown })
    .cadesplugin as (CadesPlugin & PromiseLike<unknown>) | undefined;
  if (!raw) throw new Error("CryptoPro Browser plug-in не обнаружен");
  if (typeof raw.then === "function") {
    await raw;
  }
  if (typeof raw.CreateObjectAsync !== "function") {
    throw new Error("CryptoPro Browser plug-in недоступен");
  }
  return raw as CadesPlugin;
}

function normalizedThumbprint(value: unknown): string {
  return String(value ?? "").replace(/\s+/g, "").toUpperCase();
}

export async function detectBrowserCades(): Promise<boolean> {
  try {
    await plugin();
    return true;
  } catch {
    return false;
  }
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

export async function signBrowserAuthChallenge(
  challengeBase64: string,
  certificateThumbprint: string,
): Promise<string> {
  if (!challengeBase64) throw new Error("Пустой challenge Честного знака");
  const cades = await plugin();
  const certificate = await certificateByThumbprint(cades, certificateThumbprint);

  const signer = await cades.CreateObjectAsync("CAdESCOM.CPSigner");
  await signer.propset_Certificate(certificate);
  await signer.propset_CheckCertificate(true);

  const signedData = await cades.CreateObjectAsync("CAdESCOM.CadesSignedData");
  // Exact auth content contract: Bridge returns Base64(UTF8(exact CRPT data)).
  // ContentEncoding must be configured before assigning Content.
  await signedData.propset_ContentEncoding(cades.CADESCOM_BASE64_TO_BINARY ?? 1);
  await signedData.propset_Content(challengeBase64);
  return String(
    await signedData.SignCades(
      signer,
      cades.CADESCOM_CADES_BES ?? 1,
      false,
    ),
  );
}
