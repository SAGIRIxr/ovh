/**
 * 通行证(WebAuthn)浏览器端:把后端给的 JSON 选项转成 navigator.credentials 要的二进制结构,
 * 再把结果转回 JSON 交给后端校验。不引第三方库 —— 就两次 base64url 转换。
 */

function fromB64url(s: string): ArrayBuffer {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function toB64url(buf: ArrayBuffer | null | undefined): string | undefined {
  if (!buf) return undefined;
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** 浏览器支持且在安全上下文(https / localhost)里。用 IP:端口 打开的 http 页面不行 */
export function passkeySupported(): boolean {
  return typeof window !== "undefined" && window.isSecureContext && typeof window.PublicKeyCredential === "function";
}

type Descriptor = { id: string; type: string; transports?: string[] };

export async function createPasskey(options: any): Promise<unknown> {
  const publicKey: PublicKeyCredentialCreationOptions = {
    ...options,
    challenge: fromB64url(options.challenge),
    user: { ...options.user, id: fromB64url(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((c: Descriptor) => ({ ...c, id: fromB64url(c.id) })),
  };
  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error("cancelled");
  const r = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: toB64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: (cred as any).authenticatorAttachment ?? undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: toB64url(r.clientDataJSON),
      attestationObject: toB64url(r.attestationObject),
      transports: typeof r.getTransports === "function" ? r.getTransports() : undefined,
    },
  };
}

export async function getPasskey(options: any): Promise<unknown> {
  const publicKey: PublicKeyCredentialRequestOptions = {
    ...options,
    challenge: fromB64url(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((c: Descriptor) => ({ ...c, id: fromB64url(c.id) })),
  };
  const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error("cancelled");
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: toB64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: (cred as any).authenticatorAttachment ?? undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: toB64url(r.clientDataJSON),
      authenticatorData: toB64url(r.authenticatorData),
      signature: toB64url(r.signature),
      userHandle: toB64url(r.userHandle),
    },
  };
}

/** 用户在系统弹窗里点了取消 / 超时:不当成错误刷红字 */
export function isPasskeyCancel(e: unknown): boolean {
  const name = (e as any)?.name;
  return name === "NotAllowedError" || name === "AbortError" || (e as any)?.message === "cancelled";
}
