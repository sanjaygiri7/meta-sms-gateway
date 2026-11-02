/**
 * HMAC-SHA256 verification, identical to Android (Signing.java).
 *
 * Canonical string, five lines joined by "\n", no trailing newline:
 *   POST
 *   /sms/meta
 *   TIMESTAMP
 *   NONCE
 *   SHA256_HEX_OF_EXACT_RAW_JSON_BODY
 *
 * The secret is provisioned as a Worker secret. It is interpreted, in order,
 * as 64-char hex (32 bytes), base64 of 32 bytes (the form the Android app
 * displays for provisioning), or UTF-8 text as a fallback. The same secret
 * value must be used on both sides; only its encoding may differ.
 * Never log the secret, headers, body or code.
 */

const te = new TextEncoder();

export function decodeSecret(secretText: string): Uint8Array {
  const trimmed = secretText.trim();
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) out[i] = parseInt(trimmed.slice(i * 2, i * 2 + 2), 16);
    return out;
  }
  try {
    const bin = atob(trimmed);
    if (bin.length === 32) {
      const out = new Uint8Array(32);
      for (let i = 0; i < 32; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
  } catch {
    // Fall through to UTF-8.
  }
  return te.encode(trimmed);
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return toHex(new Uint8Array(digest));
}

export async function hmacHex(secret: Uint8Array, data: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    secret as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, data as BufferSource);
  return toHex(new Uint8Array(sig));
}

export function canonicalString(
  timestamp: string,
  nonce: string,
  bodySha256Hex: string,
): string {
  return `POST\n/sms/meta\n${timestamp}\n${nonce}\n${bodySha256Hex}`;
}

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Constant-time comparison of two hex signature strings. */
export function signaturesEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function tokensEqual(a: string, b: string): boolean {
  const ab = te.encode(a);
  const bb = te.encode(b);
  if (ab.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= ab[i] ^ bb[i];
  return diff === 0;
}

export interface VerifiedHeaders {
  deviceId: string;
  timestamp: string;
  nonce: string;
}

/**
 * Verifies device ID, timestamp freshness (120s), nonce format and the HMAC
 * against the exact raw body bytes. Returns null on any failure.
 * Nonce uniqueness and event deduplication are checked separately in the
 * Durable Object, which is the only place that can do them atomically.
 */
export async function verifyHeaders(
  rawBody: Uint8Array,
  headers: Headers,
  env: { SMS_HMAC_SECRET?: string; EXPECTED_DEVICE_ID?: string },
  nowSeconds: number,
): Promise<VerifiedHeaders | null> {
  const deviceId = headers.get("X-Device-Id");
  const timestamp = headers.get("X-Timestamp");
  const nonce = headers.get("X-Nonce");
  const signature = headers.get("X-Signature");
  if (!deviceId || !timestamp || !nonce || !signature) return null;
  if (!env.EXPECTED_DEVICE_ID || deviceId !== env.EXPECTED_DEVICE_ID) return null;
  if (!env.SMS_HMAC_SECRET) return null;
  if (!/^\d+$/.test(timestamp)) return null;
  const ts = Number(timestamp);
  if (!Number.isSafeInteger(ts)) return null;
  if (Math.abs(nowSeconds - ts) > 120) return null;
  if (nonce.length === 0 || nonce.length > 128) return null;
  if (!/^[0-9a-f]{64}$/.test(signature)) return null;
  const bodyHash = await sha256Hex(rawBody);
  const canonical = canonicalString(timestamp, nonce, bodyHash);
  const expected = await hmacHex(decodeSecret(env.SMS_HMAC_SECRET), te.encode(canonical));
  if (!signaturesEqual(expected, signature)) return null;
  return { deviceId, timestamp, nonce };
}
