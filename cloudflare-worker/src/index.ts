import { accepts, extractCode, parseAllowlist } from "./filter";
import { verifyHeaders, tokensEqual } from "./verify";
import { MetaInbox } from "./inbox";

export { MetaInbox };

export interface Env {
  SMS_HMAC_SECRET: string;
  SMS_READ_TOKEN: string;
  EXPECTED_DEVICE_ID: string;
  META_ALLOWED_SENDER_IDS: string;
  META_INBOX: DurableObjectNamespace;
}

const MAX_BODY_BYTES = 4096;
const OTP_TTL_SECONDS = 300;
const NO_STORE = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };

function jsonError(status: number, error: string): Response {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { "Content-Type": "application/json", ...NO_STORE },
  });
}

function inboxStub(env: Env) {
  return env.META_INBOX.get(env.META_INBOX.idFromName("meta-inbox"));
}

async function handleSms(request: Request, env: Env): Promise<Response> {
  const contentType = request.headers.get("Content-Type") || "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    return jsonError(400, "bad_request");
  }
  const lengthHeader = request.headers.get("Content-Length");
  if (lengthHeader && Number(lengthHeader) > MAX_BODY_BYTES) {
    return jsonError(413, "too_large");
  }
  const raw = new Uint8Array(await request.arrayBuffer());
  if (raw.length > MAX_BODY_BYTES) {
    return jsonError(413, "too_large");
  }
  const nowSeconds = Math.floor(Date.now() / 1000);
  const verified = await verifyHeaders(raw, request.headers, env, nowSeconds);
  if (!verified) {
    return jsonError(401, "unauthorized");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(raw));
  } catch {
    return jsonError(400, "bad_request");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return jsonError(400, "bad_request");
  }
  const obj = parsed as Record<string, unknown>;
  const allowedKeys = new Set(["version", "eventId", "sender", "body", "receivedAt"]);
  for (const key of Object.keys(obj)) {
    if (!allowedKeys.has(key)) return jsonError(400, "bad_request");
  }
  if (
    obj.version !== 1 ||
    typeof obj.eventId !== "string" ||
    obj.eventId.length === 0 ||
    obj.eventId.length > 128 ||
    typeof obj.sender !== "string" ||
    obj.sender.length === 0 ||
    obj.sender.length > 128 ||
    typeof obj.body !== "string" ||
    obj.body.length === 0 ||
    typeof obj.receivedAt !== "string" ||
    Number.isNaN(Date.parse(obj.receivedAt))
  ) {
    return jsonError(400, "bad_request");
  }

  // Independent filtering on the Worker. Never trust the Android filter alone.
  const allowlist = parseAllowlist(env.META_ALLOWED_SENDER_IDS);
  const code = accepts(allowlist, obj.sender, obj.body)
    ? extractCode(obj.body)
    : null;
  if (code === null) {
    // Authenticated but not an approved Meta code: discard, permanent, no OTP.
    return jsonError(400, "bad_request");
  }

  const expiresAt = nowSeconds + OTP_TTL_SECONDS;
  let reserve: Response;
  try {
    reserve = await inboxStub(env).fetch(
      new Request("http://inbox/reserve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          nonce: verified.nonce,
          eventId: obj.eventId,
          code,
          expiresAt,
          now: nowSeconds,
        }),
      }),
    );
  } catch {
    return jsonError(502, "bad_gateway");
  }
  if (!reserve.ok) {
    return jsonError(502, "bad_gateway");
  }
  const result = (await reserve.json()) as { status?: string };
  if (result.status === "replay") {
    return jsonError(409, "nonce_replay");
  }
  if (result.status === "duplicate") {
    // Safely discarded duplicate event: no second OTP is created.
    return new Response(null, { status: 204, headers: { ...NO_STORE } });
  }
  if (result.status !== "stored") {
    return jsonError(502, "bad_gateway");
  }
  // The OTP is never returned in a POST response.
  return new Response(null, { status: 204, headers: { ...NO_STORE } });
}

async function handleLatest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  // Never accept a token in a query string.
  for (const key of url.searchParams.keys()) {
    if (["token", "auth", "access_token", "sms_read_token"].includes(key.toLowerCase())) {
      return jsonError(401, "unauthorized");
    }
  }
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ") || !env.SMS_READ_TOKEN) {
    return jsonError(401, "unauthorized");
  }
  if (!tokensEqual(auth.slice("Bearer ".length), env.SMS_READ_TOKEN)) {
    return jsonError(401, "unauthorized");
  }
  let consumed: Response;
  try {
    consumed = await inboxStub(env).fetch(
      new Request("http://inbox/consume", { method: "POST" }),
    );
  } catch {
    return jsonError(502, "bad_gateway");
  }
  if (consumed.status === 404) {
    return jsonError(404, "no_valid_code");
  }
  if (!consumed.ok) {
    return jsonError(502, "bad_gateway");
  }
  const data = (await consumed.json()) as { code: string; expiresAt: number };
  return new Response(JSON.stringify({ code: data.code, expiresAt: data.expiresAt }), {
    status: 200,
    headers: { "Content-Type": "application/json", ...NO_STORE },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/sms/meta") {
      if (request.method !== "POST") return jsonError(405, "method_not_allowed");
      return handleSms(request, env);
    }
    if (url.pathname === "/latest") {
      if (request.method !== "GET") return jsonError(405, "method_not_allowed");
      return handleLatest(request, env);
    }
    return jsonError(404, "not_found");
  },
};
