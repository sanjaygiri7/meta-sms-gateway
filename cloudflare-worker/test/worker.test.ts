import { describe, expect, it } from "vitest";
import worker, { type Env } from "../src/index";
import { MetaInbox, type InboxStorage } from "../src/inbox";
import { canonicalString, hmacHex, sha256Hex } from "../src/verify";

const te = new TextEncoder();

class MemoryStorage implements InboxStorage {
  map = new Map<string, unknown>();
  async get(key: string) {
    return this.map.get(key);
  }
  async put(key: string, value: unknown) {
    this.map.set(key, value);
  }
  async delete(key: string) {
    return this.map.delete(key);
  }
  async list(options?: { prefix?: string }) {
    const out = new Map<string, unknown>();
    for (const [k, v] of this.map) {
      if (!options?.prefix || k.startsWith(options.prefix)) out.set(k, v);
    }
    return out;
  }
}

const SECRET_BYTES = new Uint8Array(32);
for (let i = 0; i < 32; i++) SECRET_BYTES[i] = i;
const SECRET_BASE64 = btoa(String.fromCharCode(...SECRET_BYTES));

function makeEnv(): Env {
  const inbox = new MetaInbox({ storage: new MemoryStorage() });
  const stub = { fetch: (req: Request) => inbox.fetch(req) };
  const ns = {
    idFromName: (_name: string) => "meta-inbox",
    get: (_id: unknown) => stub,
  } as unknown as DurableObjectNamespace;
  return {
    SMS_HMAC_SECRET: SECRET_BASE64,
    SMS_READ_TOKEN: "read-token-for-tests-only",
    EXPECTED_DEVICE_ID: "device-1",
    META_ALLOWED_SENDER_IDS: "META",
    META_INBOX: ns,
  };
}

async function sign(
  body: Uint8Array,
  opts: { deviceId?: string; ts?: number; nonce?: string; secret?: Uint8Array } = {},
): Promise<Headers> {
  const ts = String(opts.ts ?? Math.floor(Date.now() / 1000));
  const nonce = opts.nonce ?? "test-nonce-1";
  const bodyHash = await sha256Hex(body);
  const sig = await hmacHex(opts.secret ?? SECRET_BYTES, te.encode(canonicalString(ts, nonce, bodyHash)));
  const h = new Headers({ "Content-Type": "application/json" });
  h.set("X-Device-Id", opts.deviceId ?? "device-1");
  h.set("X-Timestamp", ts);
  h.set("X-Nonce", nonce);
  h.set("X-Signature", sig);
  return h;
}

function smsBody(eventId = "e1", sender = "META", body = "116018 is your Meta confirmation code."): Uint8Array {
  return te.encode(
    JSON.stringify({ version: 1, eventId, sender, body, receivedAt: new Date().toISOString() }),
  );
}

async function postSms(env: Env, raw: Uint8Array, headers: Headers): Promise<Response> {
  return worker.fetch(
    new Request("https://example.workers.dev/sms/meta", {
      method: "POST",
      headers,
      body: raw as unknown as BodyInit,
    }),
    env,
  );
}

async function getLatest(env: Env, token = "read-token-for-tests-only"): Promise<Response> {
  return worker.fetch(
    new Request("https://example.workers.dev/latest", {
      headers: { Authorization: `Bearer ${token}` },
    }),
    env,
  );
}

describe("Worker endpoints", () => {
  it("accepts an approved Meta code with 204 and no OTP in the response", async () => {
    const env = makeEnv();
    const raw = smsBody();
    const res = await postSms(env, raw, await sign(raw));
    expect(res.status).toBe(204);
    expect(await res.text()).toBe("");
  });

  it("valid authenticated retrieval returns the code once, then deletes it", async () => {
    const env = makeEnv();
    const raw = smsBody();
    expect((await postSms(env, raw, await sign(raw))).status).toBe(204);
    const first = await getLatest(env);
    expect(first.status).toBe(200);
    expect(first.headers.get("Cache-Control")).toBe("no-store");
    expect(await first.json()).toMatchObject({ code: "116018" });
    const second = await getLatest(env);
    expect(second.status).toBe(404);
  });

  it("retrieval without a read token is rejected", async () => {
    const env = makeEnv();
    const res = await worker.fetch(new Request("https://example.workers.dev/latest"), env);
    expect(res.status).toBe(401);
    const withQuery = await worker.fetch(
      new Request("https://example.workers.dev/latest?token=read-token-for-tests-only", {
        headers: { Authorization: "Bearer read-token-for-tests-only" },
      }),
      env,
    );
    expect(withQuery.status).toBe(401);
  });

  it("unknown sender, unrelated body and empty allowlist are rejected", async () => {
    const env = makeEnv();
    const unknown = smsBody("e1", "OTHER");
    expect((await postSms(env, unknown, await sign(unknown))).status).toBe(400);
    const unrelated = smsBody("e2", "META", "Your OTP is 116018.");
    const unrelatedRes = await postSms(env, unrelated, await sign(unrelated, { nonce: "n-unrelated-2" }));
    expect(unrelatedRes.status).toBe(400);
    const emptyEnv = makeEnv();
    emptyEnv.META_ALLOWED_SENDER_IDS = "";
    const raw = smsBody("e3");
    const emptyRes = await postSms(emptyEnv, raw, await sign(raw, { nonce: "n-empty-2" }));
    expect(emptyRes.status).toBe(400);
  });

  it("incorrect HMAC, modified body and expired timestamp are rejected", async () => {
    const env = makeEnv();
    const raw = smsBody();
    const wrongSecret = new Uint8Array(32).fill(9);
    const badRes = await postSms(env, raw, await sign(raw, { secret: wrongSecret, nonce: "n-bad" }));
    expect(badRes.status).toBe(401);
    const sig = await sign(raw, { nonce: "n-tamper" });
    const tampered = smsBody("e2");
    expect((await postSms(env, tampered, sig)).status).toBe(401);
    const oldTs = Math.floor(Date.now() / 1000) - 300;
    const expired = smsBody("e3");
    const expiredRes = await postSms(env, expired, await sign(expired, { ts: oldTs, nonce: "n-expired" }));
    expect(expiredRes.status).toBe(401);
  });

  it("reused nonce is 409 and replayed event ID creates no second OTP", async () => {
    const env = makeEnv();
    const first = smsBody("e1");
    const firstRes = await postSms(env, first, await sign(first, { nonce: "n1-first" }));
    expect(firstRes.status).toBe(204);
    // Same nonce again, different event: replay.
    const replay = smsBody("e2");
    const replayRes = await postSms(env, replay, await sign(replay, { nonce: "n1-first" }));
    expect(replayRes.status).toBe(409);
    // Same event again, fresh nonce: safely discarded duplicate, still 204.
    const dup = smsBody("e1");
    const dupRes = await postSms(env, dup, await sign(dup, { nonce: "n2" }));
    expect(dupRes.status).toBe(204);
    const latest = await getLatest(env);
    expect(await latest.json()).toMatchObject({ code: "116018" });
  });

  it("rejects oversized bodies, wrong content type and wrong methods", async () => {
    const env = makeEnv();
    const big = te.encode("x".repeat(5000));
    const bigRes = await postSms(env, big, await sign(big, { nonce: "n-big" }));
    expect(bigRes.status).toBe(413);
    const raw = smsBody();
    const plainHeaders = await sign(raw, { nonce: "n-plain" });
    plainHeaders.set("Content-Type", "text/plain");
    expect((await postSms(env, raw, plainHeaders)).status).toBe(400);
    const getRes = await worker.fetch(new Request("https://example.workers.dev/sms/meta"), env);
    expect(getRes.status).toBe(405);
    const postLatest = await worker.fetch(
      new Request("https://example.workers.dev/latest", { method: "POST" }),
      env,
    );
    expect(postLatest.status).toBe(405);
    expect((await worker.fetch(new Request("https://example.workers.dev/other"), env)).status).toBe(404);
  });

  it("expired OTP is unavailable via /latest", async () => {
    const env = makeEnv();
    const stub = env.META_INBOX.get(env.META_INBOX.idFromName("meta-inbox"));
    const now = Math.floor(Date.now() / 1000);
    await stub.fetch(
      new Request("http://inbox/reserve", {
        method: "POST",
        body: JSON.stringify({ nonce: "nx", eventId: "ex", code: "116018", expiresAt: now - 10, now: now - 400 }),
      }),
    );
    const res = await getLatest(env);
    expect(res.status).toBe(404);
  });
});
