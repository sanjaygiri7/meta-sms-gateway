/**
 * MetaInbox Durable Object.
 *
 * Strongly consistent storage, used atomically because a Durable Object
 * handles one request at a time: check-and-record for nonces, deduplication
 * of event IDs, and storing only the newest valid OTP all happen in one
 * invocation, so a replay cannot race a first delivery.
 *
 * Stored, and nothing else:
 *   nonce:<nonce>  -> { expiresAt }   (600s, replay prevention only)
 *   event:<eventId> -> { expiresAt }  (600s, deduplication only)
 *   current        -> { code, expiresAt } (300s, only the newest OTP)
 *
 * The complete SMS body is never stored. Expired entries are removed
 * opportunistically on every request (lazy cleanup); retention is bounded
 * by the expiresAt values above and no history is kept.
 *
 * Internal protocol (only reachable through the Worker binding, never
 * directly from the internet):
 *   POST /reserve { nonce, eventId, code, expiresAt, now }
 *     -> 200 { status: "stored" | "replay" | "duplicate" }
 *   POST /consume {}
 *     -> 200 { code, expiresAt } and deletes the OTP, or 404 when none/expired
 */

export interface InboxStorage {
  get(key: string): Promise<unknown>;
  put(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<boolean | void>;
  list(options?: { prefix?: string }): Promise<Map<string, unknown>>;
}

interface Expiring {
  expiresAt: number;
}

interface CurrentOtp extends Expiring {
  code: string;
}

const NONCE_TTL_SECONDS = 600;
const EVENT_TTL_SECONDS = 600;

export class MetaInbox {
  private storage: InboxStorage;

  // Cloudflare constructs Durable Objects with (state, env). Tests pass a
  // state-like object whose `storage` is an in-memory implementation.
  constructor(state: { storage: InboxStorage }, _env?: unknown) {
    this.storage = state.storage;
  }

  private async cleanup(now: number): Promise<void> {
    for (const prefix of ["nonce:", "event:"]) {
      const entries = await this.storage.list({ prefix });
      for (const [key, value] of entries) {
        const v = value as Expiring | undefined;
        if (!v || typeof v.expiresAt !== "number" || v.expiresAt <= now) {
          await this.storage.delete(key);
        }
      }
    }
    const current = (await this.storage.get("current")) as CurrentOtp | undefined;
    if (current && current.expiresAt <= now) {
      await this.storage.delete("current");
    }
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/reserve") {
      let body: {
        nonce?: unknown;
        eventId?: unknown;
        code?: unknown;
        expiresAt?: unknown;
        now?: unknown;
      };
      try {
        body = (await request.json()) as typeof body;
      } catch {
        return json({ error: "bad_request" }, 400);
      }
      if (
        typeof body.nonce !== "string" ||
        typeof body.eventId !== "string" ||
        typeof body.code !== "string" ||
        typeof body.expiresAt !== "number" ||
        typeof body.now !== "number" ||
        !/^[0-9]{6}$/.test(body.code)
      ) {
        return json({ error: "bad_request" }, 400);
      }
      const now = body.now;
      await this.cleanup(now);
      if (await this.storage.get("nonce:" + body.nonce)) {
        return json({ status: "replay" }, 200);
      }
      if (await this.storage.get("event:" + body.eventId)) {
        return json({ status: "duplicate" }, 200);
      }
      await this.storage.put("nonce:" + body.nonce, {
        expiresAt: now + NONCE_TTL_SECONDS,
      });
      await this.storage.put("event:" + body.eventId, {
        expiresAt: now + EVENT_TTL_SECONDS,
      });
      await this.storage.put("current", { code: body.code, expiresAt: body.expiresAt });
      return json({ status: "stored" }, 200);
    }

    if (request.method === "POST" && url.pathname === "/consume") {
      const now = Math.floor(Date.now() / 1000);
      await this.cleanup(now);
      const current = (await this.storage.get("current")) as CurrentOtp | undefined;
      if (!current) {
        return json({ error: "no_valid_code" }, 404);
      }
      await this.storage.delete("current");
      return json({ code: current.code, expiresAt: current.expiresAt }, 200);
    }

    return json({ error: "not_found" }, 404);
  }
}

function json(value: unknown, status: number): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}
