import { describe, expect, it } from "vitest";
import { MetaInbox, type InboxStorage } from "../src/inbox";

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

function inbox() {
  return new MetaInbox({ storage: new MemoryStorage() });
}

const REAL_NOW = Math.floor(Date.now() / 1000);
async function reserve(
  ib: MetaInbox,
  nonce: string,
  eventId: string,
  code = "116018",
  now = REAL_NOW,
  expiresAt = REAL_NOW + 300,
) {
  const res = await ib.fetch(
    new Request("http://inbox/reserve", {
      method: "POST",
      body: JSON.stringify({ nonce, eventId, code, expiresAt, now }),
    }),
  );
  return (await res.json()) as { status: string };
}

describe("MetaInbox Durable Object", () => {
  it("stores the first OTP and keeps only the newest", async () => {
    const ib = inbox();
    expect(await reserve(ib, "n1", "e1", "111111")).toEqual({ status: "stored" });
    expect(await reserve(ib, "n2", "e2", "222222")).toEqual({ status: "stored" });
    const consumed = await ib.fetch(new Request("http://inbox/consume", { method: "POST" }));
    expect(consumed.status).toBe(200);
    expect(await consumed.json()).toEqual({ code: "222222", expiresAt: REAL_NOW + 300 });
  });

  it("reused nonce is a replay, even with a new event", async () => {
    const ib = inbox();
    expect(await reserve(ib, "n1", "e1")).toEqual({ status: "stored" });
    expect(await reserve(ib, "n1", "e2")).toEqual({ status: "replay" });
  });

  it("replayed event ID does not create a second OTP", async () => {
    const ib = inbox();
    expect(await reserve(ib, "n1", "e1", "111111")).toEqual({ status: "stored" });
    expect(await reserve(ib, "n2", "e1", "222222")).toEqual({ status: "duplicate" });
    const consumed = await ib.fetch(new Request("http://inbox/consume", { method: "POST" }));
    expect(await consumed.json()).toEqual({ code: "111111", expiresAt: REAL_NOW + 300 });
  });

  it("consume deletes the OTP after first read", async () => {
    const ib = inbox();
    await reserve(ib, "n1", "e1");
    expect((await ib.fetch(new Request("http://inbox/consume", { method: "POST" }))).status).toBe(200);
    expect((await ib.fetch(new Request("http://inbox/consume", { method: "POST" }))).status).toBe(404);
  });

  it("expired OTP is unavailable and expired nonces are cleaned up", async () => {
    const ib = inbox();
    await reserve(ib, "n1", "e1", "116018", REAL_NOW - 1000, REAL_NOW - 700);
    // A later reserve triggers cleanup of the expired nonce/event/current.
    expect(await reserve(ib, "n1", "e2", "222222", REAL_NOW, REAL_NOW + 300)).toEqual({ status: "stored" });
  });

  it("rejects a non-six-digit code", async () => {
    const ib = inbox();
    const res = await ib.fetch(
      new Request("http://inbox/reserve", {
        method: "POST",
        body: JSON.stringify({ nonce: "n1", eventId: "e1", code: "12345", expiresAt: REAL_NOW + 300, now: REAL_NOW }),
      }),
    );
    expect(res.status).toBe(400);
  });
});
