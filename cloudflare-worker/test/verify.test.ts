import { describe, expect, it } from "vitest";
import {
  canonicalString,
  decodeSecret,
  hmacHex,
  sha256Hex,
  toHex,
  verifyHeaders,
} from "../src/verify";

const te = new TextEncoder();

async function signWithSecret(
  secret: Uint8Array,
  timestamp: string,
  nonce: string,
  body: Uint8Array,
): Promise<string> {
  const bodyHash = await sha256Hex(body);
  const canonical = canonicalString(timestamp, nonce, bodyHash);
  return hmacHex(secret, te.encode(canonical));
}

function headers(deviceId: string, ts: string, nonce: string, sig: string): Headers {
  const h = new Headers();
  h.set("X-Device-Id", deviceId);
  h.set("X-Timestamp", ts);
  h.set("X-Nonce", nonce);
  h.set("X-Signature", sig);
  return h;
}

describe("HMAC verification", () => {
  const secretBytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) secretBytes[i] = i;
  const secretBase64 = btoa(String.fromCharCode(...secretBytes));
  const env = { SMS_HMAC_SECRET: secretBase64, EXPECTED_DEVICE_ID: "device-1" };
  const body = te.encode('{"version":1,"eventId":"e1"}');
  const now = 1_700_000_000;

  it("accepts a correctly signed request", async () => {
    const sig = await signWithSecret(secretBytes, String(now), "nonce-1", body);
    await expect(
      verifyHeaders(body, headers("device-1", String(now), "nonce-1", sig), env, now),
    ).resolves.toMatchObject({ deviceId: "device-1", nonce: "nonce-1" });
  });

  it("rejects an incorrect HMAC", async () => {
    const sig = await signWithSecret(secretBytes, String(now), "nonce-1", body);
    const bad = sig.slice(0, -1) + (sig.endsWith("0") ? "1" : "0");
    await expect(
      verifyHeaders(body, headers("device-1", String(now), "nonce-1", bad), env, now),
    ).resolves.toBeNull();
  });

  it("rejects a modified body", async () => {
    const sig = await signWithSecret(secretBytes, String(now), "nonce-1", body);
    const tampered = te.encode('{"version":1,"eventId":"e2"}');
    await expect(
      verifyHeaders(tampered, headers("device-1", String(now), "nonce-1", sig), env, now),
    ).resolves.toBeNull();
  });

  it("rejects an expired timestamp and accepts the 120s boundary", async () => {
    const sigOld = await signWithSecret(secretBytes, String(now - 121), "n-old", body);
    await expect(
      verifyHeaders(body, headers("device-1", String(now - 121), "n-old", sigOld), env, now),
    ).resolves.toBeNull();
    const sigEdge = await signWithSecret(secretBytes, String(now - 120), "n-edge", body);
    await expect(
      verifyHeaders(body, headers("device-1", String(now - 120), "n-edge", sigEdge), env, now),
    ).resolves.not.toBeNull();
  });

  it("rejects an unknown device and missing headers", async () => {
    const sig = await signWithSecret(secretBytes, String(now), "n1", body);
    await expect(
      verifyHeaders(body, headers("other", String(now), "n1", sig), env, now),
    ).resolves.toBeNull();
    await expect(verifyHeaders(body, new Headers(), env, now)).resolves.toBeNull();
  });

  it("verifies against the exact raw body bytes, not a reconstruction", async () => {
    // Same JSON object, different whitespace: a reconstructed body must fail.
    const raw = te.encode('{ "version": 1, "eventId": "e1" }');
    const sig = await signWithSecret(secretBytes, String(now), "n-raw", raw);
    await expect(
      verifyHeaders(raw, headers("device-1", String(now), "n-raw", sig), env, now),
    ).resolves.not.toBeNull();
    await expect(
      verifyHeaders(body, headers("device-1", String(now), "n-raw", sig), env, now),
    ).resolves.toBeNull();
  });

  it("decodes hex, base64 and UTF-8 secret forms to the same key", async () => {
    const hex = toHex(secretBytes);
    expect(decodeSecret(hex)).toEqual(secretBytes);
    expect(decodeSecret(secretBase64)).toEqual(secretBytes);
    expect(decodeSecret("plain-secret")).toEqual(te.encode("plain-secret"));
  });

  it("sha256 matches the known vector", async () => {
    expect(await sha256Hex(te.encode("abc"))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("cross-platform fixed vector matches Android", async () => {
    const body = te.encode(
      '{"version":1,"eventId":"e1","sender":"META","body":"116018 is your Meta confirmation code.","receivedAt":"2026-01-01T00:00:00Z"}',
    );
    expect(await sha256Hex(body)).toBe(
      "36f987206814c401638481de4e3ec2e9d0f395b16d83d19376fa1f0e11d559c8",
    );
    const sig = await signWithSecret(
      secretBytes,
      "1700000000",
      "0123456789abcdef0123456789abcdef",
      body,
    );
    expect(sig).toBe("f914d836081f7d8821a0169c253485877f0da94bdd90be9c13457fd2f5247f04");
  });
});
