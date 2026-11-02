import { describe, expect, it } from "vitest";
import { accepts, extractCode, isSenderAllowlisted, parseAllowlist } from "../src/filter";

describe("Meta filter (Worker, mirrored on Android)", () => {
  const allow = parseAllowlist("META");

  it("approved sender + exact code accepts", () => {
    expect(accepts(allow, "META", "116018 is your Meta confirmation code.")).toBe(true);
    expect(accepts(allow, "META", "116018 is your Meta confirmation code")).toBe(true);
    expect(extractCode("116018 is your Meta confirmation code.")).toBe("116018");
  });

  it("unknown sender + exact code rejects", () => {
    expect(accepts(allow, "OTHER", "116018 is your Meta confirmation code.")).toBe(false);
    expect(accepts(allow, "METAA", "116018 is your Meta confirmation code.")).toBe(false);
  });

  it("approved sender + unrelated OTP rejects", () => {
    expect(accepts(allow, "META", "Your OTP is 116018.")).toBe(false);
    expect(accepts(allow, "META", "116018 is your Meta confirmation code. Do not share it.")).toBe(false);
    expect(accepts(allow, "META", "Meta")).toBe(false);
  });

  it("approved sender + ordinary SMS rejects", () => {
    expect(accepts(allow, "META", "Hello world")).toBe(false);
    expect(extractCode("Hello world")).toBeNull();
  });

  it("unknown sender containing META rejects", () => {
    expect(accepts(allow, "NOTMETA", "116018 is your Meta confirmation code.")).toBe(false);
  });

  it("empty allowlist forwards nothing", () => {
    expect(accepts(new Set(), "META", "116018 is your Meta confirmation code.")).toBe(false);
    expect(accepts(parseAllowlist(""), "META", "116018 is your Meta confirmation code.")).toBe(false);
  });

  it("sender match is exact, case-insensitive, trimmed only", () => {
    expect(isSenderAllowlisted(allow, "meta")).toBe(true);
    expect(isSenderAllowlisted(allow, "  META  ")).toBe(true);
    expect(isSenderAllowlisted(allow, "X-META")).toBe(false);
    expect(isSenderAllowlisted(allow, "META-X")).toBe(false);
    expect(isSenderAllowlisted(parseAllowlist("*"), "anything")).toBe(false);
  });

  it("body requires six ASCII digits and the full template", () => {
    expect(extractCode("000001 IS YOUR META CONFIRMATION CODE.")).toBe("000001");
    expect(extractCode("12345 is your Meta confirmation code.")).toBeNull();
    expect(extractCode("1234567 is your Meta confirmation code.")).toBeNull();
    expect(extractCode("12345a is your Meta confirmation code.")).toBeNull();
    expect(extractCode("123456 is your Meta confirmation code..")).toBeNull();
  });
});
