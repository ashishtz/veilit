import { describe, expect, it } from "vitest";
import { type defaultDetectors, detectors, luhnValid } from "../src/detectors.js";
import { redact } from "../src/redact.js";

describe("luhnValid", () => {
  it("accepts valid card numbers", () => {
    expect(luhnValid("4242424242424242")).toBe(true); // Visa test
    expect(luhnValid("5555555555554444")).toBe(true); // Mastercard test
    expect(luhnValid("378282246310005")).toBe(true); // Amex test (15 digits)
  });

  it("rejects invalid numbers, wrong lengths, and non-digits", () => {
    expect(luhnValid("4242424242424241")).toBe(false);
    expect(luhnValid("123")).toBe(false); // too short
    expect(luhnValid("1".repeat(25))).toBe(false); // too long
    expect(luhnValid("4242abcd42424242")).toBe(false);
  });
});

describe("value detection (enabled by default)", () => {
  it("redacts a JWT stored under an innocent key", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const out = redact({ note: jwt });
    expect(out.note).toBe("[REDACTED]");
  });

  it("redacts a Luhn-valid credit card but leaves a random 16-digit number", () => {
    expect(redact({ x: "4242 4242 4242 4242" }).x).toBe("[REDACTED]");
    expect(redact({ x: "1111 1111 1111 1111" }).x).toBe("1111 1111 1111 1111");
  });

  it("redacts US SSNs with dashes", () => {
    expect(redact({ x: "your ssn is 123-45-6789 ok" }).x).toBe("your ssn is [REDACTED] ok");
  });

  it("redacts AWS access key ids", () => {
    expect(redact({ x: "AKIAIOSFODNN7EXAMPLE" }).x).toBe("[REDACTED]");
  });

  it("redacts GitHub, Slack, Stripe and Google keys", () => {
    expect(redact({ x: `ghp_${"a".repeat(36)}` }).x).toBe("[REDACTED]");
    expect(redact({ x: "xoxb-123456789012-abcdefABCDEF" }).x).toBe("[REDACTED]");
    expect(redact({ x: `sk_live_${"a".repeat(24)}` }).x).toBe("[REDACTED]");
    expect(redact({ x: `AIza${"b".repeat(35)}` }).x).toBe("[REDACTED]");
  });

  it("redacts PEM private keys", () => {
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----";
    expect(redact({ x: pem }).x).toBe("[REDACTED]");
  });

  it("redacts Bearer tokens embedded in a larger string", () => {
    const out = redact({ header: "Authorization: Bearer abc.def.ghi extra" });
    expect(out.header).toBe("Authorization: [REDACTED] extra");
  });

  it("redacts only the password inside a connection string, keeping user and host", () => {
    const out = redact({ db: "postgres://admin:s3cr3tp4ss@db.example.com:5432/app" });
    expect(out.db).toBe("postgres://admin:[REDACTED]@db.example.com:5432/app");
  });

  it("can be disabled with detectValues: false", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    expect(redact({ note: jwt }, { detectValues: false }).note).toBe(jwt);
  });
});

describe("opt-in PII detectors", () => {
  it("does not redact emails/IPs by default", () => {
    const out = redact({ a: "me@example.com", b: "10.0.0.1" });
    expect(out.a).toBe("me@example.com");
    expect(out.b).toBe("10.0.0.1");
  });

  it("redacts emails when the detector is added", () => {
    const out = redact({ a: "contact me@example.com now" }, { patterns: [detectors.email] });
    expect(out.a).toBe("contact [REDACTED] now");
  });

  it("redacts IPv4/IPv6 when added", () => {
    expect(redact({ a: "10.0.0.1" }, { patterns: [detectors.ipv4] }).a).toBe("[REDACTED]");
    expect(redact({ a: "2001:db8::ff00:42:8329" }, { patterns: [detectors.ipv6] }).a).toBe(
      "[REDACTED]",
    );
  });
});

describe("custom patterns", () => {
  it("accepts a bare regex and normalises the global flag", () => {
    const out = redact({ code: "ABC-1234" }, { patterns: [/ABC-\d+/] });
    expect(out.code).toBe("[REDACTED]");
  });

  it("accepts a full ValueDetector with validate", () => {
    const even: (typeof defaultDetectors)[number] = {
      name: "evenNum",
      pattern: /\b\d+\b/g,
      validate: (m) => Number(m) % 2 === 0,
    };
    const out = redact({ a: "4", b: "5" }, { patterns: [even] });
    expect(out.a).toBe("[REDACTED]");
    expect(out.b).toBe("5");
  });

  it("replaceDefaultPatterns disables the built-ins", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const out = redact(
      { note: jwt, code: "ZZ9" },
      {
        patterns: [/ZZ\d/],
        replaceDefaultPatterns: true,
      },
    );
    expect(out.note).toBe(jwt);
    expect(out.code).toBe("[REDACTED]");
  });
});
