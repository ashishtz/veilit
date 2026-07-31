import { describe, expect, it } from "vitest";
import { detectors } from "../src/detectors.js";
import { normalizeKey } from "../src/keys.js";
import { createRedactor, redact } from "../src/redact.js";

describe("normalizeKey extra cases", () => {
  it("keeps digits and lowercases mixed input", () => {
    expect(normalizeKey("Key123")).toBe("key123");
    expect(normalizeKey("A1_b2-C3")).toBe("a1b2c3");
  });
});

describe("regex keys with global flag are reset between calls", () => {
  it("matches consistently across repeated invocations", () => {
    const scrub = createRedactor({ keys: [/token/g] });
    expect(scrub({ token: "a" }).token).toBe("[REDACTED]");
    // A global regex carries lastIndex; the matcher must reset it each time.
    expect(scrub({ token: "b" }).token).toBe("[REDACTED]");
    expect(scrub({ token: "c" }).token).toBe("[REDACTED]");
  });
});

describe("Map with non-string keys", () => {
  it("recurses into values under non-string keys", () => {
    const m = new Map<unknown, unknown>([[1, { password: "x" }]]);
    const out = redact({ m }).m as Map<unknown, unknown>;
    expect(out.get(1)).toEqual({ password: "[REDACTED]" });
  });
});

describe("keepLast with value detection under an innocent key", () => {
  it("keeps the trailing characters of a detected card", () => {
    const out = redact({ memo: "card 4242424242424242 end" }, { keepLast: 4 });
    expect(out.memo).toBe("card [REDACTED]4242 end");
  });
});

describe("already-global custom detectors are used as-is", () => {
  it("respects a provided global pattern", () => {
    const out = redact(
      { a: "foo BAR baz" },
      {
        patterns: [{ name: "bar", pattern: /BAR/g }],
      },
    );
    expect(out.a).toBe("foo [REDACTED] baz");
  });
});

describe("combining opt-in detectors", () => {
  it("layers multiple PII detectors together", () => {
    const scrub = createRedactor({ patterns: [detectors.email, detectors.ipv4] });
    const out = scrub({ log: "user me@x.com from 10.1.2.3 connected" });
    expect(out.log).toBe("user [REDACTED] from [REDACTED] connected");
  });
});

describe("empty and unusual inputs", () => {
  it("handles empty containers", () => {
    expect(redact({})).toEqual({});
    expect(redact([])).toEqual([]);
    expect(redact(new Map())).toEqual(new Map());
    expect(redact(new Set())).toEqual(new Set());
  });

  it("handles an array as the top-level value", () => {
    expect(redact([{ password: "x" }, "ok"])).toEqual([{ password: "[REDACTED]" }, "ok"]);
  });
});
