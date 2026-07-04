import { describe, expect, it } from "vitest";
import { defaultSensitiveKeys, normalizeKey } from "../src/keys.js";
import { redact } from "../src/redact.js";

describe("normalizeKey", () => {
  it("lower-cases and strips separators", () => {
    expect(normalizeKey("API_KEY")).toBe("apikey");
    expect(normalizeKey("access-token")).toBe("accesstoken");
    expect(normalizeKey("Client.Secret")).toBe("clientsecret");
    expect(normalizeKey("  pass word ")).toBe("password");
  });

  it("returns empty string for separator-only keys", () => {
    expect(normalizeKey("___")).toBe("");
    expect(normalizeKey("")).toBe("");
  });
});

describe("key-based redaction", () => {
  it("redacts common secret keys regardless of casing/separators", () => {
    const input = {
      password: "hunter2",
      API_KEY: "abc",
      "access-token": "xyz",
      clientSecret: "s",
      refreshToken: "r",
    };
    const out = redact(input);
    expect(out.password).toBe("[REDACTED]");
    expect(out.API_KEY).toBe("[REDACTED]");
    expect(out["access-token"]).toBe("[REDACTED]");
    expect(out.clientSecret).toBe("[REDACTED]");
    expect(out.refreshToken).toBe("[REDACTED]");
  });

  it("redacts the whole value under a sensitive key, whatever its type", () => {
    const out = redact({
      password: { nested: "still secret" },
      credentials: [1, 2, 3],
    });
    expect(out.password).toBe("[REDACTED]");
    expect(out.credentials).toBe("[REDACTED]");
  });

  it("does NOT flag innocent look-alike keys (author, monkey, keyboard)", () => {
    const out = redact({
      author: "Ada Lovelace",
      monkey: "George",
      keyboard: "mechanical",
      publicKey: "not-secret-per-se",
      description: "a passphrase-manager app",
    });
    expect(out.author).toBe("Ada Lovelace");
    expect(out.monkey).toBe("George");
    expect(out.keyboard).toBe("mechanical");
  });

  it("flags exact-match tokens but not their substrings", () => {
    expect(redact({ auth: "x" }).auth).toBe("[REDACTED]");
    expect(redact({ author: "x" }).author).toBe("x");
    expect(redact({ pin: "1234" }).pin).toBe("[REDACTED]");
    expect(redact({ spinner: "x" }).spinner).toBe("x");
  });

  it("supports custom extra keys", () => {
    const out = redact({ nickname: "topsecret" }, { keys: ["nickname"] });
    expect(out.nickname).toBe("[REDACTED]");
  });

  it("supports regex keys", () => {
    const out = redact({ x_custom_field: "v", other: "keep" }, { keys: [/^x_custom/] });
    expect(out.x_custom_field).toBe("[REDACTED]");
    expect(out.other).toBe("keep");
  });

  it("replaceDefaultKeys drops the built-in list", () => {
    const out = redact(
      { password: "p", only_this: "x" },
      {
        keys: ["only_this"],
        replaceDefaultKeys: true,
      },
    );
    expect(out.password).toBe("p");
    expect(out.only_this).toBe("[REDACTED]");
  });

  it("exact keyMatch strategy requires whole-key equality", () => {
    const out = redact({ password: "p", userpassword: "q" }, { keyMatch: "exact" });
    // "password" normalises to exactly "password" which is not in the exact set
    // in exact mode (built-in substrings become exact), so it matches;
    // "userpassword" does not equal any exact token.
    expect(out.password).toBe("[REDACTED]");
    expect(out.userpassword).toBe("q");
  });
});

describe("defaultSensitiveKeys", () => {
  it("exposes the built-in list", () => {
    expect(defaultSensitiveKeys).toContain("password");
    expect(defaultSensitiveKeys).toContain("apikey");
    expect(Array.isArray(defaultSensitiveKeys)).toBe(true);
  });
});
