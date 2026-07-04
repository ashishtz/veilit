import { describe, expect, it, vi } from "vitest";
import { createRedactor, redact } from "../src/redact.js";
import type { RedactionContext } from "../src/types.js";

describe("primitives and pass-through", () => {
  it("returns primitives untouched", () => {
    expect(redact(42)).toBe(42);
    expect(redact(true)).toBe(true);
    expect(redact(null)).toBe(null);
    expect(redact(undefined)).toBe(undefined);
    expect(redact(10n)).toBe(10n);
  });

  it("redacts a bare sensitive string value at the top level", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    expect(redact(jwt)).toBe("[REDACTED]");
  });
});

describe("immutability", () => {
  it("never mutates the input", () => {
    const input = { password: "hunter2", user: { name: "ada" }, list: [1, 2] };
    const snapshot = structuredClone(input);
    redact(input);
    expect(input).toEqual(snapshot);
  });

  it("returns a distinct object graph", () => {
    const input = { a: { b: 1 } };
    const out = redact(input);
    expect(out).not.toBe(input);
    expect(out.a).not.toBe(input.a);
  });
});

describe("nested structures", () => {
  it("recurses through nested objects and arrays", () => {
    const out = redact({
      users: [
        { name: "ada", password: "x" },
        { name: "bob", token: "y" },
      ],
    });
    expect(out).toEqual({
      users: [
        { name: "ada", password: "[REDACTED]" },
        { name: "bob", token: "[REDACTED]" },
      ],
    });
  });
});

describe("circular references", () => {
  it("replaces cycles with the circular marker and stays serializable", () => {
    const a: Record<string, unknown> = { name: "root" };
    a.self = a;
    const out = redact(a) as Record<string, unknown>;
    expect(out.self).toBe("[CIRCULAR]");
    expect(() => JSON.stringify(out)).not.toThrow();
  });

  it("handles indirect cycles through arrays", () => {
    const node: Record<string, unknown> = { id: 1 };
    node.children = [node];
    const out = redact(node) as Record<string, unknown>;
    expect((out.children as unknown[])[0]).toBe("[CIRCULAR]");
  });

  it("does not treat repeated (non-cyclic) references as circular", () => {
    const shared = { value: 1 };
    const out = redact({ a: shared, b: shared }) as Record<string, { value: number }>;
    expect(out.a).toEqual({ value: 1 });
    expect(out.b).toEqual({ value: 1 });
  });
});

describe("depth limiting", () => {
  it("truncates beyond maxDepth", () => {
    const out = redact({ a: { b: { c: { d: 1 } } } }, { maxDepth: 2 }) as any;
    expect(out.a.b.c).toBe("[TRUNCATED]");
  });
});

describe("special object types", () => {
  it("clones Date and RegExp", () => {
    const d = new Date("2020-01-01T00:00:00Z");
    const out = redact({ d, r: /abc/gi }) as { d: Date; r: RegExp };
    expect(out.d).toBeInstanceOf(Date);
    expect(out.d.getTime()).toBe(d.getTime());
    expect(out.d).not.toBe(d);
    expect(out.r.source).toBe("abc");
    expect(out.r.flags).toBe("gi");
  });

  it("redacts Map values by key name and by content", () => {
    const m = new Map<string, unknown>([
      ["password", "secret"],
      ["note", "4242 4242 4242 4242"],
      ["safe", "hello"],
    ]);
    const out = redact({ m }).m as Map<string, unknown>;
    expect(out.get("password")).toBe("[REDACTED]");
    expect(out.get("note")).toBe("[REDACTED]");
    expect(out.get("safe")).toBe("hello");
  });

  it("recurses into Set members", () => {
    const s = new Set([{ password: "x" }, { ok: 1 }]);
    const out = redact({ s }).s as Set<Record<string, unknown>>;
    const arr = [...out];
    expect(arr[0]).toEqual({ password: "[REDACTED]" });
    expect(arr[1]).toEqual({ ok: 1 });
  });

  it("redacts inside Errors while keeping name, message and stack", () => {
    const err = new Error("connect failed: postgres://u:s3cr3t@host/db") as Error &
      Record<string, unknown>;
    err.code = "E_AUTH";
    err.password = "leaked";
    const out = redact(err) as Record<string, unknown>;
    expect(out.name).toBe("Error");
    expect(out.message).toBe("connect failed: postgres://u:[REDACTED]@host/db");
    expect(typeof out.stack).toBe("string");
    expect(out.code).toBe("E_AUTH");
    expect(out.password).toBe("[REDACTED]");
  });

  it("redacts Error.cause recursively", () => {
    const cause = new Error("inner") as Error & Record<string, unknown>;
    cause.apiKey = "k";
    const err = new Error("outer", { cause });
    const out = redact(err) as Record<string, unknown>;
    expect((out.cause as Record<string, unknown>).apiKey).toBe("[REDACTED]");
  });

  it("stringifies and scrubs URL objects", () => {
    const out = redact({ u: new URL("https://user:pass123@host.dev/path") });
    expect(out.u).toBe("https://user:[REDACTED]@host.dev/path");
  });

  it("passes typed arrays / buffers through untouched", () => {
    const buf = new Uint8Array([1, 2, 3]);
    const out = redact({ buf });
    expect(out.buf).toBe(buf);
  });
});

describe("masking options", () => {
  it("supports a custom mask string", () => {
    expect(redact({ password: "x" }, { mask: "***" }).password).toBe("***");
  });

  it("supports keepLast for partial masking of strings", () => {
    expect(redact({ card: "4242424242424242" }, { keepLast: 4 }).card).toBe("[REDACTED]4242");
    // keepLast does not apply to non-string values redacted by key
    expect(redact({ password: 12345 }, { keepLast: 2 }).password).toBe("[REDACTED]");
  });

  it("supports a mask function receiving context", () => {
    const mask = vi.fn((ctx: RedactionContext) => `<${ctx.reason}:${ctx.key ?? ctx.detector}>`);
    const out = redact({ password: "x", note: "AKIAIOSFODNN7EXAMPLE" }, { mask });
    expect(out.password).toBe("<key:password>");
    expect(out.note).toBe("<value:awsAccessKey>");
    expect(mask).toHaveBeenCalled();
  });

  it("passes an accurate path in the context", () => {
    const paths: (string | number)[][] = [];
    redact(
      { a: { b: [{ password: "x" }] } },
      {
        mask: (ctx) => {
          paths.push(ctx.path);
          return "[R]";
        },
      },
    );
    expect(paths).toContainEqual(["a", "b", 0, "password"]);
  });
});

describe("createRedactor", () => {
  it("builds a reusable redactor", () => {
    const scrub = createRedactor({ mask: "#" });
    expect(scrub({ password: "a" }).password).toBe("#");
    expect(scrub({ token: "b" }).token).toBe("#");
  });
});

describe("security: prototype pollution", () => {
  it("does not pollute Object.prototype via __proto__ keys", () => {
    const malicious = JSON.parse('{"__proto__": {"polluted": true}}');
    const out = redact({ data: malicious }) as any;
    expect(({} as any).polluted).toBeUndefined();
    expect(Object.prototype).not.toHaveProperty("polluted");
    // The own property is preserved on the clone without touching the prototype.
    expect(Object.hasOwn(out.data, "__proto__")).toBe(true);
  });
});

describe("robustness", () => {
  it("survives throwing getters", () => {
    const obj = {
      get boom(): string {
        throw new Error("nope");
      },
      safe: "ok",
    };
    const out = redact(obj) as Record<string, unknown>;
    expect(out.boom).toBe("[UNREADABLE]");
    expect(out.safe).toBe("ok");
  });

  it("produces JSON-serializable output for complex inputs", () => {
    const a: Record<string, unknown> = { password: "x", when: new Date(), re: /y/ };
    a.loop = a;
    expect(() => JSON.stringify(redact(a))).not.toThrow();
  });
});
