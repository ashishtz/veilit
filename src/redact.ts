import { defaultDetectors } from "./detectors.js";
import { createKeyMatcher, type KeyMatcher } from "./keys.js";
import type { RedactionContext, RedactOptions, ValueDetector } from "./types.js";

interface ResolvedConfig {
  mask: string | ((context: RedactionContext) => string);
  keyMatcher: KeyMatcher;
  detectors: ValueDetector[];
  detectValues: boolean;
  keepLast: number;
  maxDepth: number;
  truncated: string;
  circular: string;
}

/** Ensure a detector's regex carries the global flag required for full-string scanning. */
function ensureGlobal(re: RegExp): RegExp {
  return re.flags.includes("g") ? re : new RegExp(re.source, `${re.flags}g`);
}

function resolveConfig(options: RedactOptions = {}): ResolvedConfig {
  const detectors: ValueDetector[] = options.replaceDefaultPatterns ? [] : [...defaultDetectors];
  if (options.patterns) {
    for (const p of options.patterns) {
      if (p instanceof RegExp) {
        detectors.push({ name: "custom", pattern: ensureGlobal(p) });
      } else {
        detectors.push({ ...p, pattern: ensureGlobal(p.pattern) });
      }
    }
  }

  return {
    mask: options.mask ?? "[REDACTED]",
    keyMatcher: createKeyMatcher(
      options.keys ?? [],
      options.replaceDefaultKeys ?? false,
      options.keyMatch ?? "smart",
    ),
    detectors,
    detectValues: options.detectValues ?? true,
    keepLast: Math.max(0, options.keepLast ?? 0),
    maxDepth: options.maxDepth ?? 20,
    truncated: options.truncated ?? "[TRUNCATED]",
    circular: options.circular ?? "[CIRCULAR]",
  };
}

function applyMask(config: ResolvedConfig, context: RedactionContext): string {
  const base = typeof config.mask === "function" ? config.mask(context) : config.mask;
  const { value } = context;
  if (config.keepLast > 0 && typeof value === "string" && value.length > config.keepLast) {
    return base + value.slice(-config.keepLast);
  }
  return base;
}

/** Scan a string for sensitive substrings and replace the matching spans. */
function redactString(str: string, config: ResolvedConfig, path: (string | number)[]): string {
  if (!config.detectValues || config.detectors.length === 0) return str;
  let result = str;
  for (const detector of config.detectors) {
    const { pattern, validate, group, name } = detector;
    pattern.lastIndex = 0;
    result = result.replace(pattern, (...matchArgs: unknown[]) => {
      const match = matchArgs[0] as string;
      if (validate && !validate(match)) return match;
      if (group != null) {
        const captured = matchArgs[group];
        if (typeof captured !== "string" || captured.length === 0) return match;
        const masked = applyMask(config, {
          reason: "value",
          detector: name,
          value: captured,
          path,
        });
        return match.replace(captured, () => masked);
      }
      return applyMask(config, { reason: "value", detector: name, value: match, path });
    });
  }
  return result;
}

/** Assign a property without triggering the `__proto__` setter (prototype-pollution safe). */
function setProp(target: Record<string, unknown>, key: string, value: unknown): void {
  if (key === "__proto__") {
    Object.defineProperty(target, key, {
      value,
      enumerable: true,
      writable: true,
      configurable: true,
    });
  } else {
    target[key] = value;
  }
}

function walk(
  value: unknown,
  config: ResolvedConfig,
  depth: number,
  ancestors: Set<object>,
  path: (string | number)[],
): unknown {
  if (value === null) return null;
  const type = typeof value;
  if (type === "string") return redactString(value as string, config, path);
  if (type !== "object") return value; // number, boolean, bigint, undefined, symbol, function

  const obj = value as object;

  // Leaf object types - cloned or stringified, never recursed into.
  if (obj instanceof Date) return new Date(obj.getTime());
  if (obj instanceof RegExp) return new RegExp(obj.source, obj.flags);
  if (typeof URL !== "undefined" && obj instanceof URL) {
    return redactString(obj.toString(), config, path);
  }
  if (ArrayBuffer.isView(obj) || obj instanceof ArrayBuffer) return obj; // binary - pass through

  if (depth > config.maxDepth) return config.truncated;
  if (ancestors.has(obj)) return config.circular;
  ancestors.add(obj);
  try {
    if (obj instanceof Error) {
      return redactError(obj, config, depth, ancestors, path);
    }
    if (Array.isArray(obj)) {
      const out = new Array(obj.length);
      for (let i = 0; i < obj.length; i++) {
        out[i] = walk(obj[i], config, depth + 1, ancestors, [...path, i]);
      }
      return out;
    }
    if (obj instanceof Map) {
      const out = new Map<unknown, unknown>();
      for (const [k, v] of obj) {
        if (typeof k === "string" && config.keyMatcher.test(k)) {
          out.set(k, applyMask(config, { reason: "key", key: k, value: v, path: [...path, k] }));
        } else {
          const step = typeof k === "string" ? k : "[key]";
          out.set(k, walk(v, config, depth + 1, ancestors, [...path, step]));
        }
      }
      return out;
    }
    if (obj instanceof Set) {
      const out = new Set<unknown>();
      let i = 0;
      for (const v of obj) {
        out.add(walk(v, config, depth + 1, ancestors, [...path, i++]));
      }
      return out;
    }
    return walkPlainObject(obj as Record<string, unknown>, config, depth, ancestors, path);
  } finally {
    ancestors.delete(obj);
  }
}

function walkPlainObject(
  obj: Record<string, unknown>,
  config: ResolvedConfig,
  depth: number,
  ancestors: Set<object>,
  path: (string | number)[],
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(obj)) {
    let raw: unknown;
    try {
      raw = obj[key];
    } catch {
      // A throwing getter must never break redaction.
      setProp(out, key, "[UNREADABLE]");
      continue;
    }
    if (config.keyMatcher.test(key)) {
      setProp(
        out,
        key,
        applyMask(config, { reason: "key", key, value: raw, path: [...path, key] }),
      );
    } else {
      setProp(out, key, walk(raw, config, depth + 1, ancestors, [...path, key]));
    }
  }
  return out;
}

function redactError(
  err: Error,
  config: ResolvedConfig,
  depth: number,
  ancestors: Set<object>,
  path: (string | number)[],
): Record<string, unknown> {
  const out: Record<string, unknown> = {
    name: err.name,
    message: redactString(err.message ?? "", config, [...path, "message"]),
  };
  if (typeof err.stack === "string") {
    out.stack = redactString(err.stack, config, [...path, "stack"]);
  }
  // Own enumerable custom properties (e.g. `code`, `config`, `response`).
  for (const key of Object.keys(err)) {
    if (key === "name" || key === "message" || key === "stack") continue;
    const raw = (err as unknown as Record<string, unknown>)[key];
    if (config.keyMatcher.test(key)) {
      setProp(
        out,
        key,
        applyMask(config, { reason: "key", key, value: raw, path: [...path, key] }),
      );
    } else {
      setProp(out, key, walk(raw, config, depth + 1, ancestors, [...path, key]));
    }
  }
  // `cause` is typically non-enumerable, so surface it explicitly.
  if ("cause" in err && err.cause !== undefined && !("cause" in out)) {
    out.cause = walk(err.cause, config, depth + 1, ancestors, [...path, "cause"]);
  }
  return out;
}

/**
 * Return a redacted deep clone of `value`. The input is never mutated. Secrets
 * are removed both by sensitive key name (`password`, `apiKey`, ...) and by
 * value pattern (JWTs, credit cards, cloud keys, ...). The result is acyclic
 * and safe to `JSON.stringify`.
 *
 * @example
 * redact({ user: "ada", password: "hunter2" });
 * // → { user: "ada", password: "[REDACTED]" }
 */
export function redact<T>(value: T, options?: RedactOptions): T {
  const config = resolveConfig(options);
  return walk(value, config, 0, new Set<object>(), []) as T;
}

/**
 * Build a reusable redactor with a fixed configuration. Prefer this on hot
 * paths (e.g. a logger hook) so options are resolved only once.
 *
 * @example
 * const scrub = createRedactor({ keepLast: 4 });
 * scrub({ card: "4242424242424242" }); // → { card: "[REDACTED]4242" }
 */
export function createRedactor(options?: RedactOptions): <T>(value: T) => T {
  const config = resolveConfig(options);
  return <T>(value: T): T => walk(value, config, 0, new Set<object>(), []) as T;
}
