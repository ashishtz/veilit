/**
 * Context passed to a custom mask function so it can decide how to redact a
 * particular occurrence of sensitive data.
 */
export interface RedactionContext {
  /**
   * Why this value was redacted:
   * - `"key"` — the property key looked sensitive (e.g. `password`, `apiKey`).
   * - `"value"` — the value itself matched a detector (e.g. a JWT or card number).
   */
  reason: "key" | "value";
  /** The property key (or `Map` string key) the value was found under, if any. */
  key?: string;
  /** The name of the detector that matched, when `reason` is `"value"`. */
  detector?: string;
  /** The original (pre-redaction) value. Never logged by default. */
  value: unknown;
  /** Property path to this value, e.g. `["user", "credentials", "password"]`. */
  path: (string | number)[];
}

/**
 * A value detector recognises sensitive data by its *content* rather than by
 * the key it lives under (for example a credit-card number stored in a field
 * innocently named `note`).
 */
export interface ValueDetector {
  /** Stable, human-readable identifier (surfaced via {@link RedactionContext.detector}). */
  name: string;
  /**
   * A global-flagged regular expression used to find sensitive substrings
   * inside larger strings. When the whole string is a single match it is
   * redacted entirely; otherwise only the matching spans are replaced.
   */
  pattern: RegExp;
  /**
   * Optional extra validation applied to each regex match (e.g. a Luhn check
   * for card numbers) to cut false positives. Return `true` to confirm the
   * match is sensitive.
   */
  validate?: (match: string) => boolean;
  /**
   * When set, only this regex capture group is redacted rather than the whole
   * match — used to strip the password out of a connection string while
   * keeping the scheme, user and host readable.
   */
  group?: number;
}

/** How string property keys are compared against the sensitive-key list. */
export type KeyMatchStrategy = "smart" | "exact";

export interface RedactOptions {
  /**
   * Replacement for redacted values. Either a fixed string or a function that
   * receives the {@link RedactionContext}. Default: `"[REDACTED]"`.
   */
  mask?: string | ((context: RedactionContext) => string);
  /**
   * Extra sensitive key names or regexes, matched against property keys in
   * addition to the built-in list.
   */
  keys?: (string | RegExp)[];
  /**
   * Replace the built-in sensitive-key list entirely with {@link keys} instead
   * of extending it. Default: `false`.
   */
  replaceDefaultKeys?: boolean;
  /**
   * Extra {@link ValueDetector | value detectors} (or bare regexes) used in
   * addition to the built-in set.
   */
  patterns?: (ValueDetector | RegExp)[];
  /**
   * Replace the built-in value detectors entirely with {@link patterns}.
   * Default: `false`.
   */
  replaceDefaultPatterns?: boolean;
  /**
   * Detect sensitive values by content, not just by key name. Disable for the
   * fastest possible key-only redaction. Default: `true`.
   */
  detectValues?: boolean;
  /**
   * Keep this many trailing characters of a redacted string visible, e.g.
   * `keepLast: 4` turns a card number into `"[REDACTED]4242"`. Default: `0`.
   */
  keepLast?: number;
  /**
   * How string keys are matched. `"smart"` (default) normalises case and
   * separators and uses a curated mix of exact/substring rules to minimise
   * false positives; `"exact"` requires a normalised equality match.
   */
  keyMatch?: KeyMatchStrategy;
  /**
   * Maximum recursion depth. Anything deeper is replaced with
   * {@link truncated}. Guards against pathological structures. Default: `20`.
   */
  maxDepth?: number;
  /** Placeholder emitted when {@link maxDepth} is exceeded. Default: `"[TRUNCATED]"`. */
  truncated?: string;
  /** Placeholder emitted when a circular reference is encountered. Default: `"[CIRCULAR]"`. */
  circular?: string;
}
