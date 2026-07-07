import type { KeyMatchStrategy } from "./types.js";

/**
 * Keys matched when the normalised key *contains* one of these tokens.
 * These are strong signals that rarely appear inside innocent field names.
 */
const SUBSTRING_KEYS: readonly string[] = [
  "password",
  "passwd",
  "passphrase",
  "secret",
  "token",
  "apikey",
  "accesskey",
  "secretkey",
  "privatekey",
  "encryptionkey",
  "accesstoken",
  "refreshtoken",
  "idtoken",
  "authtoken",
  "sessiontoken",
  "clientsecret",
  "authorization",
  "credential",
  "creditcard",
  "cardnumber",
  "securitycode",
  "connectionstring",
  "sessionid",
  "cookie",
  "csrf",
  "xsrf",
];

/**
 * Keys matched only on *exact* normalised equality. These tokens (e.g. `auth`,
 * `key`, `pin`) would cause too many false positives as substrings - `auth`
 * would flag `author`, `key` would flag `monkey` or `foreignKey`.
 */
const EXACT_KEYS: readonly string[] = [
  "auth",
  "pwd",
  "pin",
  "otp",
  "ssn",
  "dsn",
  "salt",
  "mfa",
  "jwt",
  "bearer",
  "sid",
  "cvv",
  "cvc",
  "totp",
  "seed",
  "mnemonic",
];

/**
 * The complete list of tokens that trigger key-based redaction out of the box,
 * exposed for reference and documentation.
 */
export const defaultSensitiveKeys: readonly string[] = [...SUBSTRING_KEYS, ...EXACT_KEYS];

/** Lower-case a key and strip separators so `API_KEY`, `api-key`, `apiKey` all normalise alike. */
export function normalizeKey(key: string): string {
  let out = "";
  for (let i = 0; i < key.length; i++) {
    const code = key.charCodeAt(i);
    // Keep [a-z0-9]; lower-case [A-Z]; drop everything else (._-space etc.).
    if (code >= 97 && code <= 122) out += key[i];
    else if (code >= 48 && code <= 57) out += key[i];
    else if (code >= 65 && code <= 90) out += String.fromCharCode(code + 32);
  }
  return out;
}

/** A compiled key matcher produced from user options. */
export interface KeyMatcher {
  test(key: string): boolean;
}

export function createKeyMatcher(
  extra: (string | RegExp)[],
  replaceDefault: boolean,
  strategy: KeyMatchStrategy,
): KeyMatcher {
  const substrings = new Set(replaceDefault ? [] : SUBSTRING_KEYS);
  const exact = new Set(replaceDefault ? [] : EXACT_KEYS);
  const regexes: RegExp[] = [];

  for (const item of extra) {
    if (typeof item === "string") {
      const normalized = normalizeKey(item);
      if (normalized) {
        // User-supplied strings default to exact matching in "exact" mode and
        // substring matching in "smart" mode, mirroring the built-ins.
        (strategy === "exact" ? exact : substrings).add(normalized);
      }
    } else {
      regexes.push(item);
    }
  }

  return {
    test(key: string): boolean {
      // Regex matchers run against the raw key so authors can anchor precisely.
      for (const re of regexes) {
        re.lastIndex = 0;
        if (re.test(key)) return true;
      }
      const normalized = normalizeKey(key);
      if (!normalized) return false;
      // Equality check first - this is the whole of "exact" mode and also lets
      // "smart" mode match substring tokens that happen to equal the key.
      if (exact.has(normalized) || substrings.has(normalized)) return true;
      if (strategy === "exact") return false;
      for (const token of substrings) {
        if (normalized.includes(token)) return true;
      }
      return false;
    },
  };
}
