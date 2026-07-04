import type { ValueDetector } from "./types.js";

/** Luhn checksum used to validate candidate credit-card numbers. */
export function luhnValid(digits: string): boolean {
  const len = digits.length;
  if (len < 13 || len > 19) return false;
  let sum = 0;
  let double = false;
  for (let i = len - 1; i >= 0; i--) {
    const d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    let v = d;
    if (double) {
      v *= 2;
      if (v > 9) v -= 9;
    }
    sum += v;
    double = !double;
  }
  return sum % 10 === 0;
}

/** JSON Web Tokens: `header.payload.signature`, header base64url always starts `eyJ`. */
const jwt: ValueDetector = {
  name: "jwt",
  pattern: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
};

/** 13–19 digit sequences (optionally single-space/dash separated) that pass a Luhn check. */
const creditCard: ValueDetector = {
  name: "creditCard",
  pattern: /\b\d(?:[ -]?\d){12,18}\b/g,
  validate: (match) => luhnValid(match.replace(/[ -]/g, "")),
};

/** US Social Security Numbers — dashes required to keep false positives low. */
const ssn: ValueDetector = {
  name: "ssn",
  pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
};

/** AWS access key IDs (AKIA/ASIA/... prefixes + 16 uppercase alphanumerics). */
const awsAccessKey: ValueDetector = {
  name: "awsAccessKey",
  pattern: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16}\b/g,
};

/** GitHub personal-access / OAuth / app tokens and fine-grained PATs. */
const githubToken: ValueDetector = {
  name: "githubToken",
  pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g,
};

/** Slack tokens (`xoxb-`, `xoxp-`, ...). */
const slackToken: ValueDetector = {
  name: "slackToken",
  pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
};

/** Stripe secret and restricted keys (publishable `pk_` keys are not secrets). */
const stripeKey: ValueDetector = {
  name: "stripeKey",
  pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b/g,
};

/** Google API keys. */
const googleApiKey: ValueDetector = {
  name: "googleApiKey",
  pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
};

/** PEM-encoded private keys of any flavour (RSA, EC, OPENSSH, PGP, ...). */
const privateKey: ValueDetector = {
  name: "privateKey",
  pattern:
    /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g,
};

/** `Authorization: Bearer <token>` style credentials embedded in strings. */
const bearer: ValueDetector = {
  name: "bearer",
  pattern: /\bBearer\s+[A-Za-z0-9._~+/=-]+/gi,
};

/** Passwords embedded in connection strings / URLs: `scheme://user:PASS@host`. */
const urlPassword: ValueDetector = {
  name: "urlPassword",
  pattern: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:([^\s:/@]+)@/gi,
  group: 1,
};

/** Email addresses (opt-in — many apps legitimately log their own addresses). */
const email: ValueDetector = {
  name: "email",
  pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
};

/** IPv4 addresses (opt-in). */
const ipv4: ValueDetector = {
  name: "ipv4",
  pattern: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
};

/**
 * IPv6 addresses, including `::`-compressed forms (opt-in). Alternatives are
 * ordered so that the "mixed" forms (which fail cleanly rather than match a
 * prefix) are tried before the shorter "ends-with-::" forms — JS alternation
 * returns the first matching branch, not the longest.
 */
const ipv6: ValueDetector = {
  name: "ipv6",
  pattern:
    /(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}|(?:[A-F0-9]{1,4}:){1,2}(?::[A-F0-9]{1,4}){1,5}|(?:[A-F0-9]{1,4}:){1,3}(?::[A-F0-9]{1,4}){1,4}|(?:[A-F0-9]{1,4}:){1,4}(?::[A-F0-9]{1,4}){1,3}|(?:[A-F0-9]{1,4}:){1,5}(?::[A-F0-9]{1,4}){1,2}|(?:[A-F0-9]{1,4}:){1,6}:[A-F0-9]{1,4}|[A-F0-9]{1,4}:(?::[A-F0-9]{1,4}){1,6}|(?:[A-F0-9]{1,4}:){1,7}:|:(?::[A-F0-9]{1,4}){1,7}|::/gi,
};

/** North-American style phone numbers (opt-in — high false-positive risk). */
const usPhone: ValueDetector = {
  name: "usPhone",
  pattern: /\b(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}\b/g,
};

/**
 * All named detectors, exported so callers can cherry-pick opt-in ones
 * (`patterns: [detectors.email, detectors.ipv4]`) or reference built-ins.
 */
export const detectors = {
  jwt,
  creditCard,
  ssn,
  awsAccessKey,
  githubToken,
  slackToken,
  stripeKey,
  googleApiKey,
  privateKey,
  bearer,
  urlPassword,
  email,
  ipv4,
  ipv6,
  usPhone,
} as const;

/**
 * Detectors enabled by default: high-severity, low-false-positive credentials
 * and secrets. PII detectors (email, IP, phone) are intentionally opt-in.
 */
export const defaultDetectors: readonly ValueDetector[] = [
  jwt,
  creditCard,
  ssn,
  awsAccessKey,
  githubToken,
  slackToken,
  stripeKey,
  googleApiKey,
  privateKey,
  bearer,
  urlPassword,
];
