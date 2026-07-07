# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0]

Initial release.

- `redact(value, options?)` - return a redacted deep clone of any value.
- `createRedactor(options?)` - reusable, pre-compiled redactor for hot paths.
- Key-based redaction with a curated, case/separator-insensitive default key list.
- Value-based detection (default): JWTs, Luhn-validated credit cards, US SSNs,
  AWS access keys, GitHub / Slack / Stripe / Google keys, PEM private keys,
  `Bearer` tokens, and passwords inside connection strings.
- Opt-in PII detectors: email, IPv4, IPv6, US phone.
- Handles objects, arrays, `Map`, `Set`, `Error` (with `cause`), `Date`, `RegExp`,
  `URL`, and class instances; circular-safe and prototype-pollution hardened.
- Configurable mask (string or context function), partial masking (`keepLast`),
  custom keys/patterns, depth limiting, and match strategy.
- Zero runtime dependencies. Ships ESM + CJS + type declarations.
