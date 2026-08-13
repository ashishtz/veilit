# veilit

> Zero-config, zero-dependency deep redaction of secrets & PII from **any** value - by sensitive **key names** *and* **value patterns**. Circular-safe, immutable, and always JSON-serializable.

[![npm version](https://img.shields.io/npm/v/veilit.svg)](https://www.npmjs.com/package/veilit)
[![license](https://img.shields.io/npm/l/veilit.svg)](./LICENSE)
[![types](https://img.shields.io/npm/types/veilit.svg)](https://www.npmjs.com/package/veilit)
[![zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](./package.json)

You already know the story: something logs a whole request object, a user record, or an error, and a password / JWT / API key ends up in your logs, your APM, or Sentry. The usual fix is to hand-maintain a list of paths to scrub (`req.body.password`, `req.headers.authorization`, …). That list is tedious, always out of date, and **misses the secret sitting in a field you never thought about**.

`veilit` takes the opposite approach. Point it at any value and it returns a **redacted deep clone** - removing sensitive data both by **key name** (`password`, `apiKey`, `authorization`, …) *and* by **what the value actually looks like** (a JWT, a Luhn-valid card number, an AWS/GitHub/Stripe key, a PEM private key, a password inside a connection string). No paths to maintain. No config to get started.

```ts
import { redact } from "veilit";

redact({
  user: "ada",
  password: "hunter2",
  profile: { apiKey: "sk_live_8f...", email: "ada@example.com" },
  note: "my card is 4242 4242 4242 4242", // ← secret under an innocent key
  db: "postgres://admin:s3cr3t@10.0.0.5:5432/app",
});
// {
//   user: "ada",
//   password: "[REDACTED]",
//   profile: { apiKey: "[REDACTED]", email: "ada@example.com" },
//   note: "my card is [REDACTED]",
//   db: "postgres://admin:[REDACTED]@10.0.0.5:5432/app"
// }
```

## Why veilit

- **Zero-config** - a sensible, security-first default ruleset works out of the box.
- **Zero dependencies** - nothing to audit but this package. Tiny and tree-shakeable.
- **Detects secrets by value, not just by key** - the part most redactors skip. A JWT in a field called `note` still gets caught.
- **Deep & total** - objects, arrays, `Map`, `Set`, `Error` (including `cause`), `Date`, `RegExp`, `URL`, class instances, nested to any depth.
- **Safe by construction** - never mutates your input, handles circular references, throwing getters, and is hardened against prototype pollution. Output is acyclic and safe to `JSON.stringify`.
- **Framework-agnostic** - it's just a function. Drop it into Pino, Winston, `console`, Sentry's `beforeSend`, an Express error handler, or a response serializer.
- **TypeScript-first** - fully typed, ESM + CJS, generics preserve your value's type.

## Install

```bash
npm install veilit
# or: pnpm add veilit / yarn add veilit / bun add veilit
```

Requires Node.js 20+ (works in any modern runtime; no Node built-ins used).

## Usage

### One-off

```ts
import { redact } from "veilit";

logger.info(redact(requestBody));
```

### Reusable (recommended on hot paths)

`createRedactor` resolves options once and returns a fast, reusable function.

```ts
import { createRedactor } from "veilit";

const scrub = createRedactor({ keepLast: 4 });

scrub({ card: "4242424242424242" }); // → { card: "[REDACTED]4242" }
```

## What gets redacted

### By key name (default)

Keys are matched case- and separator-insensitively, so `apiKey`, `api_key`, `API-KEY`
and `apikey` are all treated alike. Innocent look-alikes such as `author`, `monkey`,
`keyboard` or `publicKey` are intentionally **not** matched.

`password`, `passwd`, `passphrase`, `secret`, `token`, `apiKey`, `accessKey`, `secretKey`,
`privateKey`, `encryptionKey`, `accessToken`, `refreshToken`, `idToken`, `authToken`,
`sessionToken`, `clientSecret`, `authorization`, `credential`, `creditCard`, `cardNumber`,
`securityCode`, `connectionString`, `sessionId`, `cookie`, `csrf`, `xsrf`, `auth`, `pwd`,
`pin`, `otp`, `ssn`, `dsn`, `salt`, `mfa`, `jwt`, `bearer`, `sid`, `cvv`, `cvc`, `totp`,
`seed`, `mnemonic`.

The full list is exported as `defaultSensitiveKeys`.

### By value pattern (default)

These are detected **wherever they appear**, even under a harmless key - the high-value
part of veilit. They're chosen to be high-severity and low-false-positive:

| Detector | Matches |
| --- | --- |
| `jwt` | JSON Web Tokens (`eyJ….….…`) |
| `creditCard` | 13–19 digit numbers that pass a **Luhn** check |
| `ssn` | US Social Security numbers (`123-45-6789`) |
| `awsAccessKey` | AWS access key IDs (`AKIA…`, `ASIA…`, …) |
| `githubToken` | GitHub PATs / OAuth / app tokens & fine-grained PATs |
| `slackToken` | Slack tokens (`xoxb-…`, `xoxp-…`, …) |
| `stripeKey` | Stripe secret & restricted keys (`sk_live_…`, `rk_…`) |
| `googleApiKey` | Google API keys (`AIza…`) |
| `privateKey` | PEM private keys (`-----BEGIN … PRIVATE KEY-----`) |
| `bearer` | `Bearer <token>` credentials embedded in strings |
| `urlPassword` | the password in `scheme://user:pass@host` (user & host kept) |

### Opt-in PII detectors

PII detectors are **off by default** (many apps legitimately log their own email
addresses or IPs). Enable the ones you want:

```ts
import { redact, detectors } from "veilit";

redact(data, { patterns: [detectors.email, detectors.ipv4, detectors.ipv6, detectors.usPhone] });
```

## Options

```ts
redact(value, {
  mask: "[REDACTED]",          // string, or (ctx) => string
  keys: ["internalId"],        // extra sensitive keys (string | RegExp)
  replaceDefaultKeys: false,   // replace the built-in key list entirely
  patterns: [detectors.email], // extra value detectors (ValueDetector | RegExp)
  replaceDefaultPatterns: false,
  detectValues: true,          // set false for the fastest key-only redaction
  keepLast: 0,                 // keep N trailing chars, e.g. "[REDACTED]4242"
  keyMatch: "smart",           // "smart" (default) | "exact"
  maxDepth: 20,                // guard against pathological structures
  truncated: "[TRUNCATED]",    // emitted past maxDepth
  circular: "[CIRCULAR]",      // emitted on circular references
});
```

### Custom mask with context

The mask can be a function, so you can label *why* something was redacted:

```ts
redact(data, {
  mask: (ctx) =>
    ctx.reason === "value" ? `[${ctx.detector}]` : `[redacted:${ctx.key}]`,
});
```

### Custom detectors

Add your own value patterns - a bare `RegExp` (the global flag is added for you)
or a full `ValueDetector` with optional validation and partial (capture-group) replacement:

```ts
redact(data, {
  patterns: [
    /INT-\d{6}/, // internal ticket ids
    {
      name: "employeeId",
      pattern: /EMP-(\d{4})/g,
      validate: (m) => m.length === 8,
    },
  ],
});
```

## Recipes

`veilit` is just a function, so it slots into whatever you already use.

**Pino** - redact every log line automatically:

```ts
import pino from "pino";
import { createRedactor } from "veilit";

const scrub = createRedactor();
const logger = pino({ formatters: { log: (o) => scrub(o) } });
```

**Sentry** - scrub events before they leave the process:

```ts
import * as Sentry from "@sentry/node";
import { createRedactor } from "veilit";

const scrub = createRedactor();
Sentry.init({ beforeSend: (event) => scrub(event) });
```

**Winston** - as a custom format:

```ts
import { format } from "winston";
import { createRedactor } from "veilit";

const scrub = createRedactor();
const redactFormat = format((info) => scrub(info));
```

**Express / Fastify** - scrub what you log in an error handler:

```ts
app.use((err, req, res, next) => {
  logger.error(redact({ err, body: req.body, headers: req.headers }));
  next(err);
});
```

## Behaviour notes & guarantees

- **Immutable.** The input is never modified; you get a fresh, redacted clone.
- **JSON-safe output.** Circular references become `"[CIRCULAR]"`, so the result is always serializable.
- **Structural clone.** Plain objects, arrays, `Map`, `Set`, `Date`, `RegExp` and `Error` are reconstructed; class instances become plain objects (what you want for logging). `Error`s become `{ name, message, stack, …ownProps, cause }` with everything scrubbed.
- **Binary is passed through.** `Buffer` / typed arrays are returned as-is (never expanded).
- **Not a substitute for not collecting secrets.** Redaction is a safety net. Detection is heuristic - value patterns can miss novel formats and can, rarely, over-redact. Treat it as defense-in-depth, and add domain-specific `keys`/`patterns` for your own secrets.

## API

| Export | Description |
| --- | --- |
| `redact(value, options?)` | Return a redacted deep clone of `value`. |
| `createRedactor(options?)` | Build a reusable redactor with fixed, pre-compiled options. |
| `detectors` | All named value detectors (built-in + opt-in PII) for cherry-picking. |
| `defaultDetectors` | The value detectors enabled by default. |
| `defaultSensitiveKeys` | The built-in sensitive-key list. |
| `normalizeKey(key)` | The key-normalisation helper used internally. |
| `luhnValid(digits)` | The Luhn checksum used by the card detector. |
| Types | `RedactOptions`, `RedactionContext`, `ValueDetector`, `KeyMatchStrategy`. |

## Performance

Redaction walks your value once. On the hot path use `createRedactor` so options are
compiled a single time, and pass `detectValues: false` if you only need key-based
redaction (skips all string scanning).

## Contributing

Issues and PRs welcome. `npm test` runs the suite, `npm run coverage`
for coverage, `npm run lint` / `npm run format` for Biome.

## License

[MIT](./LICENSE) © ashishtz
