/**
 * Credential-shaped elicitation detection.
 *
 * The MCP specification says, of form-mode elicitation:
 *
 * > *"Servers **MUST NOT** use form mode elicitation to request passwords, API keys, access
 * > tokens, or payment credentials."*
 *
 * That is a norm with no enforcement anywhere in the ecosystem. No client checks it. A malicious —
 * or merely lazy — server puts `{ "api_key": { "type": "string", "title": "API key" } }` in a
 * `requestedSchema`, the client renders a perfectly ordinary form, and the user types a live
 * credential into a dialog controlled by the untrusted party. A proxy sits exactly where this can
 * be checked, so it checks it (RESEARCH-BRIEF §4.5.3).
 *
 * ## Why this is a near-zero-false-positive rule, unlike text scanning
 *
 * It does not read prose looking for hostile intent. It reads **property names, titles and
 * `format` values in a JSON Schema** — a small, structured, machine-authored vocabulary — and
 * matches whole tokens against a short list of words that name a secret. A legitimate elicitation
 * asks for a branch name, a channel, a confirmation, a date. It does not have a property called
 * `password`, and if it does, the spec already forbids it. The failure mode is bounded: we deny a
 * request the specification says must not be sent.
 *
 * Tokenisation splits `camelCase`, `snake_case`, `kebab-case` and `dot.case`, so `apiKey`,
 * `api_key`, `API-KEY` and `auth.token` are the same to us and neither casing nor punctuation is
 * an evasion.
 */

export type CredentialConfidence = "definite" | "likely";

export interface CredentialMatch {
  /** JSON Pointer to the offending property inside `requestedSchema`. */
  readonly pointer: string;
  /** The property name as written by the server. */
  readonly property: string;
  /** Which field carried the signal. */
  readonly source: "name" | "title" | "format" | "description";
  /** The matched vocabulary entry, e.g. `"api key"`. */
  readonly matched: string;
  readonly confidence: CredentialConfidence;
}

export interface CredentialScan {
  /** True when at least one `definite` match exists. */
  readonly credentialShaped: boolean;
  readonly matches: readonly CredentialMatch[];
}

/** Single tokens that name a secret on their own. Kept short on purpose. */
const SINGLE: readonly string[] = [
  "password",
  "passwd",
  "passphrase",
  "apikey",
  "secret",
  "credential",
  "credentials",
  "mnemonic",
  "cvv",
  "cvc",
  "iban",
  "otp",
  "totp",
  // Note what is NOT here: "key" and "token" alone. "encryption key format", "token limit",
  // "max tokens" and "key name" are ordinary parameters, and a rule that fires on them would be
  // the high-false-positive kind this project refuses to ship. They only count in the pairs below.
];

/** Ordered token pairs. Both tokens must be present, in order, adjacent-or-not within the name. */
const PAIRS: readonly (readonly [string, string])[] = [
  ["api", "key"],
  ["api", "secret"],
  ["access", "token"],
  ["refresh", "token"],
  ["auth", "token"],
  ["bearer", "token"],
  ["session", "token"],
  ["id", "token"],
  ["private", "key"],
  ["secret", "key"],
  ["client", "secret"],
  ["ssh", "key"],
  ["signing", "key"],
  ["seed", "phrase"],
  ["recovery", "phrase"],
  ["recovery", "code"],
  ["backup", "code"],
  ["card", "number"],
  ["security", "code"],
  ["social", "security"],
  ["routing", "number"],
  ["pin", "code"],
  ["mfa", "code"],
  ["2fa", "code"],
  ["one", "time"],
];

/** `format` values that name a secret input. `"password"` is the standard one. */
const FORMATS: readonly string[] = ["password"];

/** Split camelCase / snake_case / kebab-case / dot.case into lowercase tokens. */
export function tokenize(text: string): string[] {
  return text
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .map((t) => t.toLowerCase())
    .filter((t) => t.length > 0);
}

/**
 * Forms written with no separator at all, which tokenisation cannot split. Matched as a substring
 * of the concatenated tokens. Kept to an explicit list rather than substring-matching the whole
 * vocabulary: `secret` as a substring also matches `secretary`, and inventing that false positive
 * to catch a spelling nobody uses is a bad trade.
 */
const GLUED: readonly string[] = ["apikey", "apisecret", "accesstoken", "refreshtoken", "authtoken", "privatekey", "secretkey", "clientsecret", "seedphrase", "cardnumber"];

function matchTokens(tokens: readonly string[]): string | undefined {
  const joined = tokens.join("");
  for (const s of SINGLE) {
    if (tokens.includes(s)) return s;
  }
  for (const g of GLUED) {
    if (joined.includes(g)) return g;
  }
  for (const [a, b] of PAIRS) {
    const i = tokens.indexOf(a);
    if (i >= 0 && tokens.indexOf(b, i + 1) >= 0) return `${a} ${b}`;
  }
  return undefined;
}

const MAX_PROPERTIES = 200;
const MAX_DEPTH = 6;

/**
 * Scan an elicitation `requestedSchema` for credential-shaped inputs.
 *
 * Walks nested `properties` because a server can bury the field one object deep; depth and
 * property count are capped so a hostile schema cannot turn the check into a denial of service.
 */
export function scanRequestedSchema(schema: unknown): CredentialScan {
  const matches: CredentialMatch[] = [];
  let visited = 0;

  walk(schema, "");

  return { credentialShaped: matches.some((m) => m.confidence === "definite"), matches };

  function walk(node: unknown, pointer: string, depth = 0): void {
    if (depth > MAX_DEPTH || node === null || typeof node !== "object" || Array.isArray(node)) return;
    const n = node as Record<string, unknown>;
    const props = n["properties"];
    if (props === null || typeof props !== "object" || Array.isArray(props)) return;

    for (const [name, sub] of Object.entries(props as Record<string, unknown>)) {
      if (++visited > MAX_PROPERTIES) return;
      const at = `${pointer}/properties/${name.replace(/~/g, "~0").replace(/\//g, "~1")}`;
      const subObj = sub !== null && typeof sub === "object" && !Array.isArray(sub) ? (sub as Record<string, unknown>) : {};

      const format = subObj["format"];
      if (typeof format === "string" && FORMATS.includes(format.toLowerCase())) {
        matches.push({ pointer: at, property: name, source: "format", matched: format.toLowerCase(), confidence: "definite" });
      }

      const byName = matchTokens(tokenize(name));
      if (byName !== undefined) {
        matches.push({ pointer: at, property: name, source: "name", matched: byName, confidence: "definite" });
      }

      const title = subObj["title"];
      if (typeof title === "string") {
        const byTitle = matchTokens(tokenize(title));
        if (byTitle !== undefined) {
          matches.push({ pointer: at, property: name, source: "title", matched: byTitle, confidence: "definite" });
        }
      }

      // Description is prose and therefore the weak signal: "we will never ask for your password"
      // is a sentence a legitimate server might write. Recorded, never sufficient on its own.
      const description = subObj["description"];
      if (typeof description === "string" && description.length <= 2048) {
        const byDesc = matchTokens(tokenize(description));
        if (byDesc !== undefined && byName === undefined) {
          matches.push({ pointer: at, property: name, source: "description", matched: byDesc, confidence: "likely" });
        }
      }

      walk(subObj, at, depth + 1);
    }
  }
}
