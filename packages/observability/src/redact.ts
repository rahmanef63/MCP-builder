/**
 * The single redaction chokepoint (docs/10, docs/14). Everything that leaves
 * the process as text — logs, audit records — passes through here first.
 */
import { stripPaths } from "./paths"

/** Key names whose value is never safe to emit. */
const SENSITIVE_KEY = /token|secret|credential|password|authorization|api[-_]?key|cookie|bearer/i

/** `Authorization: Bearer <x>` style values that arrive as free text. */
const BEARER_VALUE = /\b(bearer)\s+\S+/gi

/**
 * This product's own credential grammar, `<prefix>_<id>_<secret>` — `@cg/auth`'s
 * `TOKEN_RE`, restated rather than imported so the log path keeps no dependency
 * on the auth package.
 *
 * The key-name rule above only fires when a secret arrives as the VALUE of a
 * field called `token`/`apiKey`/…, and `BEARER_VALUE` only when the word
 * "bearer" precedes it. A bare `cgk_…` pasted into a message — an upstream error
 * body echoing the header, an exception whose text embeds the URL — matches
 * neither and would be written out in full. Matching the shape itself closes
 * that, and a live credential is never something a log line needs.
 */
const CREDENTIAL_VALUE = /\bcg[a-z]_[A-Za-z0-9][A-Za-z0-9_-]{0,127}_[A-Za-z0-9-]{16,512}\b/g

/**
 * Well-known third-party credential shapes (adopted from SI-Coder's
 * lib/redact-env.js). Each has a vendor prefix that never occurs in real
 * content, so stripping them from tool output has no false positives on data a
 * caller asked for, and enforces AGENTS.md invariant 5 for upstream tokens that
 * an adapter echoes back. Deliberately no generic "long random run" rule:
 * commit SHAs and resource ids must survive.
 */
const PROVIDER_CREDENTIALS: readonly RegExp[] = [
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
  /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b/g,
  /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
]

function stripProviderCredentials(value: string): string {
  let out = value
  for (const pattern of PROVIDER_CREDENTIALS) out = out.replace(pattern, REDACTED)
  return out
}

/** `?token=…` / `&access_token=…` in a logged URL (adopted from MSO lib/orchestration/redaction.ts). Log path only. */
const QUERY_SECRET = /([?&](?:[a-z_]*token|key|api_key|secret|password|code|client_secret)=)[^&#\s]+/gi

export const REDACTED = "[redacted]"
const CIRCULAR = "[circular]"
const TRUNCATED = "[truncated]"
const MAX_DEPTH = 8

export function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY.test(key)
}

export function redactText(value: string): string {
  const masked = stripProviderCredentials(
    value.replace(QUERY_SECRET, `$1${REDACTED}`).replace(BEARER_VALUE, `$1 ${REDACTED}`).replace(CREDENTIAL_VALUE, REDACTED),
  )
  return stripPaths(masked)
}

/**
 * The narrow sibling of `redact`, for data a caller ASKED FOR.
 *
 * `redact` is right for logs: it blanks anything under a key called `token`,
 * strips absolute paths, and truncates depth, because nobody needs a log line's
 * fidelity. It is wrong for tool output. A connector that reads a config file
 * and returns a line containing `api_key = …` is doing its job, and blanking it
 * would answer a user's own question with `[redacted]` — the product breaking,
 * dressed as security.
 *
 * This strips ONE thing: a credential in THIS gateway's own grammar
 * (`<prefix>_<id>_<secret>`). That shape is never legitimate content in a
 * connector's answer — it can only be an upstream echoing back the header it
 * was called with — so removing it has no false positives on real data.
 *
 * What it deliberately does NOT do: key-name blanking, path stripping, depth
 * truncation. Those belong to the log path.
 */
export function stripCredentials(value: string): string {
  return stripProviderCredentials(value.replace(CREDENTIAL_VALUE, REDACTED))
}

/** `stripCredentials` over every string in a structure, shape preserved. */
export function stripCredentialsDeep(value: unknown): unknown {
  return stripWalk(value, 0, new Set<object>())
}

function stripWalk(value: unknown, depth: number, seen: Set<object>): unknown {
  if (typeof value === "string") return stripCredentials(value)
  if (value === null || typeof value !== "object") return value
  // Bounded like `walk`, but the limit RETURNS the value rather than replacing
  // it: this function must never be the reason a caller loses data it asked
  // for. Past the depth cap a credential is not stripped, which is the same
  // exposure as before this existed — a regression is impossible either way.
  if (depth >= MAX_DEPTH) return value
  const object = value as object
  if (seen.has(object)) return value
  seen.add(object)
  try {
    if (Array.isArray(value)) return value.map((item) => stripWalk(item, depth + 1, seen))
    const out: Record<string, unknown> = {}
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      out[key] = stripWalk(item, depth + 1, seen)
    }
    return out
  } finally {
    seen.delete(object)
  }
}

/**
 * Deep clone with secrets removed, absolute paths reduced to basenames,
 * cycles broken, and depth bounded. Never mutates the input.
 */
export function redact(value: unknown): unknown {
  return walk(value, 0, new Set<object>())
}

function walk(value: unknown, depth: number, seen: Set<object>): unknown {
  if (value === null || value === undefined) return value
  if (typeof value === "string") return redactText(value)
  if (typeof value === "number" || typeof value === "boolean") return value
  if (typeof value === "bigint") return value.toString()
  if (typeof value === "function" || typeof value === "symbol") return `[${typeof value}]`
  if (value instanceof Date) return value.toISOString()
  if (value instanceof Error) return redactError(value)

  if (depth >= MAX_DEPTH) return TRUNCATED
  const object = value as object
  if (seen.has(object)) return CIRCULAR
  seen.add(object)
  try {
    if (Array.isArray(value)) return value.map((item) => walk(item, depth + 1, seen))
    if (value instanceof Set) return Array.from(value, (item) => walk(item, depth + 1, seen))
    if (value instanceof Map) return redactEntries(Array.from(value), depth, seen)
    return redactEntries(Object.entries(value as Record<string, unknown>), depth, seen)
  } finally {
    // Released on exit so a value referenced twice by siblings is not a cycle.
    seen.delete(object)
  }
}

function redactEntries(
  entries: Array<[unknown, unknown]>,
  depth: number,
  seen: Set<object>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [rawKey, rawValue] of entries) {
    const key = typeof rawKey === "string" ? rawKey : String(rawKey)
    out[key] = isSensitiveKey(key) ? REDACTED : walk(rawValue, depth + 1, seen)
  }
  return out
}

function redactError(error: Error): Record<string, unknown> {
  // Stacks carry absolute source paths, so they are never emitted.
  return { name: error.name, message: redactText(error.message) }
}
