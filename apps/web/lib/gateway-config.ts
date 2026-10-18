/**
 * Copy-ready client configuration for the Setup screen (docs/12).
 *
 * INVARIANT: a real credential appears in these snippets ONLY while the user is
 * looking at the key they just minted, and only because they passed it in. The
 * default is always the placeholder, nothing here reads storage, and a value
 * that is not a well-formed gateway key is redacted back to the placeholder
 * rather than pasted into a config block — AGENTS.md invariant 12 and the P0
 * "never write a real secret into a file" rule.
 */

export const API_KEY_PLACEHOLDER = "PASTE_YOUR_GATEWAY_API_KEY_HERE"
export const MCP_PATH = "/mcp"

/**
 * Shape of an AI-client API key: `cgk_<keyId>_<secret>`. Mirrors
 * `packages/auth/src/tokens.ts` (`TOKEN_RE`, prefix `TOKEN_PREFIXES.apiKey`) —
 * apps/web deliberately does not depend on @cg/auth, which is server crypto.
 * Capture group 1 is the key id, which is public; the secret is never captured
 * for display anywhere.
 */
export const API_KEY_TOKEN_PATTERN = /^cgk_([A-Za-z0-9][A-Za-z0-9_-]{0,127})_[A-Za-z0-9-]{16,512}$/

export function isApiKeyToken(value: unknown): value is string {
  return typeof value === "string" && API_KEY_TOKEN_PATTERN.test(value)
}

/**
 * The value a config block should carry: the live key while the user has it on
 * screen, the placeholder every other time. Half-typed or malformed input can
 * never reach a snippet — it redacts to the placeholder.
 */
export function apiKeyOrPlaceholder(key: string | null | undefined): string {
  return isApiKeyToken(key) ? key : API_KEY_PLACEHOLDER
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"])

/**
 * Validate NEXT_PUBLIC_GATEWAY_URL (an env var — a trust boundary) and return
 * its canonical origin form, or null. Plain http is only tolerated on loopback.
 */
export function normalizeGatewayUrl(raw: string | undefined | null): string | null {
  if (typeof raw !== "string" || raw.trim().length === 0) return null

  let url: URL
  try {
    url = new URL(raw.trim())
  } catch {
    return null
  }

  if (url.protocol !== "https:" && url.protocol !== "http:") return null
  if (url.protocol === "http:" && !LOOPBACK_HOSTS.has(url.hostname)) return null
  if (url.username !== "" || url.password !== "") return null

  const path = url.pathname.replace(/\/+$/, "")
  return `${url.origin}${path}`
}

/**
 * The gateway origin this deployment should advertise, or null if it cannot be
 * known.
 *
 * Three sources, in order of how much they are worth trusting:
 *
 * 1. `NEXT_PUBLIC_GATEWAY_URL` — set explicitly. The only one that can name a
 *    SEPARATE gateway deployment (the Bun edge on its own domain), so it wins
 *    unconditionally.
 * 2. `NEXT_PUBLIC_VERCEL_PROJECT_PRODUCTION_URL` — this project's stable
 *    production hostname. Correct for the single-origin Vercel deploy of
 *    docs/20, where the dashboard and the gateway are the same app.
 * 3. `NEXT_PUBLIC_VERCEL_URL` — this ONE deployment's hostname. A preview
 *    build's own address; useful for looking at a preview, never for a client
 *    that has to keep working after the next push.
 *
 * Each is spelled as a literal `process.env.NEXT_PUBLIC_*` member access
 * because that is what Next inlines at build time — a computed lookup resolves
 * to undefined in the bundle. Every value is public by definition (they are all
 * hostnames) and each is re-validated by `normalizeGatewayUrl`.
 */
export function publicGatewayUrl(): string | null {
  const explicit = normalizeGatewayUrl(process.env.NEXT_PUBLIC_GATEWAY_URL)
  if (explicit !== null) return explicit

  const production = (process.env.NEXT_PUBLIC_VERCEL_PROJECT_PRODUCTION_URL ?? "").trim()
  if (production.length > 0) return normalizeGatewayUrl(`https://${production}`)

  const preview = (process.env.NEXT_PUBLIC_VERCEL_URL ?? "").trim()
  if (preview.length > 0) return normalizeGatewayUrl(`https://${preview}`)

  return null
}

export function mcpEndpoint(gatewayUrl: string): string {
  return `${gatewayUrl.replace(/\/+$/, "")}${MCP_PATH}`
}

export type McpClient = "claude-code" | "cursor" | "claude-desktop"

/**
 * Client-specific `mcpServers` entry. Desktop uses a stdio bridge.
 *
 * `apiKey` is the key the user minted a moment ago, held in React state for the
 * length of the page view. Omit it — or pass anything malformed — and the block
 * carries the placeholder instead.
 */
export function mcpClientConfig(
  gatewayUrl: string,
  apiKey?: string | null,
  client: McpClient = "claude-code",
): string {
  const authorization = `Bearer ${apiKeyOrPlaceholder(apiKey)}`
  const endpoint = mcpEndpoint(gatewayUrl)
  const server = client === "claude-desktop"
    ? {
        command: "npx",
        args: ["-y", "mcp-remote", endpoint, "--header", "Authorization:${AUTH_HEADER}"],
        env: { AUTH_HEADER: authorization },
      }
    : {
        ...(client === "claude-code" ? { type: "http" } : {}),
        url: endpoint,
        headers: { Authorization: authorization },
      }
  return JSON.stringify(
    {
      mcpServers: {
        "connectors-gateway": server,
      },
    },
    null,
    2,
  )
}

/**
 * One-liner a user can paste into a terminal to prove the key works.
 *
 * `/v1/catalog`, not `/healthz`: the health probe is unauthenticated, so it
 * answers 200 for a key that is expired, revoked, or simply mistyped — a check
 * that passes whatever you paste is worse than no check. The catalog is the
 * cheapest route that actually reads the token, and its answer doubles as "here
 * is what this key can see".
 */
export function verifyCommand(gatewayUrl: string, apiKey?: string | null): string {
  return [
    "curl -fsS",
    `-H "Authorization: Bearer ${apiKeyOrPlaceholder(apiKey)}"`,
    quoteShell(`${gatewayUrl.replace(/\/+$/, "")}/v1/catalog`),
  ].join(" ")
}

/** Env block for the local agent (docs/04) — relay URL only, no secret. */
export function agentEnvSnippet(gatewayUrl: string): string {
  const relay = gatewayUrl.replace(/\/+$/, "").replace(/^http/, "ws")
  return `CG_GATEWAY_URL=${quoteShell(`${relay}/device`)}`
}

/** Keep URLs literal when copied into a POSIX shell, including apostrophes. */
function quoteShell(value: string): string {
  return "'" + value.replace(/'/g, "'\"'\"'") + "'"
}
