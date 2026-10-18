import { fail } from "./errors"
import { assertUpstreamUrl } from "./upstream_url"

const COMPOSIO_ORIGIN = "https://backend.composio.dev"
const COMPOSIO_MCP_PATH = /^\/v3\/mcp\/[A-Za-z0-9_-]+$/
const MAX_COMPOSIO_USER_ID_LENGTH = 256

/** Preserve only Composio's non-secret user selector; credentials stay sealed. */
export function assertConnectionUrl(connectorId: string, value: string): string {
  const normalized = assertUpstreamUrl(value)
  if (connectorId !== "composio") return normalized

  const target = new URL(normalized)
  const supplied = new URL(value.trim())
  if (
    target.origin !== COMPOSIO_ORIGIN ||
    !COMPOSIO_MCP_PATH.test(target.pathname) ||
    supplied.search === ""
  ) {
    return normalized
  }

  const entries = [...supplied.searchParams]
  const entry = entries[0]
  if (
    entries.length !== 1 ||
    entry?.[0] !== "user_id" ||
    entry[1].trim().length === 0 ||
    entry[1].length > MAX_COMPOSIO_USER_ID_LENGTH ||
    /[\x00-\x1f\x7f]/.test(entry[1])
  ) {
    fail("INVALID_INPUT", "Composio MCP URL must contain only one nonempty user_id.")
  }

  // Re-encode the value so embedded delimiters remain part of the identifier.
  return `${normalized}?${new URLSearchParams([["user_id", entry[1]]])}`
}
