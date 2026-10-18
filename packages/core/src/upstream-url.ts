import { GatewayError } from "./errors"
import { blockedRange, isLoopback } from "./ip-address"

const MAX_URL_LENGTH = 2048
const ALLOWED_PORTS: ReadonlySet<string> = new Set(["", "443", "8443"])
const DEFAULT_SELF_HOSTS = [
  "api-connectors.rahmanef.com",
  "site-connectors.rahmanef.com",
  "dash-connectors.rahmanef.com",
  "connect.rahmanef.com",
] as const

export type UpstreamUrlPolicy = {
  readonly allowLoopback?: boolean
  readonly blockedHosts?: readonly string[]
}

/** Pure configuration adapter: runtimes supply their own environment values. */
export function upstreamUrlPolicyFromEnvironment(
  environment: Readonly<Record<string, string | undefined>>,
): UpstreamUrlPolicy {
  const blockedHosts = (environment.UPSTREAM_BLOCKED_HOSTS ?? "").split(",")
  for (const key of ["CONVEX_CLOUD_URL", "CONVEX_SITE_URL"]) {
    const own = parseUrl(environment[key] ?? "")
    if (own !== null && !isLoopback(own.hostname)) blockedHosts.push(own.hostname)
  }
  return {
    allowLoopback: environment.NODE_ENV !== "production" &&
      (environment.ALLOW_LOOPBACK_UPSTREAM === "1" || environment.ALLOW_LOOPBACK_UPSTREAM === "true"),
    blockedHosts,
  }
}

/** Stored base identity: canonical origin/path without query, fragment or trailing slash. */
export function normalizeUpstreamUrl(value: string, policy: UpstreamUrlPolicy = {}): string {
  const url = validatedUrl(value, policy)
  return `${url.origin}${url.pathname.replace(/\/{2,}/g, "/").replace(/\/+$/, "")}`
}

/** Fetch endpoint: preserve path/query semantics; fragments cannot identify a server endpoint. */
export function normalizeUpstreamEndpointUrl(value: string, policy: UpstreamUrlPolicy = {}): string {
  const url = validatedUrl(value, policy)
  if (url.href.includes("#")) invalid("Upstream endpoint must not contain a fragment.")
  return url.href
}

function validatedUrl(value: string, policy: UpstreamUrlPolicy): URL {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_URL_LENGTH) {
    invalid("Base URL is missing or too long.")
  }
  const url = parseUrl(value.trim())
  if (url === null) invalid("Base URL is not a valid absolute URL.")
  if (url.username !== "" || url.password !== "") invalid("Base URL must not contain credentials.")

  const host = canonicalHost(url.hostname)
  if (host.length === 0) invalid("Base URL is not a valid absolute URL.")
  url.hostname = host
  const devLoopback = policy.allowLoopback === true && isLoopback(host)
  if (url.protocol !== "https:" && !(url.protocol === "http:" && devLoopback)) {
    invalid("Base URL must use https.")
  }
  if (
    !devLoopback &&
    (blockedRange(host) !== null || isLoopback(host) || host.endsWith(".local") || (!host.includes(".") && !host.includes(":")))
  ) {
    invalid("Base URL host is in a private or reserved address range.")
  }
  const selfHosts = new Set<string>(DEFAULT_SELF_HOSTS)
  for (const entry of policy.blockedHosts ?? []) {
    const blocked = canonicalHost(entry.trim())
    if (blocked.length > 0) selfHosts.add(blocked)
  }
  if (selfHosts.has(host)) invalid("Base URL must not point back at this deployment.")
  if (!devLoopback && !ALLOWED_PORTS.has(url.port)) invalid("Base URL must use port 443 or 8443.")
  return url
}

function canonicalHost(host: string): string {
  return host.toLowerCase().replace(/\.+$/, "")
}

function parseUrl(value: string): URL | null {
  try {
    return new URL(value)
  } catch {
    return null
  }
}

function invalid(message: string): never {
  throw new GatewayError("INVALID_INPUT", message)
}
