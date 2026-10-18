// @vitest-environment node
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest"
import { assertUpstreamEndpointUrl } from "@convex/_shared/upstream_url"
import { refreshOAuthToken } from "../../../gateway/src/store/token-refresh"
import { clientCredentialsGrant, exchangeCode, registerClient } from "./client"

const resource = "https://resource.example.com/mcp"

beforeEach(() => {
  for (const name of ["ALLOW_LOOPBACK_UPSTREAM", "UPSTREAM_BLOCKED_HOSTS", "CONVEX_SITE_URL", "CONVEX_CLOUD_URL"]) {
    vi.stubEnv(name, "")
  }
  vi.stubEnv("NODE_ENV", "test")
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
})

function flows(endpoint: string) {
  const options = { fetcher: fetch }
  return [
    () => exchangeCode({
      tokenEndpoint: endpoint, clientId: "fixture-client", clientSecret: null,
      code: "fixture-code", verifier: "fixture-verifier",
      redirectUri: "https://dashboard.example.com/callback", resource,
    }, options),
    () => clientCredentialsGrant({
      tokenEndpoint: endpoint, clientId: "fixture-client", clientSecret: "fixture-secret",
      scope: null, resource,
    }, options),
    () => registerClient(endpoint, "https://dashboard.example.com/callback", "Fixture", options),
    () => refreshOAuthToken({
      v: 1, grantType: "refresh_token", tokenEndpoint: endpoint,
      clientId: "fixture-client", clientSecret: null, refreshToken: "fixture-refresh",
      scope: null, resource,
    }, options),
  ]
}

function stubTransport() {
  const fetcher = vi.fn(async (_input: string | URL | Request, _init?: RequestInit) => new Response(JSON.stringify({
    access_token: "fixture-access", client_id: "fixture-client",
  })))
  vi.stubGlobal("fetch", fetcher)
  return fetcher
}

describe("initial OAuth requests and renewal share endpoint policy", () => {
  test.each([
    "https://auth.example.com:8443/token",
    "https://8.8.8.8/token",
    "https://[2606:4700:4700::1111]:8443/token",
    "HTTPS://AUTH.EXAMPLE.COM.:443//oauth/token/?tenant=one%2Ftwo",
  ])("all flows preserve an accepted endpoint: %s", async (endpoint) => {
    const fetcher = stubTransport()
    for (const flow of flows(endpoint)) await expect(flow()).resolves.toBeDefined()
    expect(fetcher).toHaveBeenCalledTimes(4)
    for (const [actual] of fetcher.mock.calls) {
      expect(actual).toBe(assertUpstreamEndpointUrl(endpoint))
    }
  })

  test.each([
    "http://auth.example.com/token",
    "https://auth.example.com:8080/token",
    "https://169.254.169.254/token",
    "https://127.0.0.1/token",
    "https://10.0.0.1/token",
    "https://[::ffff:192.168.1.1]/token",
    "https://[fec0::1]/token",
    "https://[64:ff9b:1::1]/token",
    "https://[2001:2::1]/token",
    "https://service.local/token",
    "https://internal/token",
    "https://connect.rahmanef.com./token",
    "https://user:fixture-secret@auth.example.com/token",
    "https://auth.example.com/token#fragment",
    "https://auth.example.com/token#",
  ])("all flows refuse an endpoint before sending credentials: %s", async (endpoint) => {
    const fetcher = stubTransport()
    expect(() => assertUpstreamEndpointUrl(endpoint)).toThrow()
    for (const flow of flows(endpoint)) {
      await expect(flow()).rejects.toMatchObject({ code: "invalid_endpoint" })
    }
    expect(fetcher).not.toHaveBeenCalled()
  })

  test("all flows block configured self hosts", async () => {
    vi.stubEnv("UPSTREAM_BLOCKED_HOSTS", "private.example.com.")
    vi.stubEnv("CONVEX_SITE_URL", "https://site.example.com")
    vi.stubEnv("CONVEX_CLOUD_URL", "https://cloud.example.com")
    const fetcher = stubTransport()
    for (const host of ["private.example.com", "site.example.com.", "cloud.example.com"]) {
      for (const flow of flows(`https://${host}/token`)) {
        await expect(flow()).rejects.toMatchObject({ code: "invalid_endpoint" })
      }
    }
    expect(fetcher).not.toHaveBeenCalled()
  })

  test.each(["1", "true"])("explicit local development accepts loopback for every flow: %s", async (flag) => {
    vi.stubEnv("ALLOW_LOOPBACK_UPSTREAM", flag)
    vi.stubEnv("CONVEX_SITE_URL", "http://localhost:3000")
    const fetcher = stubTransport()
    for (const flow of flows("http://localhost:3001/token?tenant=fixture")) {
      await expect(flow()).resolves.toBeDefined()
    }
    expect(fetcher).toHaveBeenCalledTimes(4)
  })

  test.each(["1", "true"])("production denies loopback even with development flag: %s", async (flag) => {
    vi.stubEnv("NODE_ENV", "production")
    vi.stubEnv("ALLOW_LOOPBACK_UPSTREAM", flag)
    const fetcher = stubTransport()
    for (const flow of flows("http://localhost:3001/token")) {
      await expect(flow()).rejects.toMatchObject({ code: "invalid_endpoint" })
    }
    expect(fetcher).not.toHaveBeenCalled()
  })
})
