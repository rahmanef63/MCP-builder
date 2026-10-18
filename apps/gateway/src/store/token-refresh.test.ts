import { describe, expect, test } from "bun:test"
import type { OAuthRenewal } from "@cg/core"
import {
  OAuthRefreshError,
  credentialNeedsRefresh,
  refreshOAuthToken,
} from "./token-refresh"

const NOW = 1_700_000_000_000
const refresh: OAuthRenewal = {
  v: 1,
  grantType: "refresh_token",
  tokenEndpoint: "https://auth.example.test/oauth/token",
  clientId: "client_1",
  clientSecret: "client_secret_1",
  refreshToken: "refresh_secret_1",
  scope: "mcp.read",
  resource: "https://api.example.test/mcp",
}

function response(document: unknown, status = 200): Response {
  return new Response(JSON.stringify(document), { status })
}

describe("refreshOAuthToken", () => {
  test("refreshes with the exact grant and preserves the old refresh token", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = []
    const result = await refreshOAuthToken(refresh, {
      now: () => NOW,
      fetcher: async (input, init = {}) => {
        calls.push({ url: String(input), init })
        return response({ access_token: "access_2", expires_in: 3600 })
      },
    })

    expect(result).toEqual({
      accessToken: "access_2",
      tokenExpiresAt: NOW + 3_600_000,
      renewal: refresh,
    })
    expect(calls).toHaveLength(1)
    expect(calls[0]?.url).toBe(refresh.tokenEndpoint)
    expect(calls[0]?.init.redirect).toBe("manual")
    expect(new Headers(calls[0]?.init.headers).get("authorization")).toBeNull()
    const body = new URLSearchParams(String(calls[0]?.init.body))
    expect(body.get("grant_type")).toBe("refresh_token")
    expect(body.get("refresh_token")).toBe("refresh_secret_1")
    expect(body.get("client_secret")).toBe("client_secret_1")
    expect(body.get("resource")).toBe(refresh.resource)
  })

  test("persists refresh-token rotation", async () => {
    const result = await refreshOAuthToken(refresh, {
      now: () => NOW,
      fetcher: async () =>
        response({ access_token: "access_2", expires_in: 120, refresh_token: "refresh_secret_2" }),
    })
    expect(result.renewal).toEqual({ ...refresh, refreshToken: "refresh_secret_2" })
  })

  test("renews client credentials without a refresh_token field", async () => {
    const machine: OAuthRenewal = {
      v: 1,
      grantType: "client_credentials",
      tokenEndpoint: "https://auth.example.test/oauth/token",
      clientId: "machine_1",
      clientSecret: "machine_secret_1",
      scope: null,
      resource: "https://api.example.test/mcp",
    }
    let body = new URLSearchParams()
    const result = await refreshOAuthToken(machine, {
      fetcher: async (_input, init = {}) => {
        body = new URLSearchParams(String(init.body))
        return response({ access_token: "machine_access" })
      },
    })
    expect(result).toEqual({ accessToken: "machine_access", renewal: machine })
    expect(body.get("grant_type")).toBe("client_credentials")
    expect(body.get("client_secret")).toBe("machine_secret_1")
    expect(body.get("refresh_token")).toBeNull()
  })

  test("a permanent OAuth refusal is typed but never repeats its secrets", async () => {
    try {
      await refreshOAuthToken(refresh, {
        fetcher: async () => response({ error: "invalid_grant", error_description: refresh.refreshToken }, 400),
      })
      throw new Error("expected refresh failure")
    } catch (error) {
      expect(error).toBeInstanceOf(OAuthRefreshError)
      expect(error).toMatchObject({ code: "invalid_grant", permanent: true })
      expect(String(error)).not.toContain(refresh.refreshToken)
      expect(String(error)).not.toContain(refresh.clientSecret ?? "")
    }
  })

  test("network and server failures remain retryable", async () => {
    await expect(
      refreshOAuthToken(refresh, { fetcher: async () => response({ error: "server_error" }, 503) }),
    ).rejects.toMatchObject({ permanent: false })
    await expect(
      refreshOAuthToken(refresh, { fetcher: async () => { throw new Error("offline") } }),
    ).rejects.toMatchObject({ code: "network_error", permanent: false })
  })

  test("refuses redirects and private/local endpoints without a second request", async () => {
    let calls = 0
    await expect(
      refreshOAuthToken(refresh, {
        fetcher: async () => {
          calls += 1
          return new Response(null, { status: 307, headers: { location: "https://evil.test" } })
        },
      }),
    ).rejects.toMatchObject({ code: "redirect_refused", permanent: true })
    expect(calls).toBe(1)

    await expect(
      refreshOAuthToken({ ...refresh, tokenEndpoint: "http://169.254.169.254/token" }),
    ).rejects.toMatchObject({ code: "invalid_endpoint", permanent: true })
  })

  test("refuses a success document with no access token", async () => {
    await expect(
      refreshOAuthToken(refresh, { fetcher: async () => response({ expires_in: 60 }) }),
    ).rejects.toMatchObject({ code: "invalid_response", permanent: false })
  })
})

describe("credentialNeedsRefresh", () => {
  test("refreshes within one minute, but not an unknown or distant expiry", () => {
    expect(credentialNeedsRefresh(undefined, NOW)).toBe(false)
    expect(credentialNeedsRefresh(NOW + 60_001, NOW)).toBe(false)
    expect(credentialNeedsRefresh(NOW + 60_000, NOW)).toBe(true)
    expect(credentialNeedsRefresh(NOW - 1, NOW)).toBe(true)
  })
})

test("a refresh response that reduces the requested provider scope fails permanently", async () => {
  const renewal = { ...refresh, scope: "read write delete" }
  const error = await refreshOAuthToken(renewal, {
    fetcher: async () => response({ access_token: "next_access", expires_in: 3600, scope: "read write" }),
  }).catch((cause: unknown) => cause)
  expect(error).toBeInstanceOf(OAuthRefreshError)
  expect((error as OAuthRefreshError).code).toBe("invalid_scope")
  expect((error as OAuthRefreshError).permanent).toBe(true)
})

test("an omitted refresh scope preserves the originally-authorized scope", async () => {
  const renewal = { ...refresh, scope: "read write" }
  const result = await refreshOAuthToken(renewal, {
    fetcher: async () => response({ access_token: "next_access", expires_in: 3600 }),
  })
  expect(result.renewal.scope).toBe("read write")
})

describe("renewal endpoint policy boundary", () => {
  test.each([
    "http://auth.example.test/oauth/token",
    "https://auth.example.test:8080/oauth/token",
    "https://user:fixture-secret@auth.example.test/oauth/token",
    "https://localhost/oauth/token",
    "https://bridge.localhost/oauth/token",
    "https://printer.local/oauth/token",
    "https://singlelabel/oauth/token",
    "https://169.254.169.254/oauth/token",
    "https://[::ffff:127.0.0.1]/oauth/token",
    "https://auth.example.test/oauth/token#fragment",
    "https://connect.rahmanef.com/oauth/token",
  ])("rejects %s before forwarding the renewal credential", async (tokenEndpoint) => {
    let calls = 0
    await expect(refreshOAuthToken({ ...refresh, tokenEndpoint }, {
      fetcher: async () => {
        calls += 1
        return response({ access_token: "unexpected" })
      },
    })).rejects.toMatchObject({ code: "invalid_endpoint", permanent: true })
    expect(calls).toBe(0)
  })

  test("retains reviewed alternate TLS port and endpoint query semantics", async () => {
    let received = ""
    await refreshOAuthToken({
      ...refresh,
      tokenEndpoint: "https://AUTH.EXAMPLE.TEST.:8443/oauth/token?tenant=fixture",
    }, {
      fetcher: async (input) => {
        received = String(input)
        return response({ access_token: "fixture-access" })
      },
    })
    expect(received).toBe("https://auth.example.test:8443/oauth/token?tenant=fixture")
  })
})
