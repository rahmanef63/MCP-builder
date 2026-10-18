import { describe, expect, test } from "bun:test"
import { GatewayError } from "./errors"
import {
  normalizeUpstreamEndpointUrl,
  normalizeUpstreamUrl,
  upstreamUrlPolicyFromEnvironment,
} from "./upstream-url"

describe("shared upstream URL policy", () => {
  for (const endpoint of [
    "https://auth.example.com/token",
    "https://auth.example.com:8443/token",
    "https://8.8.8.8/token",
    "https://[2606:4700:4700::1111]:8443/token",
  ]) {
    test(`accepts hosted/public endpoint ${endpoint}`, () => {
      expect(normalizeUpstreamEndpointUrl(endpoint)).toBe(endpoint)
      expect(normalizeUpstreamUrl(endpoint)).toBe(endpoint)
    })
  }

  for (const endpoint of [
    "http://auth.example.com/token", "ftp://auth.example.com/token",
    "https://auth.example.com:8080/token", "https://user:secret@auth.example.com/token",
    "https://169.254.169.254/token", "https://10.0.0.1/token", "https://192.168.1.1/token",
    "https://127.0.0.1/token", "https://2130706433/token", "https://0x7f.1/token",
    "https://[::1]/token", "https://[::ffff:10.0.0.1]/token", "https://[fc00::1]/token",
    "https://localhost./token", "https://service.localhost/token", "https://service.local/token",
    "https://internal/token", "https://connect.rahmanef.com./token",
    "https://api-connectors.rahmanef.com/token", "https://./token", "", "/token",
    `https://auth.example.com/${"a".repeat(2048)}`,
  ]) {
    test(`base and endpoint reject ${endpoint}`, () => {
      for (const normalize of [normalizeUpstreamUrl, normalizeUpstreamEndpointUrl]) {
        expect(() => normalize(endpoint)).toThrow(GatewayError)
        try { normalize(endpoint) } catch (error) {
          expect(error).toMatchObject({ code: "INVALID_INPUT" })
          expect(String(error)).not.toContain(endpoint || "secret")
        }
      }
    })
  }

  test("base identity stays canonical while endpoint path/query stay intact", () => {
    const raw = " HTTPS://Auth.Example.Com.:443//oauth/token/?audience=one%2Ftwo "
    expect(normalizeUpstreamUrl(raw)).toBe("https://auth.example.com/oauth/token")
    expect(normalizeUpstreamEndpointUrl(raw)).toBe("https://auth.example.com//oauth/token/?audience=one%2Ftwo")
    expect(normalizeUpstreamUrl("https://auth.example.com/token?q=1#fragment")).toBe("https://auth.example.com/token")
    for (const fragment of ["#fragment", "#"]) {
      expect(() => normalizeUpstreamEndpointUrl(`https://auth.example.com/token${fragment}`)).toThrow(GatewayError)
    }
  })

  test("self-host configuration adds to built-in hosts and canonicalizes DNS root labels", () => {
    const policy = upstreamUrlPolicyFromEnvironment({
      UPSTREAM_BLOCKED_HOSTS: " CUSTOM.Example.Com. , blocked.example.com ",
      CONVEX_SITE_URL: "https://site.example.com/",
      CONVEX_CLOUD_URL: "https://cloud.example.com/",
    })
    for (const host of ["custom.example.com", "blocked.example.com.", "site.example.com", "cloud.example.com.", "connect.rahmanef.com"]) {
      expect(() => normalizeUpstreamEndpointUrl(`https://${host}/token`, policy)).toThrow(GatewayError)
    }
    expect(normalizeUpstreamEndpointUrl("https://auth.example.com/token", policy)).toBe("https://auth.example.com/token")
  })

  test("loopback requires explicit 1/true configuration in both URL modes", () => {
    for (const setting of [undefined, "0", "false", "TRUE", "yes", "1", "true"]) {
      const policy = upstreamUrlPolicyFromEnvironment({
        ALLOW_LOOPBACK_UPSTREAM: setting,
        CONVEX_SITE_URL: "http://localhost:3000",
      })
      for (const endpoint of ["http://localhost:3001/token", "http://127.2.3.4:8888/token", "https://[::1]:444/token"]) {
        for (const normalize of [normalizeUpstreamUrl, normalizeUpstreamEndpointUrl]) {
          if (setting === "1" || setting === "true") expect(normalize(endpoint, policy)).toBe(endpoint)
          else expect(() => normalize(endpoint, policy)).toThrow(GatewayError)
        }
      }
      for (const endpoint of ["http://10.0.0.1/token", "https://169.254.169.254/token", "https://service.local/token"]) {
        expect(() => normalizeUpstreamEndpointUrl(endpoint, policy)).toThrow(GatewayError)
      }
    }
  })

  test("explicitly blocked loopback stays blocked with the development flag", () => {
    expect(() => normalizeUpstreamEndpointUrl("http://localhost:3000/token", {
      allowLoopback: true,
      blockedHosts: ["localhost"],
    })).toThrow(GatewayError)
  })
})

test("production environment never enables loopback through the development flag", () => {
  for (const flag of ["1", "true"]) {
    const policy = upstreamUrlPolicyFromEnvironment({ NODE_ENV: "production", ALLOW_LOOPBACK_UPSTREAM: flag })
    expect(policy.allowLoopback).toBe(false)
    for (const normalize of [normalizeUpstreamUrl, normalizeUpstreamEndpointUrl]) {
      expect(() => normalize("http://localhost:3000/token", policy)).toThrow(GatewayError)
    }
  }
})
