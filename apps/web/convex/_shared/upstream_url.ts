/**
 * Storage-time and OAuth URL checks share the core policy. DNS resolution and
 * connection pinning belong to the server transport, after this pure check.
 */
import {
  GatewayError,
  normalizeUpstreamEndpointUrl,
  normalizeUpstreamUrl,
  upstreamUrlPolicyFromEnvironment,
} from "@cg/core"
import { fail } from "./errors"

export function assertUpstreamUrl(value: string): string {
  return mapPolicyError(() => normalizeUpstreamUrl(value, upstreamUrlPolicyFromEnvironment(process.env)))
}

export function assertUpstreamEndpointUrl(value: string): string {
  return mapPolicyError(() => normalizeUpstreamEndpointUrl(value, upstreamUrlPolicyFromEnvironment(process.env)))
}

function mapPolicyError(validate: () => string): string {
  try {
    return validate()
  } catch (error) {
    if (error instanceof GatewayError) fail(error.code, error.message)
    throw error
  }
}
