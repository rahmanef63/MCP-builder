/**
 * Where every connector's consent screen sends the browser back.
 *
 * One route for all of them: which connector this code belongs to is in the
 * sealed flow-state cookie, not in the URL, so nothing here trusts a query
 * parameter to decide what gets written.
 *
 * The code is redeemed SERVER-SIDE and the resulting token is sealed before it
 * is stored. It never reaches the browser, is never logged, and Convex receives
 * ciphertext it cannot open.
 */
import { NextResponse } from "next/server"
import { encodeOAuthRenewal } from "@cg/core"
import { fetchMutation } from "convex/nextjs"

import { api } from "@convex/_generated/api"
import { requireViewer } from "@/app/(app)/connections/connect-support"
import { manifestFor } from "@/lib/catalog"
import { sealCredential } from "@/lib/credentials"
import { exchangeCode, tokenExpiresAt } from "@/lib/oauth/client"
import { clearFlowState, readFlowState } from "@/lib/oauth/state"
import type { ConnectErrorCode } from "@/components/connections/labels"

export const dynamic = "force-dynamic"

const DESTINATION = "/connections"

function back(request: Request, params: Record<string, string>): NextResponse {
  const url = new URL(DESTINATION, request.url)
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value)
  return NextResponse.redirect(url)
}

const failed = (request: Request, code: ConnectErrorCode): NextResponse =>
  back(request, { connect_error: code })

export async function GET(request: Request): Promise<NextResponse> {
  const params = new URL(request.url).searchParams
  const flow = await readFlowState()
  // Read once, then gone: a code can only be redeemed once, so a second visit
  // to this URL must not find a live flow to replay against.
  await clearFlowState()

  if (flow === null) return failed(request, "flow_expired")
  // The authorization server said no (usually the user pressed Cancel).
  if (params.get("error") !== null) return failed(request, "consent_denied")
  // Constant-time is not needed: `state` is single-use and this comparison
  // reveals nothing an attacker who already holds the value does not have.
  if (params.get("state") !== flow.state) return failed(request, "state_mismatch")

  const code = params.get("code") ?? ""
  if (code.length === 0) return failed(request, "consent_denied")

  const manifest = manifestFor(flow.connectorId)
  if (manifest === null || typeof manifest.endpoint !== "string") {
    return failed(request, "unknown_connector")
  }

  const viewer = await requireViewer()
  if (viewer === null) return failed(request, "not_signed_in")
  if (viewer.userId !== flow.userId) return failed(request, "state_mismatch")
  const { token } = viewer

  try {
    const issued = await exchangeCode({
      tokenEndpoint: flow.tokenEndpoint,
      code,
      redirectUri: flow.redirectUri,
      clientId: flow.clientId,
      clientSecret: flow.clientSecret,
      verifier: flow.verifier,
      resource: flow.resource,
    })
    const expiresAt = tokenExpiresAt(issued)
    const renewalCipher =
      issued.refreshToken === null || expiresAt === null
        ? undefined
        : await sealCredential(
            encodeOAuthRenewal({
              v: 1,
              grantType: "refresh_token",
              tokenEndpoint: flow.tokenEndpoint,
              clientId: flow.clientId,
              clientSecret: flow.clientSecret,
              refreshToken: issued.refreshToken,
              scope: flow.scope,
              resource: flow.resource,
            }),
          )

    await fetchMutation(
      api.features.connections.mutations.upsert,
      {
        connectorId: manifest.id,
        // From the manifest, never from the cookie or the URL: the address the
        // gateway will call is a property of the connector.
        baseUrl: manifest.endpoint,
        tokenCipher: await sealCredential(issued.accessToken),
        authType: manifest.auth.type,
        ...(expiresAt === null ? {} : { tokenExpiresAt: expiresAt }),
        ...(renewalCipher === undefined ? {} : { renewalCipher }),
      },
      { token },
    )
  } catch (error) {
    const name = error instanceof Error ? error.name : ""
    return failed(request, name === "OAuthExchangeError" ? "exchange_failed" : "save_failed")
  }

  return back(request, { connected: manifest.id })
}
