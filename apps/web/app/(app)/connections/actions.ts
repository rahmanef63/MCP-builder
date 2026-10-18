"use server"

/**
 * The three ways a connection gets created, all of them server-side. Which one
 * runs is decided by what the connector's own authorization server advertises,
 * never by a setting:
 *
 * 1. CLIENT CREDENTIALS — the server offers the grant and the user brought an id
 *    and a secret. One POST, no browser round trip, done before the page
 *    repaints. This is the shortest honest path and it is tried first.
 * 2. AUTHORIZATION CODE — everything else. Discover, obtain a client id
 *    (registering one via RFC 7591 if the server allows it, so the user types
 *    nothing at all), then send the browser to consent. Nothing is stored until
 *    the code comes back to /oauth/callback.
 * 3. TOKEN PASTE — for a service that just hands out a long-lived token.
 *
 * All three replaced a form asking for a base URL, an auth type, and ciphertext
 * the user had to produce by SSHing to the gateway host and running a CLI.
 *
 * P0: every action re-verifies the caller against Convex with their own session
 * token. `connectorId` is only ever used to look up a shipped manifest, so a
 * hand-crafted id resolves to nothing rather than to a host of the caller's
 * choosing.
 */
import { redirect } from "next/navigation"

import { oauthRedirectUri } from "@/lib/app-origin"
import { sealingAvailable } from "@/lib/credentials"
import {
  authorizeUrl,
  clientCredentialsGrant,
  createPkce,
  createState,
  registerClient,
  tokenExpiresAt,
} from "@/lib/oauth/client"
import { discoverAuthServer } from "@/lib/oauth/discovery"
import { writeFlowState } from "@/lib/oauth/state"
import {
  classify,
  collectCredential,
  connectable,
  fail,
  field,
  requireViewer,
  requireViewerToken,
  storeConnection,
  type ConnectFormState,
} from "./connect-support"

export async function startOAuthConnect(
  _previous: ConnectFormState,
  formData: FormData,
): Promise<ConnectFormState> {
  const viewer = await requireViewer()
  if (viewer === null) return fail("not_signed_in")
  const { token, userId } = viewer
  if (!sealingAvailable()) return fail("sealing_unavailable")

  const target = connectable(field(formData, "connectorId"))
  if (target === null) return fail("unknown_connector")
  // OAuth begins with PRM discovery against the server's own address, so a
  // connector the manifest cannot locate has nothing to discover. Those
  // connect by pasting a key instead — the panel hides this button for them,
  // and this is the matching server-side refusal.
  if (target.endpoint === null) return fail("endpoint_required")

  const clientIdInput = field(formData, "clientId")
  const clientSecretInput = field(formData, "clientSecret")

  let destination: string
  try {
    const server = await discoverAuthServer(target.endpoint)

    // THE SHORT PATH. A server that advertises `client_credentials` can issue a
    // token from an id and a secret alone — no browser round trip, no consent
    // screen, nothing stored between two requests. If the user brought both
    // values and the server offers the grant, connecting is over here.
    if (
      clientIdInput.length > 0 &&
      clientSecretInput.length > 0 &&
      server.grantTypes.includes("client_credentials")
    ) {
      const issued = await clientCredentialsGrant({
        tokenEndpoint: server.tokenEndpoint,
        clientId: clientIdInput,
        clientSecret: clientSecretInput,
        scope: server.scope,
        resource: server.resource,
      })
      const expiresAt = tokenExpiresAt(issued)
      await storeConnection(target, issued.accessToken, token, {
        ...(expiresAt === null ? {} : { tokenExpiresAt: expiresAt }),
        ...(expiresAt === null
          ? {}
          : {
              renewal: {
                v: 1,
                grantType: "client_credentials",
                tokenEndpoint: server.tokenEndpoint,
                clientId: clientIdInput,
                clientSecret: clientSecretInput,
                scope: server.scope,
                resource: server.resource,
              } as const,
            }),
      })
      return { error: null, connected: target.id }
    }

    let clientId = clientIdInput
    let clientSecret: string | null = clientSecretInput.length > 0 ? clientSecretInput : null
    if (clientId.length === 0) {
      // Nothing typed: only a server that registers clients on demand can be
      // connected with zero fields. Otherwise the user has to create an app in
      // that vendor's console and bring its id and secret back here.
      if (server.registrationEndpoint === null) return fail("client_id_required")
      const registered = await registerClient(
        server.registrationEndpoint,
        oauthRedirectUri(),
        "Connectors Gateway",
      )
      clientId = registered.clientId
      clientSecret = registered.clientSecret ?? clientSecret
    }

    const { verifier, challenge } = await createPkce()
    const state = createState()
    await writeFlowState({
      userId,
      connectorId: target.id,
      state,
      verifier,
      clientId,
      clientSecret,
      tokenEndpoint: server.tokenEndpoint,
      redirectUri: oauthRedirectUri(),
      resource: server.resource,
      scope: server.scope,
    })

    destination = authorizeUrl({
      authorizationEndpoint: server.authorizationEndpoint,
      clientId,
      redirectUri: oauthRedirectUri(),
      challenge,
      state,
      scope: server.scope,
      resource: server.resource,
    })
  } catch (error) {
    return fail(classify(error))
  }

  // Outside the try: redirect() signals by throwing, and catching it here would
  // turn a successful start into an error message.
  redirect(destination)
}

export async function saveTokenConnection(
  _previous: ConnectFormState,
  formData: FormData,
): Promise<ConnectFormState> {
  const token = await requireViewerToken()
  if (token === null) return fail("not_signed_in")
  if (!sealingAvailable()) return fail("sealing_unavailable")

  const target = connectable(field(formData, "connectorId"))
  if (target === null) return fail("unknown_connector")

  // Whatever this connector's manifest declared, read back by name. A field
  // marked `role: "endpoint"` is the address, not part of the credential, so
  // it is pulled out rather than sealed alongside the secrets.
  const collected = collectCredential(target.id, formData)
  if (collected.missing !== null) {
    return fail(collected.missing === "__endpoint__" ? "endpoint_required" : "secret_required")
  }

  // The address is NOT validated here: `assertUpstreamUrl` runs inside the
  // Convex mutation, so the SSRF gate cannot be skipped by a caller that
  // reaches the mutation another way. Checking it twice is how two copies of
  // one rule end up disagreeing.
  const endpoint = collected.endpoint ?? target.endpoint
  if (endpoint === null || endpoint.length === 0) return fail("endpoint_required")

  try {
    await storeConnection(target, collected.secret, token, { endpoint })
  } catch {
    return fail("save_failed")
  }
  return { error: null, connected: target.id }
}
