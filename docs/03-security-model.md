# Security model

## Security goal

The gateway should make local software remotely usable **without turning the user's machine into a public server**.

## Default trust boundaries

```text
Internet
│
├── AI Client                untrusted input
├── Public Gateway           hardened edge
│
└── encrypted device session
     │
     └── Local Agent         trusted only for paired account
          │
          └── localhost app bridge
```

## Required controls

### Gateway

- TLS only.
- Authenticate every client.
- Bind requests to user/workspace identity.
- Authorize each action.
- Validate input against connector schema.
- Apply rate limits.
- Log action, actor, connector, device, result status, latency.
- Never return raw credentials.
- Encrypt access and renewal credentials at rest; the control plane stores ciphertext only.
- Coordinate refresh with a short lease and credential generation so concurrent gateways cannot
  reuse or overwrite a rotated refresh token.

### Local Agent

- Outbound connection only.
- Per-device credential.
- Store secrets in OS secure storage where possible.
- Verify every job envelope.
- Reject expired/replayed jobs.
- Enforce local allowlist independently of cloud policy.
- Bind application bridges to loopback.
- Provide kill switch / disconnect.
- Support credential rotation and remote revocation.

### Blender

Default-deny:

- arbitrary Python;
- shell execution;
- unrestricted filesystem;
- arbitrary network access.

Safe actions should be explicit, narrow tool calls.

## Risk classes

| Risk | Example | Default behavior |
|---|---|---|
| R0 | read scene metadata | auto-allow |
| R1 | create non-destructive object | allow if connector enabled |
| R2 | modify scene/material | configurable confirmation |
| R3 | overwrite/delete/export | confirmation |
| R4 | arbitrary code/shell | disabled by default |

## Defense in depth

A compromised gateway policy should not automatically imply unlimited local execution. The local agent maintains its own capability allowlist.

### Agent credential storage by platform

The agent separates secret device credentials from non-secret device metadata when a safe native store is available:

- Linux desktop sessions use Secret Service through `secret-tool`; the credential is supplied on stdin and the config file stores only an opaque `os:connectors-agent:v1` reference.
- Headless Linux keeps the existing owner-only `0700` directory / `0600` file fallback because a Secret Service session is normally absent.
- macOS and Windows currently keep that owner-only fallback. The common `security`/PowerShell CLI approaches would expose a credential in process arguments or require an interactive prompt, so the agent does not claim native protection until a direct Keychain/DPAPI binding is available.
- Migration is write-native-first: plaintext is removed from the file only after native persistence succeeds. A config containing an OS-store reference fails closed if that store later becomes unavailable.

## Public upstream connections

The dashboard and gateway use `@cg/transport` for remote MCP calls, OAuth
discovery, client registration, initial token exchange and renewal. Before a
socket opens, the transport validates the URL and every DNS answer, rejects
private/reserved or malformed addresses, then pins a fresh connection to an
approved numeric address. The original hostname remains the HTTP Host and TLS
server name, with certificate verification enabled. Redirects never select a
new destination, and cancellation closes the upstream socket.

Initial OAuth exchange and renewal use the same pure URL policy in `@cg/core`,
including public IP literals and HTTPS port 8443. Endpoint paths and queries
are retained; stored base identities keep their existing normalization. The
loopback development exception cannot be enabled in production, and it never
permits a public hostname to resolve to a loopback address.

OAuth flow cookies contain the initiating user's authenticated Convex ID.
Callbacks verify the current user's identity before exchanging a code or
storing a credential. An account switch or an older cookie without an owner
requires starting the connection again. Deploy the new
`features/auth/identity:currentUserId` query with the backend before serving
the corresponding dashboard code; a missing query fails closed.

The public-upstream transport deliberately excludes the trusted private device
relay and the local Blender bridge, whose destinations have separate contracts.
These controls do not authorize an upstream action or replace the existing
per-action policy and approval checks. A real account connection still requires
its reviewed service endpoint to be available.
