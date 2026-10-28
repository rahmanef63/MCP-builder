# AGENTS.md

## Goal

Build a secure connector runtime that exposes a single remote gateway to AI clients while supporting both:

- remote/cloud applications;
- local desktop applications.

## Portfolio ownership

Manef portfolio product. Owner agent: **manef** (Grok Bot portfolio lead, Products). Connector-runtime work may also surface under the connectors / connectors-gateway agent lanes; do not invent other owners.

Repo: `rahmanef63/MCP-builder`.

## Read first

1. `docs/00-product-definition.md`
2. `docs/01-architecture.md`
3. `docs/03-security-model.md`
4. `docs/06-connector-contract.md`
5. `docs/13-mvp-roadmap.md`

If you are working in a clone of this template — adding a connector, deploying
it, or wondering why there are two hosts — read `docs/21-add-a-connector.md` and
`docs/20-vercel-template.md` first. `CHECKLIST.md` is what must be true before
a real AI client points at a real account; this file is how to build.

If comparing this gateway to MSO MCP / SI-Coder strengths and remaining gaps,
read `docs/22-mso-gap-analysis.md` (dated 2026-10-23; includes the 3-way
redaction table).

If working on Blender, also read `docs/11-blender-reference.md`.

If working on the local agent, also read:

- `docs/04-device-pairing.md`
- `docs/05-local-agent-protocol.md`
- `docs/14-threat-model.md`

## Current state (2026-10)

- **MANEF AI module foundation (PR #5, merge `b6da49c`)** landed under `.manef/`:
  versioned descriptor (`module.json`), preview-only `config.json`,
  `foundation.lock.json`, and the offline checker at
  `.manef/_generated/check-module.mjs`. Run
  `node .manef/_generated/check-module.mjs` from the repo root. It validates
  descriptor + layout paths only; it does not run declared commands or prove
  live readiness. Native Bun workspaces, locks, auth, credentials, connectors
  and deploy entry points stay owned by this repo — do not replace them with
  generated foundation files.
- **Gateway hardening (PR #6)** is on main: OAuth redirect URIs reject
  `userinfo`; tool-result text is capped at 64 Ki chars with `_meta["cg/truncated"]`
  and every `tools/call` carries `_meta["cg/receipt"]` (`requestId`, `timingMs`);
  observability redacts provider token shapes and query-string secrets (see
  `packages/observability/src/redact.ts` and `docs/22-mso-gap-analysis.md`).
- MVP boundary below is unchanged: careerpack + blender + one public entry +
  pairing + policy + audit. No marketplace/billing/workflow engine yet.

## Non-negotiable invariants

1. Local applications are never exposed through a raw public IP or inbound port.
2. The local agent initiates the network connection outbound.
3. Blender remains bound to loopback (`127.0.0.1` / `localhost`) unless an explicit future design changes this.
4. AI clients do not receive device credentials.
5. Connector credentials do not appear in tool output.
6. Authorization is checked per action, not only when a connection is established.
7. Dangerous capabilities such as arbitrary Python, shell execution, and unrestricted filesystem access are disabled by default.
8. Every action has explicit risk metadata.
9. Cloud and local connectors implement the same logical connector contract.
10. Protocol-specific details belong at adapters/edges; business-level action schemas stay normalized.
11. `rahmanef63/connectors` remains the cookbook/SSOT. Do not duplicate long-form recipes here when a link/reference is enough. When a runtime fix here uncovers a reusable lesson: fix it here, write the recipe there, link back to this implementation — never explain it twice.
12. Secrets, refresh tokens, device credentials, and raw OAuth tokens must never be committed to the repository.
13. The gateway edge is ONE implementation. `apps/web` mounts `apps/gateway/src/edge.ts`; it never reimplements a route, an authentication path, or a policy check. A host may contribute only what it alone knows — the caller's peer address, and whether it may own a WebSocket. A second implementation of authorization is a second thing to get wrong.
14. Bun globals live in `apps/gateway/src/main.ts` and the `scripts/` entry points, nowhere else. Everything under the edge runs on Bun and Node 22 alike, because it has to.
15. Shipping a connector and serving it are separate. `CONNECTORS_ENABLED` selects; the registry is built from the selection, and so is the adapter map — an adapter for a connector the registry will not resolve is an open upstream client nobody audited.

## MVP boundary

Implement only enough to prove:

- one cloud connector (`careerpack`);
- one local connector (`blender`);
- one public AI entry point;
- one device pairing flow;
- one policy/approval layer;
- one audit trail.

Do not build a marketplace, billing system, workflow engine, or hundreds of connectors before this works end-to-end.
