# 20 — Gap analysis: connectors-gateway vs MSO MCP vs SI-Coder

Date: 2026-10-23. Compared: this repo (`feat/adopt-mso-strengths`) against the
MSO MCP server (`mso.rahmanef.com/mcp`, 121 tools; source `/home/box/mso@6b035cfd`).
SI-Coder source: `/home/box/projects/si-coder-agent@492909a`.
Scores are 0–100 judgements, each tied to evidence below.

| Aspect | Gateway before | Gateway after | MSO | Evidence |
|---|---|---|---|---|
| Tool catalog / descriptors | 85 | 88 | 90 | GW: `apps/gateway/src/mcp/tools.ts` emits title, outputSchema, OAuth `securitySchemes`, readOnly/destructive/idempotent/openWorld hints, invoking status. MSO: 121 tools with routing hints in descriptions (“do not use as first call”), `read_pipeline` batching. |
| Auth / token | 92 | 92 | 80 | GW: OAuth 2.1 + PKCE, `packages/core/src/redirect-uri.ts` (userinfo rejected, 34d96ec), `oauth-renewal.ts`, `mcp-resource.ts`. MSO: owner bearer / client-bound sessions. |
| Registry | 90 | 90 | 75 | GW: `packages/registry`, `CONNECTORS_ENABLED` selection (invariant 15), tool-name collision guard. MSO: static capability list in `lib/capabilities`. |
| Security guards | 85 | 92 | 88 | GW: R0–R4 risk + policy/approval (`packages/core/src/risk.ts`, `packages/policy`), redaction, adapter body caps; **now** bounded model text + audit receipt (1bc7629). MSO: `fs_write.expected_sha256`, bounded exec jobs (20 min / 1 MiB), but owner shell `exec_run` is on. |
| Tests | 90 | 91 | 85 | GW: 193 test files, 1374 bun + 854 vitest pass. MSO: ~876 test files, broader surface, less per-guard depth on auth. |
| Docs | 88 | 92 | 85 | GW: numbered `docs/00–21`, AGENTS.md invariants, this file. MSO: README/AGENTS/SECURITY + docs/. |

## Adopted from MSO

1. **Bounded outputs** — `MAX_TOOL_TEXT_CHARS` (64 Ki chars) caps the text block in
   `toToolResult`; `_meta["cg/truncated"]` flags it; `structuredContent` stays whole.
2. **Audit receipt** — every `tools/call` result carries
   `_meta["cg/receipt"] = { requestId, timingMs }`, matching its audit row.

## Remaining gaps (not adopted, and why)

- **Per-tool scope tiers read/write/exec** — GW already has R0–R4 + `requiredScopes`; an
  `exec` tier would contradict invariant 7 (shell/arbitrary code disabled by default).
- **Idempotency keys** — needs a connector-contract change (`docs/06`) and a dedupe store;
  product decision on TTL and which actions qualify.
- **expected-sha write guard** — GW exposes no generic file-write action; belongs in a
  specific connector (e.g. Blender file save) once one exists.
- **read_pipeline** (server-side batch of read-only calls) — useful, but a new public
  tool surface plus policy semantics for batched R0/R1 calls; needs product sign-off.
- ChatGPT `plugin/.app.json` technical ID — requires the owner's ChatGPT account.

## Gateway strengths MSO could adopt

1. Per-action risk class R0–R4 with default DENY for R4 (would gate `exec_run`).
2. Strict OAuth redirect-URI validation incl. userinfo rejection.
3. Registry built from an explicit enable-list; unselected adapters never instantiated.
4. Tool-name collision guard that refuses to list a colliding catalog.
5. Catalog-miss auditing: unknown tool names are written to the audit trail.

## 3-way: secret redaction / credentials

| | Gateway before | Gateway after | MSO | SI-Coder | Evidence |
|---|---|---|---|---|---|
| Secret redaction / credentials | 84 | 92 | 80 | 86 | GW: `packages/observability/src/redact.ts` (single chokepoint, key-name + bearer + `cg?_` grammar for logs; narrow `stripCredentialsDeep` on tool output in `pipeline/execute.ts`), hashed API keys + sealed credentials in `packages/auth`. **Now** + provider token shapes (c7f239a), query-string secrets in logs, `pipeline/leak.test.ts` end-to-end. MSO: `lib/orchestration/redaction.ts` (query/key-value/prefix/PEM, length cap), `receipt-redaction.ts`; key-value rule would mangle data a caller asked for. SI-Coder: `lib/redact-env.js` literal env-value scrub (secret-named vars) + vendor shapes, `test/mcp-redact-e2e.test.js` spawn-level leak test; plaintext env-based credential storage. |

Adopted: SI-Coder vendor token shapes (applied to tool output and logs; no generic long-run rule so SHAs survive), SI-Coder-style end-to-end leak tests, MSO query-string secret redaction (logs only).

Not adopted:
- **Literal env-value scrubbing** — the gateway's secrets are known to `loadConfig`; wiring them into the redactor needs a config→observability seam and a decision on which values qualify (and must stay Bun-global-free, invariant 14).
- **MSO key-value rule (`password=…`) on tool output** — conflicts with the deliberate narrow tool-output design (a user reading their own config must get it back).
- **JWT shape** — legitimate id_tokens/claims appear in connector data; product decision.
