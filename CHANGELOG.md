# Changelog

All notable public changes to Gradia Guard are recorded here.

## Unreleased

## 0.1.0-beta.5 — 2026-09-03

- Added the strict `proof-bound-ag-ui.v1` TypeScript verifier, fragmented SSE
  parser, canonical proposal builder, action-receipt verifier, shared
  Python/TypeScript golden vector, and a server-side CopilotKit example.
- Kept CopilotKit/AG-UI at the interaction edge: only exact human-authorized
  `steer` and `cancel` proposals have canonical executors; tool dispatch,
  generic approval and authoritative state write remain refused.
- Added an authenticated, deny-by-default MCP stdio child proxy for the exact
  stateless newline-delimited JSON-RPC `tools/call` subset. Authorization is
  durably appended before child stdin can be written; terminal receipts bind
  the SDK occurrence and synchronous write-call fact without retaining payloads.
- Added account-free `mcp-stdio verify` and `mcp-stdio recover` commands,
  partial-write hardening, interruption-only recovery, and mutation, reorder,
  count-drift, truncation, identity/configuration, and bypass-boundary tests.

No executable-byte or child-identity attestation, handshake/discovery/streaming
compatibility, host/container non-bypassability, npm-registry publication,
external MCP interoperability, or customer deployment is claimed by this entry.

## 0.1.0-beta.4 — 2026-09-02

- Added fail-closed recovery for an interrupted MCP HTTP access v2 journal. The
  recorder independently replays the canonical durable prefix, forbids resumed
  writes, and atomically finalizes it as `recovered_interruption` without
  claiming an operating-system crash or reconstructing unappended requests.
- Added account-free `mcp-http verify` and `mcp-http recover` CLI commands,
  exclusive no-overwrite finalization, recovery/timestamp mutation checks, and
  backward verification for finalized beta.3 v1 bundles. Open v1 prefixes are
  deliberately not recoverable because their signed header says recovery was
  unsupported.

No full-host, cluster, stdio, socket-parser, pre-append, npm-registry, external-
adoption or interruption-cause claim is made by this entry.

## 0.1.0-beta.3 — 2026-09-02

- Added a durable, payload-digest-only HTTP access chain for the exact-route
  MCP proxy. Every request that reaches the Node request listener now records
  its authorization/origin presence, request shape, typed disposition, reason,
  route digest, upstream status and optional SDK occurrence before a response.
- Added account-free verification of the finalized access bundle and its
  canonical fsync journal, including mutation, reordering, count-drift and
  truncation refusals. Sessions with only pre-tool refusals finalize without
  fabricating an empty G2 SDK bundle.

No npm-registry publication or external adoption is claimed by this entry.

## 0.1.0-beta.2 — 2026-08-31

- Added the governed evaluation router with exact policy/identity binding and
  fail-closed provider dispatch.
- Made canonical ordering locale-independent across JavaScript and Python
  producers and verifiers.
- Added an account-free `proof-pack verify` command, public TypeScript API,
  cross-runtime conformance fixture, and fail-closed aggregate/semantic
  forgery checks for the versioned Wind Tunnel Proof Pack profile.
- Added a reusable GitHub Action and reference workflow whose green result
  retains the verifier's narrow integrity-and-derivation claim boundary.

No npm-registry publication or external adoption is claimed by this entry.

## 0.1.0-beta.1 — 2026-08-28

- Opened the local SDK, CLI, verifier, provider/framework/MCP adapters, portable
  runtime receipts, Docker/Kubernetes reference receipts, and offline anchor
  verification under Apache-2.0.
- Added `doctor` with telemetry-off, digest-only, disconnected-managed defaults
  and an explicit G0 assurance ceiling.
- Added a self-digested free-versus-managed capability catalog in schema v2.
- Added clean-git, pack-allowlist, dependency-audit, fresh-install, CLI, and ESM
  import release gates.
- Kept managed ingestion, remote anchor issuance, retention declarations,
  review, Analytics+, regression, certification, and Universe composition
  authenticated and deployment-specific.

No npm-registry publication or external adoption is claimed by this entry.
