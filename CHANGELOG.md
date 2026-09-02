# Changelog

All notable public changes to Gradia Guard are recorded here.

## Unreleased

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
