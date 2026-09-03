# Compatibility policy

`@gradia/guard` is a public beta. The package requires Node.js 20.12 or newer,
uses native ECMAScript modules, and pins `@ag-ui/core==0.0.59` as its sole
runtime npm dependency for the optional strict AG-UI event boundary.

## AG-UI compatibility cell

The only claimed cell is Gradia `proof-bound-ag-ui.v1`, Python
`ag-ui-protocol==0.1.22`, TypeScript `@ag-ui/core==0.0.59`, and upstream commit
`3f38925d0e6c19bf1f19502ee12e410e772ac142`. Python and TypeScript must accept
the same golden proposal, event, SSE and human-action receipt bytes. Unknown
events or fields, raw reasoning, forged authority/root/credential fields,
action-digest mutation and receipt overclaim fail closed. This does not claim
compatibility with arbitrary CopilotKit or AG-UI versions.

## MCP stdio compatibility cell

The only claimed stdio cell is the Guard-owned stateless, serialized,
newline-delimited JSON-RPC `tools/call` subset identified by
`MCP_STDIO_PROXY_PROTOCOL_SUBSET`. It does not implement `initialize`,
`initialized`, discovery, notifications, streaming, multi-round exchanges, or
arbitrary MCP server/client compatibility. The launch declaration binds an
absolute executable path, exact arguments, empty environment, and `shell: false`;
it does not attest the executable bytes or the spawned child's identity.
Only requests traversing this exact Guard-spawned child boundary are covered.

## Stable within `0.1.x`

- canonical evidence bundles remain fail-closed and self-digested;
- a verifier never silently accepts an unknown schema;
- telemetry remains off by default;
- content capture remains digest-only unless explicitly changed by the caller;
- payment never changes evidence coverage, claim truth, or admission outcomes;
- public exports are available from the package root; and
- CLI removals or incompatible argument changes require a release note and a
  new beta minor version.

## Versioned evidence schemas

Evidence schemas are independent of the npm version. A newer verifier may add
support for a new schema, but it must continue to refuse unknown or malformed
schemas. A schema is not reinterpreted after release to support a stronger
claim. Exact provider and framework compatibility is listed by:

```bash
npx @gradia/guard sdk-matrix --json
npx @gradia/guard framework-matrix --json
```

Those catalogs describe the pinned cells exercised by this release, not every
version or live-provider deployment.

The `gradia-wind-tunnel-evidence-manifest.v1` Proof Pack profile is a research
artifact profile, not a Guard execution-bundle tier. Guard verifies its
`gradia-wind-tunnel-frames.v1` chain and declared aggregates independently and
refuses unknown profiles. Adding another research profile requires a new
versioned schema and conformance fixture; it cannot silently reinterpret v1.

## Python ABI parity

The source-complete `packages/guard-python` beta emits the same
`gradia.guard.sdk-bundle.v1` bytes and ships an independent dependency-free
verifier. Cross-language tests require the Node verifier to accept a Python
bundle and the Python verifier to accept a Node bundle. This is evidence-format
parity, not framework, transport, enforcement, registry, or support parity.
The Python package is not yet published to PyPI.

## Beta change rule

Before `1.0.0`, TypeScript types and beta APIs may change. Any breaking change
must be named in `CHANGELOG.md`, increment the beta minor version, and ship with
a migration example. Security and verifier correctness take priority over
preserving behavior that would accept invalid or overstated evidence.
