# Compatibility policy

`gradia-guard` is a source-complete, unpublished beta candidate for Python 3.12
and newer. It has no runtime dependencies and emits
`gradia.guard.sdk-bundle.v1`, the same ABI as `@gradia/guard`.

## Stable within `0.1.x`

- unknown evidence schemas fail closed;
- capture stays digest-only;
- direct and uninstrumented I/O remains explicitly unobserved;
- Node and Python verifiers accept the same valid bytes and reject digest,
  chain, policy-timing, retry, parentage, identity, and censor mutations;
- payment cannot change coverage or claim truth; and
- breaking API changes require a beta-minor bump and a migration note.

## Exact framework cell

The tested automatic hook is `LangChainGuardCallback` against
`langchain-core==1.6.1`. It covers framework-visible model and registered-tool
callbacks with exact caller-provided identities. Other versions and arbitrary
frameworks are not implied. A callback is not a network interceptor and cannot
prove calls outside the callback did not occur.

The recorder and callback serialize concurrent in-process operations before
advancing the evidence chain. This does not make a bundle safe for writes from
multiple processes; each process must use a separate recorder/session.
