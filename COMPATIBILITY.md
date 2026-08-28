# Compatibility policy

`@gradia/guard` is a public beta. The package requires Node.js 20.12 or newer,
uses native ECMAScript modules, and has zero runtime npm dependencies.

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

## Beta change rule

Before `1.0.0`, TypeScript types and beta APIs may change. Any breaking change
must be named in `CHANGELOG.md`, increment the beta minor version, and ship with
a migration example. Security and verifier correctness take priority over
preserving behavior that would accept invalid or overstated evidence.
