# Checked Docker MCP stdio proof

This fixture is one narrow, replayable runtime cell. It runs the pinned
`@modelcontextprotocol/server-everything@2026.8.31` package as a Guard-routed
stdio child inside a fresh `node:22-alpine` container with no network, a
read-only root filesystem, a non-root user, all Linux capabilities dropped,
and `no-new-privileges`.

From `packages/guard`:

```sh
npm run build
node scripts/docker-mcp-stdio-proof.mjs --out /tmp/guard-mcp-stdio-proof
```

The script verifies one exact `echo` success and a forced 100 ms transport
timeout on `trigger-long-running-operation`. The timeout is recorded as a tool
failure and never attributed to the model. It verifies both digest-only receipt
chains, scans the saved artifacts for common credential forms, and emits a
self-digested proof receipt.

The checked `live-docker-proof/` fixture was produced by that script. Its
ceiling is intentional: it does not prove that an alternate process, another
stdio path, a Docker operator, or the host cannot bypass this routed cell. It
also does not prove arbitrary MCP-server compatibility or complete file,
process, network, credential, and side-effect capture.
