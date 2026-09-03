import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  canonicalJson,
  digestCanonical,
  issueWorkloadIdentity,
  sealMcpStdioProxyConfiguration,
  sealPolicy,
  startAuthenticatedMcpStdioProxy,
  verifyMcpStdioAccessBundleDirectory,
  verifySdkBundle,
  type GuardWorkloadIdentityClaims,
  type SdkToolIdentity,
} from "../src/index.js";

const OFFICIAL_SERVER_PACKAGE_VERSION = "2026.8.31";
const now = 1_788_400_000;
const keys = generateKeyPairSync("ed25519");
const toolIdentity: SdkToolIdentity = {
  schema_version: "gradia.guard.sdk-tool-identity.v1",
  registry_id: "official-everything",
  tool_id: "echo",
  tool_version: OFFICIAL_SERVER_PACKAGE_VERSION,
  interface_sha256: digestCanonical({
    package: "@modelcontextprotocol/server-everything",
    version: OFFICIAL_SERVER_PACKAGE_VERSION,
    tool: "echo",
    arguments: { message: "string" },
  }),
};

test("Guard dispatches to the pinned official MCP Everything server with verified payload-free receipts", async () => {
  const officialServer = join(
    process.cwd(),
    "node_modules",
    "@modelcontextprotocol",
    "server-everything",
    "dist",
    "index.js",
  );
  assert.equal(existsSync(officialServer), true, "pinned official MCP server is not installed");

  const policy = sealPolicy({
    schema_version: "gradia.guard.policy.v1",
    policy_id: "official-mcp-compatibility",
    policy_version: OFFICIAL_SERVER_PACKAGE_VERSION,
    default_decision: "blocked",
    model_routes: [],
    tool_routes: [{
      registry_id: toolIdentity.registry_id,
      tool_id: toolIdentity.tool_id,
      tool_version: toolIdentity.tool_version,
      interface_sha256: toolIdentity.interface_sha256,
      authority_scope_ids: ["mcp.echo"],
      max_request_bytes: 4_096,
      max_attempt_number: 1,
    }],
  });
  const configuration = sealMcpStdioProxyConfiguration({
    schema_version: "gradia.guard.mcp-stdio-proxy-configuration.v1",
    configuration_id: "official-mcp-everything",
    configuration_version: OFFICIAL_SERVER_PACKAGE_VERSION,
    default_decision: "blocked",
    server_id: toolIdentity.registry_id,
    tool_routes: [{
      tool_name: toolIdentity.tool_id,
      tool_identity: toolIdentity,
      authority_scope_ids: ["mcp.echo"],
    }],
  });
  const claims = {
    issuer_id: "gradia-compatibility-proof",
    organization_id: "gradia-public",
    project_id: "guard-mcp",
    workload_id: "official-server-proof",
    deployment_id: "local-clean-node",
    audience: "guard-mcp-stdio",
    policy_sha256: policy.policy_sha256,
    image_sha256: digestCanonical({ runtime: process.version }),
    configuration_sha256: configuration.configuration_sha256,
    collector_sha256: digestCanonical({ collector: "mcp-stdio-beta-5" }),
    authority_scope_ids: ["mcp.echo"],
    issued_at_unix: now,
    not_before_unix: now,
    expires_at_unix: now + 300,
    nonce_sha256: digestCanonical({ nonce: "official-everything-compatibility" }),
  } satisfies GuardWorkloadIdentityClaims;
  const directory = join(mkdtempSync(join(tmpdir(), "gradia-official-mcp-")), "session");
  const proxy = await startAuthenticatedMcpStdioProxy({
    directory,
    policy,
    configuration,
    workloadIdentity: issueWorkloadIdentity(claims, "compatibility-key-v1", keys.privateKey),
    trustedPublicKeys: { "compatibility-key-v1": keys.publicKey },
    workloadExpectation: {
      issuerId: claims.issuer_id,
      organizationId: claims.organization_id,
      projectId: claims.project_id,
      workloadId: claims.workload_id,
      deploymentId: claims.deployment_id,
      audience: claims.audience,
      policySha256: claims.policy_sha256,
      imageSha256: claims.image_sha256,
      configurationSha256: claims.configuration_sha256,
      collectorSha256: claims.collector_sha256,
    },
    maxIdentityLifetimeSeconds: 600,
    nowUnix: () => now + 1,
    command: process.execPath,
    args: [officialServer, "stdio"],
    responseTimeoutMs: 5_000,
  });

  const marker = "guard-official-mcp-live-proof";
  const result = await proxy.invoke({
    serverId: toolIdentity.registry_id,
    toolIdentity,
    toolRequestBody: Buffer.from(canonicalJson({ message: marker }), "utf8"),
    toolRequestMediaType: "application/json",
    authorityScopeIds: ["mcp.echo"],
    logicalOperationId: "official-echo-1",
    attemptNumber: 1,
    retryOfOccurrenceSha256: null,
    parentOccurrenceSha256: null,
    stateRootBefore: null,
  });
  assert.equal(result.disposition, "completed");
  const body = JSON.parse(
    Buffer.from(result.response?.toolResultBody ?? []).toString("utf8"),
  ) as { content?: Array<{ type?: unknown; text?: unknown }> };
  assert.deepEqual(body.content, [{ type: "text", text: `Echo: ${marker}` }]);

  const closed = await proxy.close();
  assert.equal(closed.transaction_count, 1);
  assert.equal(closed.completed_transactions, 1);
  assert.equal(closed.failed_transactions, 0);
  const access = verifyMcpStdioAccessBundleDirectory(
    join(directory, "mcp-stdio-access"),
  );
  assert.equal(access.ok, true, access.blockers.join(","));
  assert.equal(verifySdkBundle(join(directory, "mcp-evidence")).ok, true);
  const accessJournal = readFileSync(
    join(directory, "mcp-stdio-access", "receipts.ndjson"),
    "utf8",
  );
  assert.equal(accessJournal.includes(marker), false);
});
