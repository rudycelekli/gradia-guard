import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  AuthenticatedMcpToolAdapter,
  canonicalJson,
  digestCanonical,
  enforcementBoundary,
  issueWorkloadIdentity,
  sealPolicy,
  verifyEnforcementBoundary,
  verifySdkBundle,
  type GuardMcpToolInvoker,
  type GuardPolicy,
  type GuardWorkloadIdentity,
  type GuardWorkloadIdentityClaims,
  type SdkStateRootIdentity,
  type SdkToolIdentity,
} from "../src/index.js";

const keys = generateKeyPairSync("ed25519");
const now = 1_787_549_400;
const interfaceSha256 = digestCanonical({ interface: "case.read.v1" });
const toolIdentity: SdkToolIdentity = {
  schema_version: "gradia.guard.sdk-tool-identity.v1",
  registry_id: "case-tools",
  tool_id: "case.read",
  tool_version: "v1",
  interface_sha256: interfaceSha256,
};
const rootBefore: SdkStateRootIdentity = {
  schema_version: "gradia.guard.sdk-state-root.v1",
  source: "application_declared",
  namespace_id: "case-world",
  root_sha256: digestCanonical({ state: "before" }),
};
const rootAfter: SdkStateRootIdentity = {
  schema_version: "gradia.guard.sdk-state-root.v1",
  source: "application_declared",
  namespace_id: "case-world",
  root_sha256: digestCanonical({ state: "after" }),
};

function policy(): GuardPolicy {
  return sealPolicy({
    schema_version: "gradia.guard.policy.v1",
    policy_id: "mcp-policy",
    policy_version: "v1",
    default_decision: "blocked",
    model_routes: [],
    tool_routes: [
      {
        registry_id: toolIdentity.registry_id,
        tool_id: toolIdentity.tool_id,
        tool_version: toolIdentity.tool_version,
        interface_sha256: toolIdentity.interface_sha256,
        authority_scope_ids: ["case.read"],
        max_request_bytes: 10_000,
        max_attempt_number: 2,
      },
    ],
  });
}

function claims(source: GuardPolicy): GuardWorkloadIdentityClaims {
  return {
    issuer_id: "gradia-managed",
    organization_id: "org-1",
    project_id: "project-1",
    workload_id: "agent-1",
    deployment_id: "deployment-1",
    audience: "guard-mcp",
    policy_sha256: source.policy_sha256,
    image_sha256: digestCanonical({ image: "v1" }),
    configuration_sha256: digestCanonical({ mcp: "v1" }),
    collector_sha256: digestCanonical({ collector: "v1" }),
    authority_scope_ids: ["case.read"],
    issued_at_unix: now,
    not_before_unix: now,
    expires_at_unix: now + 300,
    nonce_sha256: digestCanonical({ nonce: "mcp-adapter" }),
  };
}

function directory(label = "gradia-mcp-"): string {
  return join(mkdtempSync(join(tmpdir(), label)), "bundle");
}

function makeAdapter(
  bundle: string,
  invokeTool: GuardMcpToolInvoker,
  overrides: { policy?: GuardPolicy; identity?: GuardWorkloadIdentity } = {},
): AuthenticatedMcpToolAdapter {
  const sourcePolicy = overrides.policy ?? policy();
  const sourceClaims = claims(sourcePolicy);
  const identity =
    overrides.identity ?? issueWorkloadIdentity(sourceClaims, "issuer-key-v1", keys.privateKey);
  return new AuthenticatedMcpToolAdapter({
    directory: bundle,
    policy: sourcePolicy,
    workloadIdentity: identity,
    trustedPublicKeys: { "issuer-key-v1": keys.publicKey },
    workloadExpectation: {
      issuerId: sourceClaims.issuer_id,
      organizationId: sourceClaims.organization_id,
      projectId: sourceClaims.project_id,
      workloadId: sourceClaims.workload_id,
      deploymentId: sourceClaims.deployment_id,
      audience: sourceClaims.audience,
      policySha256: sourceClaims.policy_sha256,
      imageSha256: sourceClaims.image_sha256,
      configurationSha256: sourceClaims.configuration_sha256,
      collectorSha256: sourceClaims.collector_sha256,
    },
    maxIdentityLifetimeSeconds: 600,
    nowUnix: () => now + 1,
    invokeTool,
  });
}

const request = {
  serverId: "case-tools",
  toolIdentity,
  toolRequestBody: Buffer.from('{"case_id":"private-case","api_key":"never-store"}'),
  toolRequestMediaType: "application/json" as const,
  authorityScopeIds: ["case.read"],
  logicalOperationId: "tool-call-1",
  attemptNumber: 1,
  retryOfOccurrenceSha256: null,
  parentOccurrenceSha256: null,
  stateRootBefore: rootBefore,
};

function response(overrides: Record<string, unknown> = {}) {
  return {
    resolvedServerId: toolIdentity.registry_id,
    resolvedToolIdentity: toolIdentity,
    toolResultBody: Buffer.from('{"status":"found","secret":"never-store-result"}'),
    toolResultMediaType: "application/json",
    isError: false,
    stateRootAfter: rootAfter,
    ...overrides,
  };
}

test("covered MCP invocation enforces signed identity and exact tool policy before invocation", async () => {
  const bundle = directory();
  let invocations = 0;
  const adapter = makeAdapter(bundle, async (input) => {
    invocations += 1;
    assert.equal(input.serverId, toolIdentity.registry_id);
    assert.deepEqual(input.toolIdentity, toolIdentity);
    return response();
  });
  const result = await adapter.invoke(request);
  adapter.finalize();
  assert.equal(invocations, 1);
  assert.equal(result.disposition, "completed");
  assert.equal(result.action?.outcome, "success");
  assert.doesNotThrow(() => verifyEnforcementBoundary(result.boundary));
  assert.deepEqual(verifySdkBundle(bundle).blockers, []);
  const evidence = readFileSync(join(bundle, "frames.ndjson"), "utf8");
  assert.match(evidence, new RegExp(result.boundary.boundary_sha256));
  assert.doesNotMatch(evidence, /private-case|never-store|api_key|secret/);
});

test("unlisted tool, wrong scope, and MCP server confusion deny with no invocation", async () => {
  const cases = [
    { ...request, toolIdentity: { ...toolIdentity, tool_id: "case.delete" } },
    { ...request, authorityScopeIds: ["case.write"] },
    { ...request, serverId: "case-tools.evil" },
  ];
  for (const [index, candidate] of cases.entries()) {
    let invocations = 0;
    const bundle = directory("gradia-mcp-deny-");
    const adapter = makeAdapter(bundle, async () => {
      invocations += 1;
      throw new Error("must not invoke");
    });
    const result = await adapter.invoke({
      ...candidate,
      logicalOperationId: `denied-tool-${index}`,
    });
    adapter.finalize();
    assert.equal(invocations, 0);
    assert.equal(result.disposition, "blocked");
    assert.deepEqual(verifySdkBundle(bundle).blockers, []);
  }
});

test("tampered signed identity and tampered sealed policy fail before tool invocation", async () => {
  const sourcePolicy = policy();
  const identity = issueWorkloadIdentity(claims(sourcePolicy), "issuer-key-v1", keys.privateKey);
  const tamperedIdentity = JSON.parse(canonicalJson(identity)) as GuardWorkloadIdentity;
  tamperedIdentity.claims.workload_id = "attacker";
  let invocations = 0;
  const bundle = directory("gradia-mcp-identity-");
  const adapter = makeAdapter(
    bundle,
    async () => {
      invocations += 1;
      return response();
    },
    { policy: sourcePolicy, identity: tamperedIdentity },
  );
  const result = await adapter.invoke(request);
  adapter.finalize();
  assert.equal(invocations, 0);
  assert.equal(result.disposition, "blocked");
  assert.equal(result.identitySha256, null);

  const tamperedPolicy = JSON.parse(canonicalJson(sourcePolicy)) as GuardPolicy;
  tamperedPolicy.tool_routes[0]!.max_request_bytes += 1;
  assert.throws(
    () => makeAdapter(directory(), async () => response(), { policy: tamperedPolicy }),
    /guard_policy_digest_mismatch/,
  );
});

test("server, tool, version, and interface substitution are withheld and fail evidence verification", async () => {
  const substitutions = [
    { resolvedServerId: "substitute-server" },
    { resolvedToolIdentity: { ...toolIdentity, tool_id: "case.write" } },
    { resolvedToolIdentity: { ...toolIdentity, tool_version: "v2" } },
    { resolvedToolIdentity: { ...toolIdentity, interface_sha256: digestCanonical({ other: true }) } },
  ];
  for (const [index, substitution] of substitutions.entries()) {
    const bundle = directory("gradia-mcp-substitution-");
    const adapter = makeAdapter(bundle, async () => response(substitution));
    const result = await adapter.invoke({
      ...request,
      logicalOperationId: `substitution-${index}`,
    });
    adapter.finalize();
    assert.equal(result.disposition, "identity_mismatch");
    assert.equal(result.response, null);
    assert.ok(
      verifySdkBundle(bundle).blockers.some((item) =>
        item.startsWith("sdk_identity_mismatch_recorded"),
      ),
    );
  }
});

test("MCP transport, tool, and protocol failures remain distinct and secret-free", async () => {
  const cases: readonly [GuardMcpToolInvoker, string][] = [
    [async () => { throw new Error("private credential detail"); }, "tool_failure"],
    [async () => response({ isError: true }), "tool_failure"],
    [async () => ({ ...response(), toolResultBody: new Uint8Array() }), "protocol_failure"],
  ];
  for (const [index, [invoker, expected]] of cases.entries()) {
    const bundle = directory("gradia-mcp-failure-");
    const adapter = makeAdapter(bundle, invoker);
    const result = await adapter.invoke({ ...request, logicalOperationId: `failure-${index}` });
    adapter.finalize();
    assert.equal(result.disposition, expected);
    assert.deepEqual(verifySdkBundle(bundle).blockers, []);
    assert.doesNotMatch(
      readFileSync(join(bundle, "frames.ndjson"), "utf8"),
      /private credential detail|never-store-result/,
    );
  }
});

test("MCP adapter has no header or credential extension and boundary discloses bypass", async () => {
  const adapter = makeAdapter(directory(), async () => response());
  await assert.rejects(
    adapter.invoke({
      ...request,
      headers: { authorization: "Bearer never-store" },
    } as Parameters<AuthenticatedMcpToolAdapter["invoke"]>[0]),
    /guard_mcp_request_keys_invalid/,
  );
  assert.throws(() => adapter.finalize(), /sdk_empty_bundle_cannot_finalize/);

  const boundary = enforcementBoundary("mcp_tool_adapter");
  assert.equal(boundary.capture_boundary, "explicit_mcp_tool_adapter");
  assert.equal(boundary.bypass_possible, true);
  assert.equal(boundary.full_host_enforcement, false);
  assert.equal(boundary.kubernetes_network_policy_enforced, false);
  assert.match(boundary.bypass_declaration, /not_invoked_through_this_adapter/);
  const overclaim = JSON.parse(canonicalJson(boundary)) as typeof boundary;
  (overclaim as unknown as { bypass_possible: boolean }).bypass_possible = false;
  assert.throws(() => verifyEnforcementBoundary(overclaim), /boundary_mismatch/);
});
