import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { appendFileSync, existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  canonicalJson,
  digestCanonical,
  issueWorkloadIdentity,
  MCP_HTTP_PROXY_PROTOCOL_VERSION,
  sealMcpHttpProxyConfiguration,
  sealPolicy,
  startAuthenticatedMcpHttpProxy,
  verifyMcpHttpAccessBundle,
  verifyMcpHttpAccessBundleDirectory,
  verifyMcpHttpProxyConfiguration,
  verifySdkBundle,
  type GuardMcpHttpProxyConfiguration,
  type McpHttpAccessBundle,
  type GuardMcpToolInvoker,
  type GuardPolicy,
  type GuardWorkloadIdentityClaims,
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

function policy(): GuardPolicy {
  return sealPolicy({
    schema_version: "gradia.guard.policy.v1",
    policy_id: "mcp-http-policy",
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
        max_attempt_number: 1,
      },
    ],
  });
}

function configuration(): GuardMcpHttpProxyConfiguration {
  return sealMcpHttpProxyConfiguration({
    schema_version: "gradia.guard.mcp-http-proxy-configuration.v1",
    configuration_id: "mcp-http-configuration",
    configuration_version: "v1",
    default_decision: "blocked",
    tool_routes: [
      {
        server_id: "case-tools",
        tool_name: "case.read",
        tool_identity: toolIdentity,
        authority_scope_ids: ["case.read"],
        description: "Read one permitted case by exact identifier.",
        input_schema: {
          type: "object",
          additionalProperties: false,
          properties: { case_id: { type: "string" } },
          required: ["case_id"],
        },
      },
    ],
  });
}

function claims(sourcePolicy: GuardPolicy, sourceConfiguration: GuardMcpHttpProxyConfiguration) {
  return {
    issuer_id: "gradia-managed",
    organization_id: "org-1",
    project_id: "project-1",
    workload_id: "agent-1",
    deployment_id: "deployment-1",
    audience: "guard-mcp-http",
    policy_sha256: sourcePolicy.policy_sha256,
    image_sha256: digestCanonical({ image: "v1" }),
    configuration_sha256: sourceConfiguration.configuration_sha256,
    collector_sha256: digestCanonical({ collector: "mcp-http-v1" }),
    authority_scope_ids: ["case.read"],
    issued_at_unix: now,
    not_before_unix: now,
    expires_at_unix: now + 300,
    nonce_sha256: digestCanonical({ nonce: "mcp-http" }),
  } satisfies GuardWorkloadIdentityClaims;
}

function directory(): string {
  return join(mkdtempSync(join(tmpdir(), "gradia-mcp-http-")), "runtime");
}

async function proxy(invokeTool: GuardMcpToolInvoker) {
  const sourcePolicy = policy();
  const sourceConfiguration = configuration();
  const sourceClaims = claims(sourcePolicy, sourceConfiguration);
  const root = directory();
  const instance = await startAuthenticatedMcpHttpProxy({
    directory: root,
    policy: sourcePolicy,
    configuration: sourceConfiguration,
    workloadIdentity: issueWorkloadIdentity(sourceClaims, "issuer-key-v1", keys.privateKey),
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
  return { instance, root };
}

function headers(environment: Readonly<Record<string, string>>, method: string, name?: string) {
  return {
    authorization: environment["GRADIA_GUARD_MCP_AUTHORIZATION"] as string,
    "content-type": "application/json",
    "mcp-protocol-version": environment["GRADIA_GUARD_MCP_PROTOCOL_VERSION"] as string,
    "mcp-method": method,
    ...(name === undefined ? {} : { "mcp-name": name }),
  };
}

async function post(
  endpoint: string,
  environment: Readonly<Record<string, string>>,
  body: Record<string, unknown>,
  overrides: Record<string, string> = {},
) {
  const method = String(body["method"]);
  const params: Record<string, unknown> = {
    ...(body["params"] as Record<string, unknown>),
    _meta: {
      "io.modelcontextprotocol/clientCapabilities": {},
      "io.modelcontextprotocol/clientInfo": { name: "test-client", version: "1.0.0" },
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    },
  };
  return fetch(endpoint, {
    method: "POST",
    headers: { ...headers(environment, method, params["name"] as string | undefined), ...overrides },
    body: canonicalJson({ ...body, params }),
  });
}

function successfulResponse() {
  return {
    resolvedServerId: toolIdentity.registry_id,
    resolvedToolIdentity: toolIdentity,
    toolResultBody: Buffer.from(
      canonicalJson({ content: [{ text: "found", type: "text" }], isError: false }),
    ),
    toolResultMediaType: "application/json",
    isError: false,
    stateRootAfter: null,
  };
}

test("modern MCP HTTP discovery and exact tool call produce verified secret-free G2 evidence", async () => {
  let invocations = 0;
  const { instance, root } = await proxy(async (input) => {
    invocations += 1;
    assert.equal(input.serverId, "case-tools");
    assert.deepEqual(input.toolIdentity, toolIdentity);
    assert.equal(Buffer.from(input.toolRequestBody).toString("utf8"), '{"case_id":"private-case"}');
    return successfulResponse();
  });
  const environment = instance.childEnvironment("case-tools");
  const endpoint = environment["GRADIA_GUARD_MCP_ENDPOINT"] as string;
  assert.match(endpoint, /^http:\/\/127\.0\.0\.1:[0-9]+\/mcp\/case-tools$/);

  const listed = await post(endpoint, environment, {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/list",
    params: {},
  });
  assert.equal(listed.status, 200);
  const listedText = await listed.text();
  assert.match(listedText, /case\.read/);
  assert.match(listedText, /"cacheScope":"private"/);
  assert.match(listedText, /"resultType":"complete"/);

  const discovered = await post(endpoint, environment, {
    jsonrpc: "2.0",
    id: "discover-1",
    method: "server/discover",
    params: {},
  });
  assert.equal(discovered.status, 200);
  const discoveredText = await discovered.text();
  assert.match(discoveredText, /2026-07-28/);
  assert.match(discoveredText, /gradia-guard-mcp-proxy/);

  const called = await post(endpoint, environment, {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: { name: "case.read", arguments: { case_id: "private-case" } },
  });
  assert.equal(called.status, 200);
  assert.match(called.headers.get("x-gradia-occurrence-sha256") ?? "", /^[a-f0-9]{64}$/);
  assert.match(await called.text(), /found/);

  const closed = await instance.close();
  assert.equal(invocations, 1);
  assert.equal(closed.sdk_bundle_directory, join(root, "mcp-evidence"));
  assert.equal(closed.http_access_bundle_directory, join(root, "mcp-http-access"));
  assert.equal(closed.http_access_receipt_count, 3);
  assert.match(closed.http_access_chain_head_sha256, /^[a-f0-9]{64}$/);
  assert.equal(closed.accepted_tool_requests, 1);
  assert.equal(closed.blocked_tool_requests, 0);
  assert.deepEqual(verifySdkBundle(join(root, "mcp-evidence")).blockers, []);
  const evidence = readFileSync(join(root, "mcp-evidence", "frames.ndjson"), "utf8");
  assert.doesNotMatch(evidence, /private-case|found/);
  assert.match(evidence, new RegExp(configuration().configuration_sha256));
  const accessDirectory = join(root, "mcp-http-access");
  const accessVerification = verifyMcpHttpAccessBundleDirectory(accessDirectory);
  assert.equal(accessVerification.ok, true, accessVerification.blockers.join(","));
  assert.deepEqual(accessVerification.counters, {
    total_requests: 3,
    completed_metadata_requests: 2,
    accepted_tool_requests: 1,
    blocked_tool_requests: 0,
    unauthorized_http_requests: 0,
    malformed_http_requests: 0,
    failed_tool_requests: 0,
  });
  const accessEvidence = ["header.json", "receipts.ndjson", "bundle.json"]
    .map((name) => readFileSync(join(accessDirectory, name), "utf8"))
    .join("\n");
  assert.doesNotMatch(accessEvidence, /private-case|found/);
  assert.doesNotMatch(
    accessEvidence,
    new RegExp((environment["GRADIA_GUARD_MCP_AUTHORIZATION"] as string).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
  );
});

test("unlisted tools, header mismatch, wrong capability, and browser origins never invoke upstream", async () => {
  let invocations = 0;
  const { instance, root } = await proxy(async () => {
    invocations += 1;
    return successfulResponse();
  });
  const environment = instance.childEnvironment("case-tools");
  const endpoint = environment["GRADIA_GUARD_MCP_ENDPOINT"] as string;
  const unlisted = await post(endpoint, environment, {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name: "case.delete", arguments: {} },
  });
  assert.equal(unlisted.status, 403);
  const mismatch = await post(
    endpoint,
    environment,
    {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "case.read", arguments: { case_id: "x" } },
    },
    { "mcp-name": "case.delete" },
  );
  assert.equal(mismatch.status, 400);
  const wrong = await post(
    endpoint,
    environment,
    { jsonrpc: "2.0", id: 3, method: "tools/list", params: {} },
    { authorization: "Bearer wrong" },
  );
  assert.equal(wrong.status, 401);
  const origin = await post(
    endpoint,
    environment,
    { jsonrpc: "2.0", id: 4, method: "tools/list", params: {} },
    { origin: "https://attacker.example" },
  );
  assert.equal(origin.status, 403);

  const success = await post(endpoint, environment, {
    jsonrpc: "2.0",
    id: 5,
    method: "tools/call",
    params: { name: "case.read", arguments: { case_id: "allowed" } },
  });
  assert.equal(success.status, 200);

  const adapterDenied = await post(endpoint, environment, {
    jsonrpc: "2.0",
    id: 6,
    method: "tools/call",
    params: { name: "case.read", arguments: { case_id: "x".repeat(20_000) } },
  });
  assert.equal(adapterDenied.status, 403);
  assert.match(adapterDenied.headers.get("x-gradia-occurrence-sha256") ?? "", /^[a-f0-9]{64}$/);
  const closed = await instance.close();
  assert.equal(invocations, 1);
  assert.equal(closed.blocked_tool_requests, 2);
  assert.equal(closed.malformed_http_requests, 1);
  assert.equal(closed.unauthorized_http_requests, 2);
  assert.deepEqual(verifySdkBundle(join(root, "mcp-evidence")).blockers, []);
  const accessDirectory = join(root, "mcp-http-access");
  const accessVerification = verifyMcpHttpAccessBundleDirectory(accessDirectory);
  assert.equal(accessVerification.ok, true, accessVerification.blockers.join(","));
  assert.deepEqual(accessVerification.counters, {
    total_requests: 6,
    completed_metadata_requests: 0,
    accepted_tool_requests: 1,
    blocked_tool_requests: 3,
    unauthorized_http_requests: 2,
    malformed_http_requests: 1,
    failed_tool_requests: 0,
  });
  const bundle = JSON.parse(
    readFileSync(join(accessDirectory, "bundle.json"), "utf8"),
  ) as McpHttpAccessBundle;
  assert.deepEqual(bundle.receipts.map((receipt) => receipt.outcome.reason_code), [
    "tool_route_not_allowed",
    "protocol_refused",
    "authorization_refused",
    "origin_not_allowed",
    "tool_call_completed",
    "adapter_policy_refused",
  ]);
  assert.equal(bundle.receipts[2]?.request.body_observed, false);
  assert.equal(bundle.receipts[3]?.request.body_observed, false);
  assert.equal(bundle.receipts[4]?.outcome.upstream_invoked, true);
  assert.equal(bundle.receipts[5]?.outcome.upstream_invoked, false);
  assert.match(bundle.receipts[5]?.outcome.sdk_occurrence_sha256 ?? "", /^[a-f0-9]{64}$/);
});

test("HTTP access verifier refuses mutation, reorder, count drift, and journal truncation", async () => {
  const { instance, root } = await proxy(async () => successfulResponse());
  const environment = instance.childEnvironment("case-tools");
  const endpoint = environment["GRADIA_GUARD_MCP_ENDPOINT"] as string;
  await post(endpoint, environment, {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/list",
    params: {},
  });
  await post(endpoint, environment, {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: { name: "case.read", arguments: { case_id: "mutation-secret" } },
  });
  await instance.close();
  const accessDirectory = join(root, "mcp-http-access");
  const original = JSON.parse(
    readFileSync(join(accessDirectory, "bundle.json"), "utf8"),
  ) as McpHttpAccessBundle;

  const mutated = JSON.parse(canonicalJson(original)) as McpHttpAccessBundle;
  mutated.receipts[0]!.outcome.http_status = 500;
  assert.equal(verifyMcpHttpAccessBundle(mutated).ok, false);

  const reordered = JSON.parse(canonicalJson(original)) as McpHttpAccessBundle;
  reordered.receipts = [reordered.receipts[1]!, reordered.receipts[0]!];
  assert.equal(verifyMcpHttpAccessBundle(reordered).ok, false);

  const shortened = JSON.parse(canonicalJson(original)) as McpHttpAccessBundle;
  shortened.receipts = shortened.receipts.slice(0, 1);
  assert.equal(verifyMcpHttpAccessBundle(shortened).ok, false);

  appendFileSync(join(accessDirectory, "receipts.ndjson"), "{", "utf8");
  const truncated = verifyMcpHttpAccessBundleDirectory(accessDirectory);
  assert.equal(truncated.ok, false);
  assert.ok(truncated.blockers.includes("mcp_http_access_journal_truncated"));
});

test("HTTP access verifier fails closed rather than throwing on arbitrary malformed shapes", () => {
  for (const candidate of [
    null,
    {},
    { header: {}, receipts: [null], finalization: {} },
    { header: [], receipts: {}, finalization: [] },
    { header: { schema_version: "wrong" }, receipts: [{}], finalization: { counters: null } },
  ]) {
    const result = verifyMcpHttpAccessBundle(candidate);
    assert.equal(result.ok, false);
    assert.ok(result.blockers.length > 0);
  }
});

test("HTTP method, target, and malformed body refusals are durable and never invoke upstream", async () => {
  let invocations = 0;
  const { instance, root } = await proxy(async () => {
    invocations += 1;
    return successfulResponse();
  });
  const environment = instance.childEnvironment("case-tools");
  const endpoint = environment["GRADIA_GUARD_MCP_ENDPOINT"] as string;
  const authorization = environment["GRADIA_GUARD_MCP_AUTHORIZATION"] as string;

  const wrongMethod = await fetch(endpoint, {
    method: "GET",
    headers: { authorization, "content-type": "application/json" },
  });
  assert.equal(wrongMethod.status, 400);

  const wrongTarget = await fetch(`${instance.origin}/mcp/not-configured`, {
    method: "POST",
    headers: {
      authorization,
      "content-type": "application/json",
      "mcp-method": "tools/list",
      "mcp-protocol-version": MCP_HTTP_PROXY_PROTOCOL_VERSION,
    },
    body: "{}",
  });
  assert.equal(wrongTarget.status, 400);

  const malformedBody = await fetch(endpoint, {
    method: "POST",
    headers: {
      authorization,
      "content-type": "application/json",
      "mcp-method": "tools/list",
      "mcp-protocol-version": MCP_HTTP_PROXY_PROTOCOL_VERSION,
    },
    body: "{",
  });
  assert.equal(malformedBody.status, 400);

  const closed = await instance.close();
  assert.equal(invocations, 0);
  assert.equal(closed.sdk_bundle_directory, null);
  assert.equal(existsSync(join(root, "mcp-evidence")), false);
  assert.equal(closed.malformed_http_requests, 3);
  const accessDirectory = join(root, "mcp-http-access");
  const verified = verifyMcpHttpAccessBundleDirectory(accessDirectory);
  assert.equal(verified.ok, true, verified.blockers.join(","));
  assert.deepEqual(verified.counters, {
    total_requests: 3,
    completed_metadata_requests: 0,
    accepted_tool_requests: 0,
    blocked_tool_requests: 0,
    unauthorized_http_requests: 0,
    malformed_http_requests: 3,
    failed_tool_requests: 0,
  });
  const bundle = JSON.parse(
    readFileSync(join(accessDirectory, "bundle.json"), "utf8"),
  ) as McpHttpAccessBundle;
  assert.deepEqual(bundle.receipts.map((receipt) => receipt.outcome.reason_code), [
    "http_request_refused",
    "target_refused",
    "body_refused",
  ]);
  assert.deepEqual(bundle.receipts.map((receipt) => receipt.request.body_observed), [
    false,
    false,
    true,
  ]);
});

test("proxy startup verifies signed workload identity before creating evidence", async () => {
  const sourcePolicy = policy();
  const sourceConfiguration = configuration();
  const sourceClaims = claims(sourcePolicy, sourceConfiguration);
  const foreignKeys = generateKeyPairSync("ed25519");
  const root = directory();
  await assert.rejects(
    startAuthenticatedMcpHttpProxy({
      directory: root,
      policy: sourcePolicy,
      configuration: sourceConfiguration,
      workloadIdentity: issueWorkloadIdentity(
        sourceClaims,
        "issuer-key-v1",
        foreignKeys.privateKey,
      ),
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
      invokeTool: async () => successfulResponse(),
    }),
    /guard_workload_identity_signature_invalid/,
  );
  assert.equal(existsSync(root), false);
});

test("configuration is self-digested and must exactly match policy and workload identity", async () => {
  const exactConfiguration = configuration();
  assert.doesNotThrow(() => verifyMcpHttpProxyConfiguration(exactConfiguration));
  const tampered = JSON.parse(canonicalJson(exactConfiguration)) as GuardMcpHttpProxyConfiguration;
  tampered.tool_routes[0]!.description = "Changed after sealing";
  assert.throws(
    () => verifyMcpHttpProxyConfiguration(tampered),
    /guard_mcp_http_configuration_digest_mismatch/,
  );

  const sourcePolicy = policy();
  const wrongConfiguration = sealMcpHttpProxyConfiguration({
    schema_version: exactConfiguration.schema_version,
    configuration_id: exactConfiguration.configuration_id,
    configuration_version: "v2",
    default_decision: exactConfiguration.default_decision,
    tool_routes: exactConfiguration.tool_routes,
  });
  const sourceClaims = claims(sourcePolicy, exactConfiguration);
  await assert.rejects(
    startAuthenticatedMcpHttpProxy({
      directory: directory(),
      policy: sourcePolicy,
      configuration: wrongConfiguration,
      workloadIdentity: issueWorkloadIdentity(sourceClaims, "issuer-key-v1", keys.privateKey),
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
      invokeTool: async () => successfulResponse(),
    }),
    /guard_mcp_http_expected_configuration_mismatch/,
  );
});
