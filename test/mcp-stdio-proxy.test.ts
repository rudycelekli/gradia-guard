import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import {
  appendFileSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  canonicalJson,
  digestCanonical,
  DurableMcpStdioAccessRecorder,
  issueWorkloadIdentity,
  recoverInterruptedMcpStdioAccess,
  sealMcpStdioProxyConfiguration,
  sealPolicy,
  startAuthenticatedMcpStdioProxy,
  verifyMcpStdioAccessBundle,
  verifyMcpStdioAccessBundleDirectory,
  verifySdkBundle,
  type AuthenticatedMcpToolRequest,
  type GuardMcpStdioProxyConfiguration,
  type GuardPolicy,
  type GuardWorkloadIdentityClaims,
  type SdkToolIdentity,
} from "../src/index.js";
import { writeMcpStdioBufferFully } from "../src/mcp-stdio-evidence.js";

const keys = generateKeyPairSync("ed25519");
const now = 1_788_400_000;
const toolIdentity: SdkToolIdentity = {
  schema_version: "gradia.guard.sdk-tool-identity.v1",
  registry_id: "case-tools",
  tool_id: "case.read",
  tool_version: "v1",
  interface_sha256: digestCanonical({ interface: "case.read.v1" }),
};

function policy(): GuardPolicy {
  return sealPolicy({
    schema_version: "gradia.guard.policy.v1",
    policy_id: "mcp-stdio-policy",
    policy_version: "v1",
    default_decision: "blocked",
    model_routes: [],
    tool_routes: [{
      registry_id: toolIdentity.registry_id,
      tool_id: toolIdentity.tool_id,
      tool_version: toolIdentity.tool_version,
      interface_sha256: toolIdentity.interface_sha256,
      authority_scope_ids: ["case.read"],
      max_request_bytes: 10_000,
      max_attempt_number: 1,
    }],
  });
}

function configuration(): GuardMcpStdioProxyConfiguration {
  return sealMcpStdioProxyConfiguration({
    schema_version: "gradia.guard.mcp-stdio-proxy-configuration.v1",
    configuration_id: "mcp-stdio-config",
    configuration_version: "v1",
    default_decision: "blocked",
    server_id: "case-tools",
    tool_routes: [{
      tool_name: "case.read",
      tool_identity: toolIdentity,
      authority_scope_ids: ["case.read"],
    }],
  });
}

function claims(sourcePolicy: GuardPolicy, sourceConfiguration: GuardMcpStdioProxyConfiguration) {
  return {
    issuer_id: "gradia-managed",
    organization_id: "org-1",
    project_id: "project-1",
    workload_id: "agent-1",
    deployment_id: "deployment-1",
    audience: "guard-mcp-stdio",
    policy_sha256: sourcePolicy.policy_sha256,
    image_sha256: digestCanonical({ image: "v1" }),
    configuration_sha256: sourceConfiguration.configuration_sha256,
    collector_sha256: digestCanonical({ collector: "mcp-stdio-v1" }),
    authority_scope_ids: ["case.read"],
    issued_at_unix: now,
    not_before_unix: now,
    expires_at_unix: now + 300,
    nonce_sha256: digestCanonical({ nonce: "mcp-stdio" }),
  } satisfies GuardWorkloadIdentityClaims;
}

function request(input: {
  logicalOperationId: string;
  body?: Record<string, unknown>;
  identity?: SdkToolIdentity;
}): AuthenticatedMcpToolRequest {
  const identity = input.identity ?? toolIdentity;
  return {
    serverId: identity.registry_id,
    toolIdentity: identity,
    toolRequestBody: Buffer.from(canonicalJson(input.body ?? { case_id: "private-case" })),
    toolRequestMediaType: "application/json",
    authorityScopeIds: ["case.read"],
    logicalOperationId: input.logicalOperationId,
    attemptNumber: 1,
    retryOfOccurrenceSha256: null,
    parentOccurrenceSha256: null,
    stateRootBefore: null,
  };
}

function root(): string {
  return join(mkdtempSync(join(tmpdir(), "gradia-mcp-stdio-")), "session");
}

const childScript = String.raw`
let buffer = "";
let calls = 0;
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  for (;;) {
    const newline = buffer.indexOf("\n");
    if (newline < 0) return;
    const line = buffer.slice(0, newline);
    buffer = buffer.slice(newline + 1);
    const request = JSON.parse(line);
    calls += 1;
    if (request.params.arguments.mode === "crash") process.exit(17);
    process.stdout.write(JSON.stringify({
      jsonrpc: "2.0",
      id: request.id,
      result: { calls, found: request.params.arguments.case_id },
    }) + "\n");
  }
});
`;

async function proxy(directory = root()) {
  const sourcePolicy = policy();
  const sourceConfiguration = configuration();
  const sourceClaims = claims(sourcePolicy, sourceConfiguration);
  return {
    directory,
    instance: await startAuthenticatedMcpStdioProxy({
      directory,
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
      command: process.execPath,
      args: ["-e", childScript],
      responseTimeoutMs: 2_000,
    }),
  };
}

test("authorized stdio dispatch is persisted before child execution and closes with verified SDK evidence", async () => {
  const { instance, directory } = await proxy();
  const result = await instance.invoke(request({ logicalOperationId: "read-1" }));
  assert.equal(result.disposition, "completed");
  assert.deepEqual(
    JSON.parse(Buffer.from(result.response?.toolResultBody ?? []).toString("utf8")),
    { calls: 1, found: "private-case" },
  );
  const closed = await instance.close();
  assert.equal(closed.transaction_count, 1);
  assert.equal(closed.completed_transactions, 1);
  assert.equal(
    closed.protocol_subset,
    "stateless_newline_delimited_json_rpc_tools_call_only_no_initialize_initialized_discovery_notifications_streaming_or_multi_round",
  );
  assert.equal(closed.claim_boundary, "stdio_calls_through_this_spawned_child_only_not_host_or_container_non_bypassability");

  const access = verifyMcpStdioAccessBundleDirectory(join(directory, "mcp-stdio-access"));
  assert.equal(access.ok, true, access.blockers.join(","));
  assert.equal(access.receipt_count, 2);
  const journal = readFileSync(join(directory, "mcp-stdio-access", "receipts.ndjson"), "utf8");
  assert.equal(journal.includes("private-case"), false);
  const rows = journal.trim().split("\n").map((line) => JSON.parse(line) as Record<string, unknown>);
  assert.equal(rows[0]?.["receipt_kind"], "authorization");
  assert.equal(rows[0]?.["authorization_decision"], "allowed");
  assert.equal(rows[0]?.["child_stdin_write_called"], false);
  assert.equal(rows[1]?.["receipt_kind"], "terminal");
  assert.equal(rows[1]?.["child_stdin_write_called"], true);
  const header = JSON.parse(
    readFileSync(join(directory, "mcp-stdio-access", "header.json"), "utf8"),
  ) as Record<string, unknown>;
  assert.equal(
    header["child_launch_binding"],
    "declared_absolute_path_arguments_empty_environment_and_shell_false_not_executable_bytes_or_child_identity",
  );
  assert.equal(
    header["protocol_subset"],
    "stateless_newline_delimited_json_rpc_tools_call_only_no_initialize_initialized_discovery_notifications_streaming_or_multi_round",
  );
  const sdk = verifySdkBundle(join(directory, "mcp-evidence"));
  assert.equal(sdk.ok, true, sdk.blockers.join(","));
});

test("a fast response cannot outrun the exact synchronous child-stdin write-call fact", async () => {
  const { instance, directory } = await proxy();
  interface WritableProbe {
    write(
      chunk: string,
      encoding: BufferEncoding,
      callback: (error?: Error | null) => void,
    ): boolean;
  }
  const writable = (instance as unknown as { child: { stdin: WritableProbe } }).child.stdin;
  const originalWrite = writable.write.bind(writable);
  let releaseWriteCallback: (() => void) | undefined;
  writable.write = (chunk, encoding, callback) => originalWrite(
    chunk,
    encoding,
    (error) => {
      releaseWriteCallback = () => callback(error);
    },
  );

  const result = await instance.invoke(request({ logicalOperationId: "fast-response-1" }));
  assert.equal(result.disposition, "completed");
  const rowsBeforeCallback = readFileSync(
    join(directory, "mcp-stdio-access", "receipts.ndjson"),
    "utf8",
  ).trim().split("\n").map((line) => JSON.parse(line) as Record<string, unknown>);
  assert.equal(rowsBeforeCallback[1]?.["child_stdin_write_called"], true);
  assert.equal(typeof releaseWriteCallback, "function");
  releaseWriteCallback?.();
  await instance.close();
});

test("durable writers loop over partial UTF-8 writes and reject zero progress", () => {
  const source = Buffer.from("proof-🔐-bound", "utf8");
  const captured: number[] = [];
  const calls: Array<{ offset: number; length: number }> = [];
  writeMcpStdioBufferFully(99, source, (descriptor, buffer, offset, length) => {
    assert.equal(descriptor, 99);
    const count = Math.min(2, length);
    calls.push({ offset, length });
    captured.push(...buffer.subarray(offset, offset + count));
    return count;
  });
  assert.deepEqual(Buffer.from(captured), source);
  assert.ok(calls.length > 1);
  assert.throws(
    () => writeMcpStdioBufferFully(99, source, () => 0),
    /mcp_stdio_access_partial_write_failed/,
  );
});

test("unconfigured identity is blocked before stdio and the next allowed call is the child's first", async () => {
  const { instance, directory } = await proxy();
  const otherIdentity = { ...toolIdentity, tool_id: "case.delete" };
  const blocked = await instance.invoke(request({ logicalOperationId: "blocked-1", identity: otherIdentity }));
  assert.equal(blocked.disposition, "blocked");
  assert.equal(blocked.action, null);
  const allowed = await instance.invoke(request({ logicalOperationId: "read-1" }));
  const body = JSON.parse(Buffer.from(allowed.response?.toolResultBody ?? []).toString("utf8")) as { calls: number };
  assert.equal(body.calls, 1);
  const closed = await instance.close();
  assert.equal(closed.blocked_transactions, 1);
  assert.equal(closed.completed_transactions, 1);

  const rows = readFileSync(join(directory, "mcp-stdio-access", "receipts.ndjson"), "utf8")
    .trim().split("\n").map((line) => JSON.parse(line) as Record<string, unknown>);
  assert.equal(rows[0]?.["authorization_decision"], "blocked");
  assert.equal(rows[1]?.["terminal_disposition"], "blocked");
  assert.equal(rows[1]?.["child_stdin_write_called"], false);
});

test("observed child crash becomes tool failure with a closed transaction, never a model failure", async () => {
  const { instance, directory } = await proxy();
  const result = await instance.invoke(request({ logicalOperationId: "crash-1", body: { mode: "crash" } }));
  assert.equal(result.disposition, "tool_failure");
  assert.equal(result.action?.outcome, "tool_failure");
  const closed = await instance.close();
  assert.equal(closed.child_exit_code, 17);
  assert.equal(closed.failed_transactions, 1);
  const checked = verifyMcpStdioAccessBundleDirectory(join(directory, "mcp-stdio-access"));
  assert.equal(checked.ok, true, checked.blockers.join(","));
});

test("invalid argument JSON fails after authorization but before any child bytes are written", async () => {
  const { instance, directory } = await proxy();
  const malformed = request({ logicalOperationId: "malformed-1" });
  malformed.toolRequestBody = Buffer.from("not-json", "utf8");
  const failed = await instance.invoke(malformed);
  assert.equal(failed.disposition, "tool_failure");
  const allowed = await instance.invoke(request({ logicalOperationId: "read-after-malformed" }));
  const body = JSON.parse(Buffer.from(allowed.response?.toolResultBody ?? []).toString("utf8")) as { calls: number };
  assert.equal(body.calls, 1);
  await instance.close();
  const rows = readFileSync(join(directory, "mcp-stdio-access", "receipts.ndjson"), "utf8")
    .trim().split("\n").map((line) => JSON.parse(line) as Record<string, unknown>);
  assert.equal(rows[1]?.["terminal_disposition"], "tool_failure");
  assert.equal(rows[1]?.["child_stdin_write_called"], false);
});

test("recovery closes an fsynced authorized transaction only as interrupted_unknown", () => {
  const directory = root();
  const recorder = new DurableMcpStdioAccessRecorder({
    directory,
    sessionId: "recovery-1",
    createdAt: "2026-09-03T12:00:00.000Z",
    configurationSha256: digestCanonical({ configuration: "v1" }),
    policySha256: digestCanonical({ policy: "v1" }),
    workloadIdentitySha256: digestCanonical({ identity: "v1" }),
    childLaunchDeclarationSha256: digestCanonical({ command: "v1" }),
    now: () => "2026-09-03T12:00:01.000Z",
  });
  recorder.authorize({
    requestId: "request-1",
    logicalOperationId: "operation-1",
    attemptNumber: 1,
    routeSha256: digestCanonical({ route: "v1" }),
    requestSha256: digestCanonical({ request: "v1" }),
    requestByteLength: 42,
  }, "allowed");
  const bundle = recoverInterruptedMcpStdioAccess(
    directory,
    () => "2026-09-03T12:00:02.000Z",
  );
  const checked = verifyMcpStdioAccessBundle(bundle);
  assert.equal(checked.ok, true, checked.blockers.join(","));
  assert.equal(bundle.finalization.terminal_status, "recovered_interruption");
  assert.equal(bundle.finalization.counters.interrupted_unknown_transactions, 1);
  const terminal = bundle.receipts.at(-1);
  assert.equal(terminal?.receipt_kind, "terminal");
  if (terminal?.receipt_kind === "terminal") {
    assert.equal(terminal.terminal_disposition, "interrupted_unknown");
    assert.equal(terminal.sdk_occurrence_sha256, null);
    assert.equal(terminal.recovery_synthesized, true);
  }
});

test("MCP stdio CLI recovers and independently verifies an interrupted prefix", () => {
  const directory = root();
  const recorder = new DurableMcpStdioAccessRecorder({
    directory,
    sessionId: "stdio-cli-recovery",
    createdAt: "2020-01-01T00:00:00.000Z",
    configurationSha256: digestCanonical({ configuration: "v1" }),
    policySha256: digestCanonical({ policy: "v1" }),
    workloadIdentitySha256: digestCanonical({ identity: "v1" }),
    childLaunchDeclarationSha256: digestCanonical({ command: "v1" }),
    now: () => "2020-01-01T00:00:01.000Z",
  });
  recorder.authorize({
    requestId: "request-1",
    logicalOperationId: "operation-1",
    attemptNumber: 1,
    routeSha256: digestCanonical({ route: "v1" }),
    requestSha256: digestCanonical({ request: "v1" }),
    requestByteLength: 42,
  }, "allowed");

  const recovered = JSON.parse(
    execFileSync(
      process.execPath,
      ["dist/src/cli.js", "mcp-stdio", "recover", directory],
      { cwd: process.cwd(), encoding: "utf8" },
    ),
  ) as Record<string, unknown>;
  assert.equal(recovered["ok"], true);
  assert.equal(recovered["terminal_status"], "recovered_interruption");
  assert.equal(recovered["recovery_performed"], true);
  assert.equal(recovered["receipt_count"], 2);

  const verified = JSON.parse(
    execFileSync(
      process.execPath,
      ["dist/src/cli.js", "mcp-stdio", "verify", directory],
      { cwd: process.cwd(), encoding: "utf8" },
    ),
  ) as Record<string, unknown>;
  assert.equal(verified["ok"], true);
  assert.equal(verified["receipt_count"], 2);
  assert.equal(
    verified["claim_boundary"],
    "stdio_calls_through_this_dispatcher_only_not_host_or_container_non_bypassability",
  );
});

test("recovery can finalize a completely closed durable prefix without inventing another transaction", () => {
  const directory = root();
  const recorder = new DurableMcpStdioAccessRecorder({
    directory,
    createdAt: "2026-09-03T12:00:00.000Z",
    configurationSha256: digestCanonical({ configuration: "v1" }),
    policySha256: digestCanonical({ policy: "v1" }),
    workloadIdentitySha256: digestCanonical({ identity: "v1" }),
    childLaunchDeclarationSha256: digestCanonical({ command: "v1" }),
    now: () => "2026-09-03T12:00:01.000Z",
  });
  recorder.authorize({
    requestId: "request-closed",
    logicalOperationId: "operation-closed",
    attemptNumber: 1,
    routeSha256: digestCanonical({ route: "v1" }),
    requestSha256: digestCanonical({ request: "v1" }),
    requestByteLength: 42,
  }, "blocked");
  recorder.terminal(
    "request-closed",
    "blocked",
    digestCanonical({ occurrence: "closed" }),
    false,
  );
  const bundle = recoverInterruptedMcpStdioAccess(
    directory,
    () => "2026-09-03T12:00:02.000Z",
  );
  assert.equal(bundle.receipts.length, 2);
  assert.equal(bundle.finalization.recovery_performed, true);
  assert.equal(bundle.finalization.terminal_status, "recovered_interruption");
  assert.equal(verifyMcpStdioAccessBundle(bundle).ok, true);
});

test("truncated recovery journal and post-finalization mutation are rejected", () => {
  const directory = root();
  const recorder = new DurableMcpStdioAccessRecorder({
    directory,
    createdAt: "2026-09-03T12:00:00.000Z",
    configurationSha256: digestCanonical({ configuration: "v1" }),
    policySha256: digestCanonical({ policy: "v1" }),
    workloadIdentitySha256: digestCanonical({ identity: "v1" }),
    childLaunchDeclarationSha256: digestCanonical({ command: "v1" }),
    now: () => "2026-09-03T12:00:01.000Z",
  });
  recorder.authorize({
    requestId: "request-1",
    logicalOperationId: "operation-1",
    attemptNumber: 1,
    routeSha256: digestCanonical({ route: "v1" }),
    requestSha256: digestCanonical({ request: "v1" }),
    requestByteLength: 42,
  }, "blocked");
  recorder.terminal("request-1", "blocked", digestCanonical({ occurrence: "v1" }), false);
  recorder.finalize();
  const bundlePath = join(directory, "bundle.json");
  const bundle = JSON.parse(readFileSync(bundlePath, "utf8")) as {
    receipts: Array<Record<string, unknown>>;
  };
  if (bundle.receipts[1] !== undefined) bundle.receipts[1]["child_stdin_write_called"] = true;
  writeFileSync(bundlePath, `${canonicalJson(bundle)}\n`);
  assert.equal(verifyMcpStdioAccessBundleDirectory(directory).ok, false);

  const interrupted = root();
  const open = new DurableMcpStdioAccessRecorder({
    directory: interrupted,
    createdAt: "2026-09-03T12:00:00.000Z",
    configurationSha256: digestCanonical({ configuration: "v1" }),
    policySha256: digestCanonical({ policy: "v1" }),
    workloadIdentitySha256: digestCanonical({ identity: "v1" }),
    childLaunchDeclarationSha256: digestCanonical({ command: "v1" }),
    now: () => "2026-09-03T12:00:01.000Z",
  });
  open.authorize({
    requestId: "request-2",
    logicalOperationId: "operation-2",
    attemptNumber: 1,
    routeSha256: digestCanonical({ route: "v2" }),
    requestSha256: digestCanonical({ request: "v2" }),
    requestByteLength: 42,
  }, "allowed");
  appendFileSync(join(interrupted, "receipts.ndjson"), "{");
  assert.throws(
    () => recoverInterruptedMcpStdioAccess(interrupted, () => "2026-09-03T12:00:02.000Z"),
    /mcp_stdio_access_recovery_invalid/,
  );
});

test("startup refuses a policy containing child-unconfigured routes", async () => {
  const sourceConfiguration = configuration();
  const basePolicy = policy();
  const sourcePolicy = sealPolicy({
    schema_version: basePolicy.schema_version,
    policy_id: basePolicy.policy_id,
    policy_version: basePolicy.policy_version,
    default_decision: basePolicy.default_decision,
    model_routes: basePolicy.model_routes,
    tool_routes: [
      ...basePolicy.tool_routes,
      {
        registry_id: "other-server",
        tool_id: "other.read",
        tool_version: "v1",
        interface_sha256: digestCanonical({ interface: "other" }),
        authority_scope_ids: ["case.read"],
        max_request_bytes: 100,
        max_attempt_number: 1,
      },
    ],
  });
  const sourceClaims = claims(sourcePolicy, sourceConfiguration);
  await assert.rejects(
    startAuthenticatedMcpStdioProxy({
      directory: root(),
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
      command: process.execPath,
      args: ["-e", childScript],
    }),
    /guard_mcp_stdio_policy_has_unconfigured_tool_routes/,
  );
});

test("a child that exits immediately cannot be dispatched to and still closes access evidence", async () => {
  const sourcePolicy = policy();
  const sourceConfiguration = configuration();
  const sourceClaims = claims(sourcePolicy, sourceConfiguration);
  const directory = root();
  const instance = await startAuthenticatedMcpStdioProxy({
    directory,
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
    command: process.execPath,
    args: ["-e", "process.exit(23)"],
  });
  await new Promise((resolve) => setTimeout(resolve, 30));
  const outcome = await instance.invoke(request({ logicalOperationId: "late-1" }))
    .then((result) => result.disposition, (error: unknown) => {
      assert.match(String(error), /child_not_running/);
      return "not_running" as const;
    });
  assert.ok(["not_running", "tool_failure"].includes(outcome));
  const closed = await instance.close();
  assert.equal(closed.child_exit_code, 23);
  assert.ok([0, 1].includes(closed.transaction_count));
  assert.equal(verifyMcpStdioAccessBundleDirectory(join(directory, "mcp-stdio-access")).ok, true);
});

test("spawn failure leaves a recoverable zero-transaction access prefix", async () => {
  const sourcePolicy = policy();
  const sourceConfiguration = configuration();
  const sourceClaims = claims(sourcePolicy, sourceConfiguration);
  const directory = root();
  await assert.rejects(
    startAuthenticatedMcpStdioProxy({
      directory,
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
      command: `/definitely-not-a-real-gradia-mcp-server-${process.pid}`,
    }),
    /guard_mcp_stdio_spawn_failed/,
  );
  const accessDirectory = join(directory, "mcp-stdio-access");
  const recovered = recoverInterruptedMcpStdioAccess(
    accessDirectory,
    () => "2026-09-03T12:00:02.000Z",
  );
  assert.equal(recovered.finalization.counters.total_transactions, 0);
  assert.equal(recovered.finalization.terminal_status, "recovered_interruption");
  const checked = verifyMcpStdioAccessBundleDirectory(accessDirectory);
  assert.equal(checked.ok, true, checked.blockers.join(","));
});
