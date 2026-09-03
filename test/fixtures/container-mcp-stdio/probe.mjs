import { createHash, generateKeyPairSync } from "node:crypto";
import { connect } from "node:net";
import { lstatSync, readFileSync, readlinkSync, readdirSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import {
  canonicalJson,
  digestCanonical,
  issueWorkloadIdentity,
  sealMcpStdioProxyConfiguration,
  sealPolicy,
  startAuthenticatedMcpStdioProxy,
  verifyMcpStdioAccessBundleDirectory,
  verifySdkBundle,
} from "/opt/guard/dist/src/index.js";

const PACKAGE_NAME = "@modelcontextprotocol/server-everything";
const PACKAGE_VERSION = "2026.8.31";
const PACKAGE_ROOT = "/opt/guard/node_modules/@modelcontextprotocol/server-everything";
const ENTRYPOINT = `${PACKAGE_ROOT}/dist/index.js`;
const COMMAND = "/usr/local/bin/node";
const OUTPUT = "/proof-output";
const DEPENDENCY_LOCK = "/opt/guard/package-lock.json";
const NOW = Math.floor(Date.now() / 1000);
const keys = generateKeyPairSync("ed25519");

function shaFile(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function shaTree(root) {
  const entries = [];
  const stack = [root];
  while (stack.length > 0) {
    const path = stack.pop();
    const stat = lstatSync(path);
    const name = relative(root, path) || ".";
    if (stat.isDirectory()) {
      stack.push(...readdirSync(path).sort().reverse().map((child) => join(path, child)));
    } else if (stat.isSymbolicLink()) {
      entries.push({ path: name, kind: "symlink", target: readlinkSync(path) });
    } else if (stat.isFile()) {
      entries.push({ path: name, kind: "file", byte_length: stat.size, sha256: shaFile(path) });
    }
  }
  return digestCanonical(entries);
}

function identity(toolName, shape) {
  return {
    schema_version: "gradia.guard.sdk-tool-identity.v1",
    registry_id: "official-everything",
    tool_id: toolName,
    tool_version: PACKAGE_VERSION,
    interface_sha256: digestCanonical({
      package: PACKAGE_NAME,
      version: PACKAGE_VERSION,
      tool: toolName,
      arguments: shape,
    }),
  };
}

async function runCell({ id, tool, args, timeoutMs }) {
  const toolIdentity = identity(tool, tool === "echo"
    ? { message: "string" }
    : { duration: "number", steps: "number" });
  const scope = `mcp.${id}`;
  const policy = sealPolicy({
    schema_version: "gradia.guard.policy.v1",
    policy_id: `container-${id}`,
    policy_version: PACKAGE_VERSION,
    default_decision: "blocked",
    model_routes: [],
    tool_routes: [{
      registry_id: toolIdentity.registry_id,
      tool_id: toolIdentity.tool_id,
      tool_version: toolIdentity.tool_version,
      interface_sha256: toolIdentity.interface_sha256,
      authority_scope_ids: [scope],
      max_request_bytes: 4_096,
      max_attempt_number: 1,
    }],
  });
  const configuration = sealMcpStdioProxyConfiguration({
    schema_version: "gradia.guard.mcp-stdio-proxy-configuration.v1",
    configuration_id: `container-${id}`,
    configuration_version: PACKAGE_VERSION,
    default_decision: "blocked",
    server_id: toolIdentity.registry_id,
    tool_routes: [{
      tool_name: toolIdentity.tool_id,
      tool_identity: toolIdentity,
      authority_scope_ids: [scope],
    }],
  });
  const claims = {
    issuer_id: "gradia-container-proof",
    organization_id: "gradia-public",
    project_id: "guard-mcp",
    workload_id: `official-${id}`,
    deployment_id: "docker-network-none",
    audience: "guard-mcp-stdio",
    policy_sha256: policy.policy_sha256,
    image_sha256: digestCanonical({ entrypoint_sha256: shaFile(ENTRYPOINT) }),
    configuration_sha256: configuration.configuration_sha256,
    collector_sha256: digestCanonical({ collector: "container-mcp-stdio-proof-v1" }),
    authority_scope_ids: [scope],
    issued_at_unix: NOW,
    not_before_unix: NOW,
    expires_at_unix: NOW + 300,
    nonce_sha256: digestCanonical({ id, now: NOW }),
  };
  const directory = join(OUTPUT, id);
  const proxy = await startAuthenticatedMcpStdioProxy({
    directory,
    policy,
    configuration,
    workloadIdentity: issueWorkloadIdentity(claims, "container-proof-key-v1", keys.privateKey),
    trustedPublicKeys: { "container-proof-key-v1": keys.publicKey },
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
    nowUnix: () => NOW + 1,
    command: COMMAND,
    args: [ENTRYPOINT, "stdio"],
    responseTimeoutMs: timeoutMs,
  });
  const body = Buffer.from(canonicalJson(args), "utf8");
  const result = await proxy.invoke({
    serverId: toolIdentity.registry_id,
    toolIdentity,
    toolRequestBody: body,
    toolRequestMediaType: "application/json",
    authorityScopeIds: [scope],
    logicalOperationId: `${id}-operation-1`,
    attemptNumber: 1,
    retryOfOccurrenceSha256: null,
    parentOccurrenceSha256: null,
    stateRootBefore: null,
  });
  const closed = await proxy.close();
  const access = verifyMcpStdioAccessBundleDirectory(join(directory, "mcp-stdio-access"));
  const sdk = verifySdkBundle(join(directory, "mcp-evidence"));
  if (!access.ok || !sdk.ok || access.counters === null || access.chain_head_sha256 === null || sdk.chain_head_sha256 === null) {
    throw new Error(`evidence_invalid:${id}:${[...access.blockers, ...sdk.blockers].join(",")}`);
  }
  const files = evidenceFiles(directory);
  const requestMarker = body.toString("utf8");
  const terminal = readFileSync(join(directory, "mcp-stdio-access", "receipts.ndjson"), "utf8")
    .trim().split("\n").map((line) => JSON.parse(line)).find((receipt) => receipt.receipt_kind === "terminal");
  return {
    result,
    closed,
    access,
    sdk,
    request_marker_absent: files.every((text) => !text.includes(requestMarker)),
    terminal,
  };
}

function evidenceFiles(directory) {
  const output = [];
  for (const child of ["mcp-stdio-access", "mcp-evidence"]) {
    for (const name of readdirSync(join(directory, child))) {
      output.push(readFileSync(join(directory, child, name), "utf8"));
    }
  }
  return output;
}

async function networkBlocked() {
  return await new Promise((resolve) => {
    const socket = connect({ host: "1.1.1.1", port: 443 });
    const timer = setTimeout(() => { socket.destroy(); resolve(true); }, 1_000);
    socket.once("connect", () => { clearTimeout(timer); socket.destroy(); resolve(false); });
    socket.once("error", () => { clearTimeout(timer); resolve(true); });
  });
}

const manifest = JSON.parse(readFileSync(join(PACKAGE_ROOT, "package.json"), "utf8"));
if (manifest.name !== PACKAGE_NAME || manifest.version !== PACKAGE_VERSION) {
  throw new Error("official_package_identity_mismatch");
}
if (process.execPath !== COMMAND || process.platform !== "linux" || process.getuid() !== 65532 || process.getgid() !== 65532) {
  throw new Error("container_runtime_identity_mismatch");
}
const providerNames = ["ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY", "XAI_API_KEY"]
  .filter((name) => Object.prototype.hasOwnProperty.call(process.env, name));
if (providerNames.length !== 0) throw new Error("provider_credential_name_present");

const marker = `guard-container-echo-${createHash("sha256").update(String(NOW)).digest("hex").slice(0, 16)}`;
const success = await runCell({ id: "success", tool: "echo", args: { message: marker }, timeoutMs: 5_000 });
const successBody = JSON.parse(Buffer.from(success.result.response?.toolResultBody ?? []).toString("utf8"));
if (success.result.disposition !== "completed" || canonicalJson(successBody.content) !== canonicalJson([{ type: "text", text: `Echo: ${marker}` }])) {
  throw new Error("official_echo_result_mismatch");
}
const timeout = await runCell({ id: "timeout", tool: "trigger-long-running-operation", args: { duration: 2, steps: 1 }, timeoutMs: 100 });
if (timeout.result.disposition !== "tool_failure" || timeout.closed.child_signal !== "SIGKILL" || timeout.terminal?.child_stdin_write_called !== true) {
  throw new Error("official_timeout_result_mismatch");
}

const output = {
  schema_version: "gradia.guard.container-mcp-stdio-probe-output.v1",
  observed_at: new Date().toISOString(),
  runtime: {
    platform: process.platform,
    architecture: process.arch,
    node_version: process.version,
    effective_uid: process.getuid(),
    effective_gid: process.getgid(),
    node_executable_sha256: shaFile(COMMAND),
    provider_credential_names_present: providerNames,
  },
  child: {
    package_name: manifest.name,
    package_version: manifest.version,
    package_manifest_sha256: shaFile(join(PACKAGE_ROOT, "package.json")),
    package_tree_sha256: shaTree(PACKAGE_ROOT),
    dependency_lock_sha256: shaFile(DEPENDENCY_LOCK),
    entrypoint_sha256: shaFile(ENTRYPOINT),
    command_path: COMMAND,
    command_path_sha256: shaFile(COMMAND),
    arguments: [ENTRYPOINT, "stdio"],
    success_child_launch_declaration_sha256: success.closed.stdio_access_chain_head_sha256 && JSON.parse(readFileSync(join(OUTPUT, "success", "mcp-stdio-access", "header.json"), "utf8")).child_launch_declaration_sha256,
    timeout_child_launch_declaration_sha256: timeout.closed.stdio_access_chain_head_sha256 && JSON.parse(readFileSync(join(OUTPUT, "timeout", "mcp-stdio-access", "header.json"), "utf8")).child_launch_declaration_sha256,
  },
  success: {
    disposition: success.result.disposition,
    exact_response_verified: true,
    transaction_count: success.closed.transaction_count,
    access_receipt_count: success.access.receipt_count,
    access_chain_head_sha256: success.access.chain_head_sha256,
    sdk_frame_count: success.sdk.frame_count,
    sdk_chain_head_sha256: success.sdk.chain_head_sha256,
    payload_marker_absent_from_receipt_files: success.request_marker_absent,
  },
  timeout: {
    disposition: timeout.result.disposition,
    child_stdin_write_called: timeout.terminal.child_stdin_write_called,
    child_signal: timeout.closed.child_signal,
    transaction_count: timeout.closed.transaction_count,
    access_receipt_count: timeout.access.receipt_count,
    access_chain_head_sha256: timeout.access.chain_head_sha256,
    sdk_frame_count: timeout.sdk.frame_count,
    sdk_chain_head_sha256: timeout.sdk.chain_head_sha256,
    payload_marker_absent_from_receipt_files: timeout.request_marker_absent,
  },
  network: { direct_egress_blocked: await networkBlocked() },
};
writeFileSync(join(OUTPUT, "probe-output.json"), `${canonicalJson(output)}\n`, { flag: "wx", mode: 0o600 });
