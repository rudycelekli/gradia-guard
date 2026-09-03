import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { canonicalJson, sha256 } from "../dist/src/canonical.js";
import {
  sealContainerMcpStdioProof,
  verifyContainerMcpStdioProof,
} from "../dist/src/container-mcp-stdio-proof.js";

const IMAGE = "node:22-alpine";
const DOCKER = process.env.GRADIA_GUARD_DOCKER_BINARY || "docker";
const container = `gradia-guard-mcp-${randomBytes(8).toString("hex")}`;
const requestedOutput = outputArgument(process.argv.slice(2));
const parent = requestedOutput === null
  ? mkdtempSync(join(tmpdir(), "gradia-container-mcp-stdio-"))
  : dirname(resolve(requestedOutput));
const output = requestedOutput === null ? join(parent, "proof") : resolve(requestedOutput);
if (existsSync(output)) throw new Error("container_mcp_stdio_output_exists");
mkdirSync(parent, { recursive: true, mode: 0o700 });
mkdirSync(output, { mode: 0o700 });

const packageRoot = resolve(process.cwd());
const dist = join(packageRoot, "dist");
const modules = join(packageRoot, "node_modules");
const dependencyLock = join(packageRoot, "package-lock.json");
const probe = join(packageRoot, "test", "fixtures", "container-mcp-stdio", "probe.mjs");
for (const path of [dist, modules, dependencyLock, probe]) {
  if (!existsSync(path)) throw new Error(`container_mcp_stdio_input_missing:${path}`);
}

function docker(args, options = {}) {
  return execFileSync(DOCKER, args, {
    encoding: "utf8",
    maxBuffer: 20_000_000,
    timeout: 120_000,
    ...options,
  });
}

let created = false;
try {
  const identifier = docker([
    "create",
    "--name", container,
    "--network", "none",
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--user", "65532:65532",
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
    "--mount", `type=bind,src=${dist},dst=/opt/guard/dist,readonly`,
    "--mount", `type=bind,src=${modules},dst=/opt/guard/node_modules,readonly`,
    "--mount", `type=bind,src=${dependencyLock},dst=/opt/guard/package-lock.json,readonly`,
    "--mount", `type=bind,src=${probe},dst=/opt/guard/probe.mjs,readonly`,
    "--mount", `type=bind,src=${output},dst=/proof-output`,
    IMAGE,
    "/usr/local/bin/node", "/opt/guard/probe.mjs",
  ]).trim();
  created = true;
  const inspectBefore = JSON.parse(docker(["inspect", container]))[0];
  const run = spawnSync(DOCKER, ["start", "-a", container], {
    encoding: "utf8",
    maxBuffer: 20_000_000,
    timeout: 120_000,
  });
  if (run.error || run.status !== 0 || run.stdout !== "" || run.stderr !== "") {
    throw new Error(`container_mcp_stdio_probe_failed:${run.status ?? "unavailable"}:${(run.stderr || run.stdout).trim()}`);
  }
  const inspectAfter = JSON.parse(docker(["inspect", container]))[0];
  if (inspectAfter.State.ExitCode !== 0 || inspectAfter.State.OOMKilled !== false) {
    throw new Error("container_mcp_stdio_exit_invalid");
  }
  const probeOutput = JSON.parse(readFileSync(join(output, "probe-output.json"), "utf8"));
  const securityOpt = inspectBefore.HostConfig.SecurityOpt ?? [];
  const mounts = inspectBefore.Mounts ?? [];
  const environment = inspectBefore.Config.Env ?? [];
  const providerNames = ["ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY", "XAI_API_KEY"]
    .filter((name) => environment.some((entry) => entry.startsWith(`${name}=`)));
  const body = {
    schema_version: "gradia.guard.container-mcp-stdio-proof.v1",
    proof_id: `mcp-stdio-${identifier.slice(0, 24)}`,
    observed_at: probeOutput.observed_at,
    orchestrator: "docker",
    runtime: {
      container_id_sha256: sha256(identifier),
      image_id_sha256: sha256(inspectBefore.Image),
      configured_image_sha256: sha256(inspectBefore.Config.Image),
      platform: probeOutput.runtime.platform,
      architecture: probeOutput.runtime.architecture,
      node_version: probeOutput.runtime.node_version,
      node_executable_sha256: probeOutput.runtime.node_executable_sha256,
      configured_user: inspectBefore.Config.User,
      effective_uid: probeOutput.runtime.effective_uid,
      effective_gid: probeOutput.runtime.effective_gid,
      read_only_root_filesystem: inspectBefore.HostConfig.ReadonlyRootfs,
      privileged: inspectBefore.HostConfig.Privileged,
      cap_drop: inspectBefore.HostConfig.CapDrop,
      no_new_privileges: securityOpt.includes("no-new-privileges"),
      network_mode: inspectBefore.HostConfig.NetworkMode,
      docker_socket_mounted: mounts.some((mount) => mount.Destination === "/var/run/docker.sock"),
      provider_credential_names_present: providerNames,
    },
    child: {
      package_name: probeOutput.child.package_name,
      package_version: probeOutput.child.package_version,
      package_manifest_sha256: probeOutput.child.package_manifest_sha256,
      package_tree_sha256: probeOutput.child.package_tree_sha256,
      dependency_lock_sha256: probeOutput.child.dependency_lock_sha256,
      entrypoint_sha256: probeOutput.child.entrypoint_sha256,
      command_path: probeOutput.child.command_path,
      command_path_sha256: probeOutput.child.command_path_sha256,
      arguments: probeOutput.child.arguments,
      environment: "empty",
      shell: false,
      child_launch_declaration_sha256: probeOutput.child.success_child_launch_declaration_sha256,
      resolved_identity_attestation: "configuration_and_bytes_bound_not_running_child_attested",
    },
    success: {
      tool_name: "echo",
      disposition: probeOutput.success.disposition,
      exact_response_verified: probeOutput.success.exact_response_verified,
      transaction_count: probeOutput.success.transaction_count,
      access_receipt_count: probeOutput.success.access_receipt_count,
      access_chain_head_sha256: probeOutput.success.access_chain_head_sha256,
      sdk_frame_count: probeOutput.success.sdk_frame_count,
      sdk_chain_head_sha256: probeOutput.success.sdk_chain_head_sha256,
      payload_marker_absent_from_receipt_files: probeOutput.success.payload_marker_absent_from_receipt_files,
    },
    timeout: {
      tool_name: "trigger-long-running-operation",
      response_timeout_ms: 100,
      requested_duration_seconds: 2,
      disposition: probeOutput.timeout.disposition,
      child_stdin_write_called: probeOutput.timeout.child_stdin_write_called,
      child_signal: probeOutput.timeout.child_signal,
      transaction_count: probeOutput.timeout.transaction_count,
      access_receipt_count: probeOutput.timeout.access_receipt_count,
      access_chain_head_sha256: probeOutput.timeout.access_chain_head_sha256,
      sdk_frame_count: probeOutput.timeout.sdk_frame_count,
      sdk_chain_head_sha256: probeOutput.timeout.sdk_chain_head_sha256,
      payload_marker_absent_from_receipt_files: probeOutput.timeout.payload_marker_absent_from_receipt_files,
      model_failure_inferred: false,
    },
    ceiling: {
      direct_network_egress_probe_blocked: probeOutput.network.direct_egress_blocked,
      routed_stdio_call_observed: true,
      exact_package_bytes_observed: true,
      alternate_process_or_stdio_bypass_blocked: false,
      docker_operator_bypass_possible: true,
      host_non_bypassability_proved: false,
      full_container_process_capture_proved: false,
      file_network_credential_and_side_effect_capture_proved: false,
      arbitrary_mcp_server_compatibility_proved: false,
    },
    claim_boundary: "one_exact_pinned_mcp_stdio_server_inside_one_measured_docker_boundary",
  };
  if (probeOutput.child.success_child_launch_declaration_sha256 !== probeOutput.child.timeout_child_launch_declaration_sha256) {
    throw new Error("container_mcp_stdio_child_launch_drift");
  }
  const receipt = sealContainerMcpStdioProof(body);
  const verification = verifyContainerMcpStdioProof(receipt);
  if (!verification.ok) throw new Error(`container_mcp_stdio_self_verification_failed:${verification.blockers.join(",")}`);
  assertNoSensitiveEvidence(output);
  writeFileSync(join(output, "receipt.json"), `${canonicalJson(receipt)}\n`, { flag: "wx", mode: 0o600 });
  writeFileSync(join(output, "verification.json"), `${canonicalJson(verification)}\n`, { flag: "wx", mode: 0o600 });
  assertNoSensitiveEvidence(output);
  process.stdout.write(`${canonicalJson({
    ok: true,
    output_directory: output,
    receipt_sha256: receipt.receipt_sha256,
    container_id_sha256: receipt.runtime.container_id_sha256,
    image_id_sha256: receipt.runtime.image_id_sha256,
    package_manifest_sha256: receipt.child.package_manifest_sha256,
    package_tree_sha256: receipt.child.package_tree_sha256,
    dependency_lock_sha256: receipt.child.dependency_lock_sha256,
    entrypoint_sha256: receipt.child.entrypoint_sha256,
    success_disposition: receipt.success.disposition,
    timeout_disposition: receipt.timeout.disposition,
    timeout_model_failure_inferred: receipt.timeout.model_failure_inferred,
    claim_boundary: receipt.claim_boundary,
  })}\n`);
} finally {
  if (created) {
    try { docker(["rm", "-f", container], { stdio: "ignore" }); } catch { /* best effort */ }
  }
}

function assertNoSensitiveEvidence(directory) {
  const forbidden = [
    /sk-[A-Za-z0-9_-]{16,}/,
    /AIza[A-Za-z0-9_-]{20,}/,
    /-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----/,
    /(?:ANTHROPIC|GEMINI|GOOGLE|OPENAI|XAI)_API_KEY\s*[=:]\s*[^\s\"]+/,
  ];
  const stack = [directory];
  while (stack.length > 0) {
    const path = stack.pop();
    if (statSync(path).isDirectory()) {
      stack.push(...readdirSync(path).map((name) => join(path, name)));
      continue;
    }
    const text = readFileSync(path, "utf8");
    if (forbidden.some((pattern) => pattern.test(text))) throw new Error("container_mcp_stdio_sensitive_evidence_detected");
  }
}

function outputArgument(args) {
  if (args.length === 0) return null;
  if (args.length !== 2 || args[0] !== "--out" || !args[1]) throw new Error("usage: node scripts/docker-mcp-stdio-proof.mjs [--out DIRECTORY]");
  return args[1];
}
