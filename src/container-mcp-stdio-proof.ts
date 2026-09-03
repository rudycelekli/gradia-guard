import { canonicalJson, digestCanonical, isSha256, sha256 } from "./canonical.js";
import { assertStableId } from "./security.js";

export const CONTAINER_MCP_STDIO_PROOF_SCHEMA_VERSION =
  "gradia.guard.container-mcp-stdio-proof.v1" as const;

export interface ContainerMcpStdioProofBody {
  schema_version: typeof CONTAINER_MCP_STDIO_PROOF_SCHEMA_VERSION;
  proof_id: string;
  observed_at: string;
  orchestrator: "docker";
  runtime: {
    container_id_sha256: string;
    image_id_sha256: string;
    configured_image_sha256: string;
    platform: "linux";
    architecture: string;
    node_version: string;
    node_executable_sha256: string;
    configured_user: "65532:65532";
    effective_uid: 65532;
    effective_gid: 65532;
    read_only_root_filesystem: true;
    privileged: false;
    cap_drop: readonly ["ALL"];
    no_new_privileges: true;
    network_mode: "none";
    docker_socket_mounted: false;
    provider_credential_names_present: readonly [];
  };
  child: {
    package_name: "@modelcontextprotocol/server-everything";
    package_version: "2026.8.31";
    package_manifest_sha256: string;
    package_tree_sha256: string;
    dependency_lock_sha256: string;
    entrypoint_sha256: string;
    command_path: "/usr/local/bin/node";
    command_path_sha256: string;
    arguments: readonly [
      "/opt/guard/node_modules/@modelcontextprotocol/server-everything/dist/index.js",
      "stdio",
    ];
    environment: "empty";
    shell: false;
    child_launch_declaration_sha256: string;
    resolved_identity_attestation: "configuration_and_bytes_bound_not_running_child_attested";
  };
  success: {
    tool_name: "echo";
    disposition: "completed";
    exact_response_verified: true;
    transaction_count: 1;
    access_receipt_count: 2;
    access_chain_head_sha256: string;
    sdk_frame_count: 2;
    sdk_chain_head_sha256: string;
    payload_marker_absent_from_receipt_files: true;
  };
  timeout: {
    tool_name: "trigger-long-running-operation";
    response_timeout_ms: 100;
    requested_duration_seconds: 2;
    disposition: "tool_failure";
    child_stdin_write_called: true;
    child_signal: "SIGKILL";
    transaction_count: 1;
    access_receipt_count: 2;
    access_chain_head_sha256: string;
    sdk_frame_count: 2;
    sdk_chain_head_sha256: string;
    payload_marker_absent_from_receipt_files: true;
    model_failure_inferred: false;
  };
  ceiling: {
    direct_network_egress_probe_blocked: true;
    routed_stdio_call_observed: true;
    exact_package_bytes_observed: true;
    alternate_process_or_stdio_bypass_blocked: false;
    docker_operator_bypass_possible: true;
    host_non_bypassability_proved: false;
    full_container_process_capture_proved: false;
    file_network_credential_and_side_effect_capture_proved: false;
    arbitrary_mcp_server_compatibility_proved: false;
  };
  claim_boundary: "one_exact_pinned_mcp_stdio_server_inside_one_measured_docker_boundary";
}

export interface ContainerMcpStdioProof extends ContainerMcpStdioProofBody {
  receipt_sha256: string;
}

export interface ContainerMcpStdioProofVerification {
  ok: boolean;
  blockers: readonly string[];
  receipt_sha256: string | null;
}

export function sealContainerMcpStdioProof(
  body: ContainerMcpStdioProofBody,
): ContainerMcpStdioProof {
  validateBody(body);
  const frozen = JSON.parse(canonicalJson(body)) as ContainerMcpStdioProofBody;
  return { ...frozen, receipt_sha256: digestCanonical(frozen) };
}

export function verifyContainerMcpStdioProof(
  value: unknown,
): ContainerMcpStdioProofVerification {
  const blockers: string[] = [];
  let receipt: ContainerMcpStdioProof | null = null;
  try {
    receipt = parseReceipt(value);
  } catch (error) {
    blockers.push(error instanceof Error ? error.message : "container_mcp_stdio_proof_invalid");
  }
  return {
    ok: blockers.length === 0,
    blockers,
    receipt_sha256: blockers.length === 0 ? receipt?.receipt_sha256 ?? null : null,
  };
}

function parseReceipt(value: unknown): ContainerMcpStdioProof {
  if (!record(value)) throw new Error("container_mcp_stdio_proof_shape_invalid");
  exactKeys(value, [
    "ceiling",
    "child",
    "claim_boundary",
    "observed_at",
    "orchestrator",
    "proof_id",
    "receipt_sha256",
    "runtime",
    "schema_version",
    "success",
    "timeout",
  ], "container_mcp_stdio_proof");
  const receipt = value as unknown as ContainerMcpStdioProof;
  const { receipt_sha256: _digest, ...body } = receipt;
  validateBody(body);
  if (!isSha256(receipt.receipt_sha256) || receipt.receipt_sha256 !== digestCanonical(body)) {
    throw new Error("container_mcp_stdio_proof_digest_mismatch");
  }
  return receipt;
}

function validateBody(body: ContainerMcpStdioProofBody): void {
  exactKeys(body as unknown as Record<string, unknown>, [
    "ceiling",
    "child",
    "claim_boundary",
    "observed_at",
    "orchestrator",
    "proof_id",
    "runtime",
    "schema_version",
    "success",
    "timeout",
  ], "container_mcp_stdio_proof_body");
  if (body.schema_version !== CONTAINER_MCP_STDIO_PROOF_SCHEMA_VERSION) throw new Error("container_mcp_stdio_proof_schema_invalid");
  assertStableId(body.proof_id, "container_mcp_stdio_proof_id");
  if (!Number.isFinite(Date.parse(body.observed_at)) || new Date(body.observed_at).toISOString() !== body.observed_at) throw new Error("container_mcp_stdio_proof_timestamp_invalid");
  if (body.orchestrator !== "docker" || body.claim_boundary !== "one_exact_pinned_mcp_stdio_server_inside_one_measured_docker_boundary") throw new Error("container_mcp_stdio_proof_boundary_invalid");
  validateRuntime(body.runtime);
  validateChild(body.child);
  if (body.child.command_path_sha256 !== body.runtime.node_executable_sha256) {
    throw new Error("container_mcp_stdio_node_identity_mismatch");
  }
  validateSuccess(body.success);
  validateTimeout(body.timeout);
  validateCeiling(body.ceiling);
}

function validateRuntime(value: ContainerMcpStdioProofBody["runtime"]): void {
  if (!record(value)) throw new Error("container_mcp_stdio_runtime_shape_invalid");
  exactKeys(value, ["architecture", "cap_drop", "configured_image_sha256", "configured_user", "docker_socket_mounted", "effective_gid", "effective_uid", "image_id_sha256", "network_mode", "no_new_privileges", "node_executable_sha256", "node_version", "platform", "privileged", "provider_credential_names_present", "read_only_root_filesystem", "container_id_sha256"], "container_mcp_stdio_runtime");
  digests([value.container_id_sha256, value.image_id_sha256, value.configured_image_sha256, value.node_executable_sha256]);
  if (value.configured_image_sha256 !== sha256("node:22-alpine")) throw new Error("container_mcp_stdio_image_reference_invalid");
  if (value.platform !== "linux" || typeof value.architecture !== "string" || !/^[a-z0-9_]{2,30}$/.test(value.architecture) || typeof value.node_version !== "string" || !/^v\d+\.\d+\.\d+$/.test(value.node_version)) throw new Error("container_mcp_stdio_runtime_identity_invalid");
  if (value.configured_user !== "65532:65532" || value.effective_uid !== 65532 || value.effective_gid !== 65532 || value.read_only_root_filesystem !== true || value.privileged !== false || canonicalJson(value.cap_drop) !== canonicalJson(["ALL"]) || value.no_new_privileges !== true || value.network_mode !== "none" || value.docker_socket_mounted !== false || canonicalJson(value.provider_credential_names_present) !== "[]") throw new Error("container_mcp_stdio_runtime_posture_invalid");
}

function validateChild(value: ContainerMcpStdioProofBody["child"]): void {
  if (!record(value)) throw new Error("container_mcp_stdio_child_shape_invalid");
  exactKeys(value, ["arguments", "child_launch_declaration_sha256", "command_path", "command_path_sha256", "dependency_lock_sha256", "entrypoint_sha256", "environment", "package_manifest_sha256", "package_name", "package_tree_sha256", "package_version", "resolved_identity_attestation", "shell"], "container_mcp_stdio_child");
  digests([value.package_manifest_sha256, value.package_tree_sha256, value.dependency_lock_sha256, value.entrypoint_sha256, value.command_path_sha256, value.child_launch_declaration_sha256]);
  if (value.package_name !== "@modelcontextprotocol/server-everything" || value.package_version !== "2026.8.31" || value.command_path !== "/usr/local/bin/node" || canonicalJson(value.arguments) !== canonicalJson(["/opt/guard/node_modules/@modelcontextprotocol/server-everything/dist/index.js", "stdio"]) || value.environment !== "empty" || value.shell !== false || value.resolved_identity_attestation !== "configuration_and_bytes_bound_not_running_child_attested") throw new Error("container_mcp_stdio_child_identity_invalid");
  if (value.child_launch_declaration_sha256 !== digestCanonical({ command: value.command_path, args: value.arguments, environment: value.environment, shell: value.shell })) throw new Error("container_mcp_stdio_child_launch_invalid");
}

function validateSuccess(value: ContainerMcpStdioProofBody["success"]): void {
  if (!record(value)) throw new Error("container_mcp_stdio_success_shape_invalid");
  exactKeys(value, ["access_chain_head_sha256", "access_receipt_count", "disposition", "exact_response_verified", "payload_marker_absent_from_receipt_files", "sdk_chain_head_sha256", "sdk_frame_count", "tool_name", "transaction_count"], "container_mcp_stdio_success");
  digests([value.access_chain_head_sha256, value.sdk_chain_head_sha256]);
  if (value.tool_name !== "echo" || value.disposition !== "completed" || value.exact_response_verified !== true || value.transaction_count !== 1 || value.access_receipt_count !== 2 || value.sdk_frame_count !== 2 || value.payload_marker_absent_from_receipt_files !== true) throw new Error("container_mcp_stdio_success_invalid");
}

function validateTimeout(value: ContainerMcpStdioProofBody["timeout"]): void {
  if (!record(value)) throw new Error("container_mcp_stdio_timeout_shape_invalid");
  exactKeys(value, ["access_chain_head_sha256", "access_receipt_count", "child_signal", "child_stdin_write_called", "disposition", "model_failure_inferred", "payload_marker_absent_from_receipt_files", "requested_duration_seconds", "response_timeout_ms", "sdk_chain_head_sha256", "sdk_frame_count", "tool_name", "transaction_count"], "container_mcp_stdio_timeout");
  digests([value.access_chain_head_sha256, value.sdk_chain_head_sha256]);
  if (value.tool_name !== "trigger-long-running-operation" || value.response_timeout_ms !== 100 || value.requested_duration_seconds !== 2 || value.disposition !== "tool_failure" || value.child_stdin_write_called !== true || value.child_signal !== "SIGKILL" || value.transaction_count !== 1 || value.access_receipt_count !== 2 || value.sdk_frame_count !== 2 || value.payload_marker_absent_from_receipt_files !== true || value.model_failure_inferred !== false) throw new Error("container_mcp_stdio_timeout_invalid");
}

function validateCeiling(value: ContainerMcpStdioProofBody["ceiling"]): void {
  if (!record(value)) throw new Error("container_mcp_stdio_ceiling_shape_invalid");
  const expected: ContainerMcpStdioProofBody["ceiling"] = {
    direct_network_egress_probe_blocked: true,
    routed_stdio_call_observed: true,
    exact_package_bytes_observed: true,
    alternate_process_or_stdio_bypass_blocked: false,
    docker_operator_bypass_possible: true,
    host_non_bypassability_proved: false,
    full_container_process_capture_proved: false,
    file_network_credential_and_side_effect_capture_proved: false,
    arbitrary_mcp_server_compatibility_proved: false,
  };
  exactKeys(value, Object.keys(expected), "container_mcp_stdio_ceiling");
  if (canonicalJson(value) !== canonicalJson(expected)) throw new Error("container_mcp_stdio_ceiling_overclaim");
}

function digests(values: readonly unknown[]): void {
  if (values.some((value) => !isSha256(value))) throw new Error("container_mcp_stdio_digest_invalid");
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  if (canonicalJson(Object.keys(value).sort()) !== canonicalJson([...keys].sort())) throw new Error(`${label}_keys_invalid`);
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
