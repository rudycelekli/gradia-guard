import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import {
  digestCanonical,
  sha256,
  sealContainerMcpStdioProof,
  verifyContainerMcpStdioProof,
  verifyMcpStdioAccessBundleDirectory,
  verifySdkBundle,
  type ContainerMcpStdioProofBody,
} from "../src/index.js";

const hash = (character: string): string => character.repeat(64);

function body(): ContainerMcpStdioProofBody {
  return {
    schema_version: "gradia.guard.container-mcp-stdio-proof.v1",
    proof_id: "mcp-stdio-0123456789abcdef01234567",
    observed_at: "2026-09-03T12:00:00.000Z",
    orchestrator: "docker",
    runtime: {
      container_id_sha256: hash("1"),
      image_id_sha256: hash("2"),
      configured_image_sha256: sha256("node:22-alpine"),
      platform: "linux",
      architecture: "arm64",
      node_version: "v22.19.0",
      node_executable_sha256: hash("4"),
      configured_user: "65532:65532",
      effective_uid: 65532,
      effective_gid: 65532,
      read_only_root_filesystem: true,
      privileged: false,
      cap_drop: ["ALL"],
      no_new_privileges: true,
      network_mode: "none",
      docker_socket_mounted: false,
      provider_credential_names_present: [],
    },
    child: {
      package_name: "@modelcontextprotocol/server-everything",
      package_version: "2026.8.31",
      package_manifest_sha256: hash("5"),
      package_tree_sha256: hash("d"),
      dependency_lock_sha256: hash("e"),
      entrypoint_sha256: hash("6"),
      command_path: "/usr/local/bin/node",
      command_path_sha256: hash("4"),
      arguments: [
        "/opt/guard/node_modules/@modelcontextprotocol/server-everything/dist/index.js",
        "stdio",
      ],
      environment: "empty",
      shell: false,
      child_launch_declaration_sha256: digestCanonical({
        command: "/usr/local/bin/node",
        args: [
          "/opt/guard/node_modules/@modelcontextprotocol/server-everything/dist/index.js",
          "stdio",
        ],
        environment: "empty",
        shell: false,
      }),
      resolved_identity_attestation: "configuration_and_bytes_bound_not_running_child_attested",
    },
    success: {
      tool_name: "echo",
      disposition: "completed",
      exact_response_verified: true,
      transaction_count: 1,
      access_receipt_count: 2,
      access_chain_head_sha256: hash("8"),
      sdk_frame_count: 2,
      sdk_chain_head_sha256: hash("9"),
      payload_marker_absent_from_receipt_files: true,
    },
    timeout: {
      tool_name: "trigger-long-running-operation",
      response_timeout_ms: 100,
      requested_duration_seconds: 2,
      disposition: "tool_failure",
      child_stdin_write_called: true,
      child_signal: "SIGKILL",
      transaction_count: 1,
      access_receipt_count: 2,
      access_chain_head_sha256: hash("a"),
      sdk_frame_count: 2,
      sdk_chain_head_sha256: hash("b"),
      payload_marker_absent_from_receipt_files: true,
      model_failure_inferred: false,
    },
    ceiling: {
      direct_network_egress_probe_blocked: true,
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
}

test("container MCP stdio proof verifies the exact narrow cell", () => {
  const receipt = sealContainerMcpStdioProof(body());
  const verification = verifyContainerMcpStdioProof(receipt);
  assert.equal(verification.ok, true, verification.blockers.join(","));
  assert.equal(verification.receipt_sha256, receipt.receipt_sha256);
});

test("container MCP stdio proof rejects semantic forgeries even after digest recomputation", () => {
  for (const mutate of [
    (candidate: Record<string, any>) => { candidate["child"].package_version = "2026.9.1"; },
    (candidate: Record<string, any>) => { candidate["ceiling"].alternate_process_or_stdio_bypass_blocked = true; },
    (candidate: Record<string, any>) => { candidate["timeout"].model_failure_inferred = true; },
    (candidate: Record<string, any>) => { candidate["child"].command_path_sha256 = hash("c"); },
  ]) {
    const candidate = structuredClone(sealContainerMcpStdioProof(body())) as Record<string, any>;
    mutate(candidate);
    const { receipt_sha256: _digest, ...candidateBody } = candidate;
    candidate["receipt_sha256"] = digestCanonical(candidateBody);
    assert.equal(verifyContainerMcpStdioProof(candidate).ok, false);
  }
});

test("container MCP stdio proof rejects undeclared fields and digest drift", () => {
  const extra = structuredClone(sealContainerMcpStdioProof(body())) as unknown as Record<string, unknown>;
  extra["marketing_claim"] = "non-bypassable";
  assert.equal(verifyContainerMcpStdioProof(extra).ok, false);
  const drift = structuredClone(sealContainerMcpStdioProof(body()));
  drift.receipt_sha256 = hash("f");
  assert.equal(verifyContainerMcpStdioProof(drift).ok, false);
});

test("checked live Docker proof keeps both payload-free evidence chains independently verifiable", () => {
  const directory = join(
    process.cwd(),
    "test",
    "fixtures",
    "container-mcp-stdio",
    "live-docker-proof",
  );
  const receipt = JSON.parse(readFileSync(join(directory, "receipt.json"), "utf8"));
  const proof = verifyContainerMcpStdioProof(receipt);
  assert.equal(proof.ok, true, proof.blockers.join(","));
  for (const cell of ["success", "timeout"] as const) {
    const access = verifyMcpStdioAccessBundleDirectory(
      join(directory, cell, "mcp-stdio-access"),
    );
    const sdk = verifySdkBundle(join(directory, cell, "mcp-evidence"));
    assert.equal(access.ok, true, access.blockers.join(","));
    assert.equal(sdk.ok, true, sdk.blockers.join(","));
    assert.equal(access.receipt_count, receipt[cell].access_receipt_count);
    assert.equal(access.chain_head_sha256, receipt[cell].access_chain_head_sha256);
    assert.equal(sdk.frame_count, receipt[cell].sdk_frame_count);
    assert.equal(sdk.chain_head_sha256, receipt[cell].sdk_chain_head_sha256);
  }
});
