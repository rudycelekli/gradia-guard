import assert from "node:assert/strict";
import test from "node:test";
import { digestCanonical } from "../src/canonical.js";
import {
  CONTAINER_ENFORCEMENT_SCHEMA_VERSION,
  verifyContainerEnforcementReceipt,
  type ContainerEnforcementReceiptBody,
  type ContainerSecurityPosture,
} from "../src/container-enforcement.js";

function posture(networks: readonly string[], credentials: readonly string[] = []): ContainerSecurityPosture {
  return {
    container_id_sha256: "1".repeat(64),
    image_id_sha256: "2".repeat(64),
    configured_image_sha256: "3".repeat(64),
    user: "65532:65532",
    non_root_user: true,
    read_only_rootfs: true,
    privileged: false,
    cap_drop_all: true,
    no_new_privileges: true,
    host_network: false,
    host_pid: false,
    docker_socket_mounted: false,
    provider_credential_names_present: credentials,
    network_id_sha256s: networks,
  };
}

function receipt(): Record<string, unknown> {
  const internal = "4".repeat(64);
  const body: ContainerEnforcementReceiptBody = {
    schema_version: CONTAINER_ENFORCEMENT_SCHEMA_VERSION,
    runtime_id: "runtime-01",
    observed_at: "2026-08-26T20:00:00.000Z",
    orchestrator: "docker",
    collector_authority: "docker_daemon_inspection_and_root_launched_probes",
    policy_sha256: "5".repeat(64),
    configuration_sha256: "6".repeat(64),
    workload_identity_sha256: "7".repeat(64),
    agent: posture([internal]),
    gateway: posture([internal, "8".repeat(64)], ["OPENAI_API_KEY"]),
    network: {
      internal_network_id_sha256: internal,
      internal_network_flag: true,
      agent_network_count: 1,
      gateway_network_count: 2,
      gateway_dual_homed: true,
      direct_egress_probe: "blocked",
      gateway_reachability_probe: "allowed",
      direct_probe_command_sha256: "9".repeat(64),
      gateway_probe_command_sha256: "a".repeat(64),
    },
    coverage: {
      model_network_egress_enforced: true,
      provider_credentials_withheld_from_agent: true,
      agent_root_filesystem_read_only: true,
      unprivileged_workload: true,
      workload_network_bypass_possible: false,
      operator_or_docker_daemon_bypass_possible: true,
      process_spawn_capture_complete: false,
      file_read_capture_complete: false,
      side_effect_capture_complete: false,
      full_world_state_capture: false,
      full_host_enforcement: false,
    },
  };
  return { ...body, receipt_sha256: digestCanonical(body) };
}

test("container receipt admits only the proved network and credential boundary", () => {
  const verified = verifyContainerEnforcementReceipt(receipt());
  assert.equal(verified.coverage.model_network_egress_enforced, true);
  assert.equal(verified.coverage.workload_network_bypass_possible, false);
  assert.equal(verified.coverage.full_host_enforcement, false);
  assert.equal(verified.coverage.file_read_capture_complete, false);
});

test("container receipt refuses overclaim, agent credentials, and rehashed weak posture", () => {
  const overclaim = receipt();
  (overclaim["coverage"] as Record<string, unknown>)["full_host_enforcement"] = true;
  const { receipt_sha256: _old, ...overclaimBody } = overclaim;
  overclaim["receipt_sha256"] = digestCanonical(overclaimBody);
  assert.throws(
    () => verifyContainerEnforcementReceipt(overclaim),
    /container_enforcement_coverage_overclaim/,
  );

  const credential = receipt();
  (credential["agent"] as Record<string, unknown>)["provider_credential_names_present"] = [
    "ANTHROPIC_API_KEY",
  ];
  const { receipt_sha256: _credentialDigest, ...credentialBody } = credential;
  credential["receipt_sha256"] = digestCanonical(credentialBody);
  assert.throws(
    () => verifyContainerEnforcementReceipt(credential),
    /container_enforcement_agent_provider_credential_present/,
  );

  const weak = receipt();
  (weak["agent"] as Record<string, unknown>)["read_only_rootfs"] = false;
  const { receipt_sha256: _weakDigest, ...weakBody } = weak;
  weak["receipt_sha256"] = digestCanonical(weakBody);
  assert.throws(
    () => verifyContainerEnforcementReceipt(weak),
    /container_enforcement_security_posture_invalid/,
  );
});
