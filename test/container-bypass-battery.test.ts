import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { digestCanonical } from "../src/canonical.js";
import {
  collectDockerContainerBypassBattery,
  verifyContainerBypassBatteryReceipt,
} from "../src/container-bypass-battery.js";
import {
  CONTAINER_ENFORCEMENT_SCHEMA_VERSION,
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

function containerReceipt(): Record<string, unknown> {
  const internal = "4".repeat(64);
  const body: ContainerEnforcementReceiptBody = {
    schema_version: CONTAINER_ENFORCEMENT_SCHEMA_VERSION,
    runtime_id: "runtime-bypass-01",
    observed_at: "2026-08-27T20:00:00.000Z",
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

function fakeDocker(exitCode: number): string {
  const directory = mkdtempSync(join(tmpdir(), "gradia-bypass-docker-"));
  const executable = join(directory, "docker");
  writeFileSync(executable, `#!/bin/sh\nexit ${exitCode}\n`, { mode: 0o700 });
  chmodSync(executable, 0o700);
  return executable;
}

test("Docker bypass battery binds five passing probes to the measured container", () => {
  const container = containerReceipt();
  const receipt = collectDockerContainerBypassBattery({
    agentContainer: "agent-proof",
    containerEnforcementReceipt: container,
    dockerBinary: fakeDocker(0),
    now: () => new Date("2026-08-27T21:00:00.000Z"),
  });
  const verified = verifyContainerBypassBatteryReceipt(receipt, container);
  assert.equal(verified.probes.alternate_client_raw_tcp_external, "blocked");
  assert.equal(verified.probes.link_local_metadata_raw_tcp, "blocked");
  assert.equal(verified.probes.root_filesystem_write, "blocked");
  assert.equal(verified.probes.writable_tmp_round_trip, "allowed");
  assert.equal(verified.probes.spawned_subprocess_raw_tcp_external, "blocked");
  assert.equal(verified.coverage.complete_bypass_exhaustion, false);
  assert.equal(verified.coverage.operator_or_docker_daemon_bypass_possible, true);
});

test("Docker bypass battery refuses failed probes and rehashed overclaims", () => {
  const container = containerReceipt();
  assert.throws(
    () =>
      collectDockerContainerBypassBattery({
        agentContainer: "agent-proof",
        containerEnforcementReceipt: container,
        dockerBinary: fakeDocker(41),
      }),
    /container_bypass_alternate_client_probe_failed/,
  );

  const valid = structuredClone(
    collectDockerContainerBypassBattery({
      agentContainer: "agent-proof",
      containerEnforcementReceipt: container,
      dockerBinary: fakeDocker(0),
    }),
  ) as unknown as Record<string, unknown>;
  const coverage = valid["coverage"] as Record<string, unknown>;
  coverage["complete_bypass_exhaustion"] = true;
  const { receipt_sha256: _oldDigest, ...body } = valid;
  valid["receipt_sha256"] = digestCanonical(body);
  assert.throws(
    () => verifyContainerBypassBatteryReceipt(valid, container),
    /container_bypass_coverage_overclaim/,
  );
});

test("checked-in live Docker receipts replay independently", () => {
  const fixtureRoot = join(process.cwd(), "test/fixtures/container-enforcement");
  const container = JSON.parse(
    readFileSync(join(fixtureRoot, "live-docker-container-receipt.json"), "utf8"),
  ) as unknown;
  const bypass = JSON.parse(
    readFileSync(join(fixtureRoot, "live-docker-bypass-battery.json"), "utf8"),
  ) as unknown;
  const verified = verifyContainerBypassBatteryReceipt(bypass, container);
  assert.equal(
    verified.receipt_sha256,
    "f293fd478081d5236e88ee3af0b5327bda9eac7c857ccd4b4a6545f4922c0f99",
  );
});
