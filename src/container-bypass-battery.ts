import { spawnSync } from "node:child_process";
import { canonicalJson, digestCanonical, isSha256 } from "./canonical.js";
import {
  verifyContainerEnforcementReceipt,
  type ContainerEnforcementReceipt,
} from "./container-enforcement.js";
import { assertStableId } from "./security.js";

export const CONTAINER_BYPASS_BATTERY_SCHEMA_VERSION =
  "gradia.guard.container-bypass-battery-receipt.v1" as const;

export interface ContainerBypassProbeSet {
  alternate_client_raw_tcp_external: "blocked";
  link_local_metadata_raw_tcp: "blocked";
  root_filesystem_write: "blocked";
  writable_tmp_round_trip: "allowed";
  spawned_subprocess_raw_tcp_external: "blocked";
  alternate_client_command_sha256: string;
  link_local_command_sha256: string;
  root_write_command_sha256: string;
  tmp_write_command_sha256: string;
  subprocess_command_sha256: string;
}

export interface ContainerBypassBatteryCoverage {
  alternate_client_egress_bypass_observed: false;
  link_local_metadata_bypass_observed: false;
  root_filesystem_write_bypass_observed: false;
  writable_tmp_available: true;
  subprocess_spawn_possible: true;
  spawned_subprocess_egress_bypass_observed: false;
  complete_bypass_exhaustion: false;
  operator_or_docker_daemon_bypass_possible: true;
  full_host_enforcement: false;
}

export interface ContainerBypassBatteryReceiptBody {
  schema_version: typeof CONTAINER_BYPASS_BATTERY_SCHEMA_VERSION;
  runtime_id: string;
  observed_at: string;
  orchestrator: "docker";
  collector_authority: "docker_daemon_exec_probes";
  container_enforcement_receipt_sha256: string;
  agent_container_id_sha256: string;
  probes: ContainerBypassProbeSet;
  coverage: ContainerBypassBatteryCoverage;
  claim_boundary: "five_observed_docker_agent_probes_not_exhaustive_non_bypassability";
}

export interface ContainerBypassBatteryReceipt extends ContainerBypassBatteryReceiptBody {
  receipt_sha256: string;
}

export interface DockerContainerBypassBatteryOptions {
  agentContainer: string;
  containerEnforcementReceipt: unknown;
  now?: () => Date;
  dockerBinary?: string;
}

const RAW_TCP_EXTERNAL = [
  "node",
  "-e",
  "const n=require('node:net');const s=n.connect({host:'1.1.1.1',port:443});const t=setTimeout(()=>{s.destroy();process.exit(0)},2500);s.on('connect',()=>{clearTimeout(t);s.destroy();process.exit(41)});s.on('error',()=>{clearTimeout(t);process.exit(0)});",
] as const;

const RAW_TCP_LINK_LOCAL = [
  "node",
  "-e",
  "const n=require('node:net');const s=n.connect({host:'169.254.169.254',port:80});const t=setTimeout(()=>{s.destroy();process.exit(0)},2500);s.on('connect',()=>{clearTimeout(t);s.destroy();process.exit(41)});s.on('error',()=>{clearTimeout(t);process.exit(0)});",
] as const;

const ROOT_WRITE = [
  "node",
  "-e",
  "const f=require('node:fs');const p='/gradia-guard-root-write-probe';try{f.writeFileSync(p,'x');try{f.unlinkSync(p)}catch{}process.exit(41)}catch{process.exit(0)}",
] as const;

const TMP_WRITE = [
  "node",
  "-e",
  "const f=require('node:fs');const p='/tmp/gradia-guard-write-probe';try{f.writeFileSync(p,'x',{flag:'wx'});if(f.readFileSync(p,'utf8')!=='x')process.exit(41);f.unlinkSync(p);process.exit(0)}catch{process.exit(41)}",
] as const;

const SUBPROCESS_RAW_TCP = [
  "node",
  "-e",
  "const c=require('node:child_process');const x=\"const n=require('node:net');const s=n.connect({host:'1.1.1.1',port:443});const t=setTimeout(()=>{s.destroy();process.exit(0)},2500);s.on('connect',()=>{clearTimeout(t);s.destroy();process.exit(41)});s.on('error',()=>{clearTimeout(t);process.exit(0)});\";const r=c.spawnSync(process.execPath,['-e',x],{timeout:5000,stdio:'ignore'});process.exit(r.status===0?0:41);",
] as const;

/**
 * Exercise five independent bypass surfaces inside the exact measured agent
 * container. Success means the expected posture was observed at probe time;
 * the resulting receipt deliberately refuses an exhaustive non-bypass claim.
 */
export function collectDockerContainerBypassBattery(
  options: DockerContainerBypassBatteryOptions,
): ContainerBypassBatteryReceipt {
  const container = verifyContainerEnforcementReceipt(options.containerEnforcementReceipt);
  assertStableId(options.agentContainer, "container_bypass_agent_container");
  const docker = options.dockerBinary ?? "docker";
  runExpectedProbe(docker, options.agentContainer, RAW_TCP_EXTERNAL, "alternate_client");
  runExpectedProbe(docker, options.agentContainer, RAW_TCP_LINK_LOCAL, "link_local");
  runExpectedProbe(docker, options.agentContainer, ROOT_WRITE, "root_write");
  runExpectedProbe(docker, options.agentContainer, TMP_WRITE, "tmp_write");
  runExpectedProbe(docker, options.agentContainer, SUBPROCESS_RAW_TCP, "subprocess");
  const body: ContainerBypassBatteryReceiptBody = {
    schema_version: CONTAINER_BYPASS_BATTERY_SCHEMA_VERSION,
    runtime_id: container.runtime_id,
    observed_at: (options.now ?? (() => new Date()))().toISOString(),
    orchestrator: "docker",
    collector_authority: "docker_daemon_exec_probes",
    container_enforcement_receipt_sha256: container.receipt_sha256,
    agent_container_id_sha256: container.agent.container_id_sha256,
    probes: {
      alternate_client_raw_tcp_external: "blocked",
      link_local_metadata_raw_tcp: "blocked",
      root_filesystem_write: "blocked",
      writable_tmp_round_trip: "allowed",
      spawned_subprocess_raw_tcp_external: "blocked",
      alternate_client_command_sha256: digestCanonical(RAW_TCP_EXTERNAL),
      link_local_command_sha256: digestCanonical(RAW_TCP_LINK_LOCAL),
      root_write_command_sha256: digestCanonical(ROOT_WRITE),
      tmp_write_command_sha256: digestCanonical(TMP_WRITE),
      subprocess_command_sha256: digestCanonical(SUBPROCESS_RAW_TCP),
    },
    coverage: containerBypassBatteryCoverage(),
    claim_boundary: "five_observed_docker_agent_probes_not_exhaustive_non_bypassability",
  };
  const receipt = { ...body, receipt_sha256: digestCanonical(body) };
  return verifyContainerBypassBatteryReceipt(receipt, container);
}

export function verifyContainerBypassBatteryReceipt(
  value: unknown,
  containerEnforcementReceipt: unknown,
): ContainerBypassBatteryReceipt {
  const container = verifyContainerEnforcementReceipt(containerEnforcementReceipt);
  if (!record(value)) throw new Error("container_bypass_receipt_shape_invalid");
  exactKeys(
    value,
    [
      "agent_container_id_sha256",
      "claim_boundary",
      "collector_authority",
      "container_enforcement_receipt_sha256",
      "coverage",
      "observed_at",
      "orchestrator",
      "probes",
      "receipt_sha256",
      "runtime_id",
      "schema_version",
    ],
    "container_bypass_receipt",
  );
  const receipt = value as unknown as ContainerBypassBatteryReceipt;
  if (receipt.schema_version !== CONTAINER_BYPASS_BATTERY_SCHEMA_VERSION) {
    throw new Error("container_bypass_schema_invalid");
  }
  assertStableId(receipt.runtime_id, "container_bypass_runtime_id");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(receipt.observed_at)) {
    throw new Error("container_bypass_observed_at_invalid");
  }
  if (
    receipt.orchestrator !== "docker" ||
    receipt.collector_authority !== "docker_daemon_exec_probes"
  ) {
    throw new Error("container_bypass_collector_invalid");
  }
  if (
    receipt.runtime_id !== container.runtime_id ||
    receipt.container_enforcement_receipt_sha256 !== container.receipt_sha256 ||
    receipt.agent_container_id_sha256 !== container.agent.container_id_sha256
  ) {
    throw new Error("container_bypass_enforcement_binding_mismatch");
  }
  if (!record(receipt.probes)) throw new Error("container_bypass_probes_shape_invalid");
  const expectedProbes: ContainerBypassProbeSet = {
    alternate_client_raw_tcp_external: "blocked",
    link_local_metadata_raw_tcp: "blocked",
    root_filesystem_write: "blocked",
    writable_tmp_round_trip: "allowed",
    spawned_subprocess_raw_tcp_external: "blocked",
    alternate_client_command_sha256: digestCanonical(RAW_TCP_EXTERNAL),
    link_local_command_sha256: digestCanonical(RAW_TCP_LINK_LOCAL),
    root_write_command_sha256: digestCanonical(ROOT_WRITE),
    tmp_write_command_sha256: digestCanonical(TMP_WRITE),
    subprocess_command_sha256: digestCanonical(SUBPROCESS_RAW_TCP),
  };
  exactKeys(receipt.probes, Object.keys(expectedProbes), "container_bypass_probes");
  if (canonicalJson(receipt.probes) !== canonicalJson(expectedProbes)) {
    throw new Error("container_bypass_probe_claim_invalid");
  }
  if (!record(receipt.coverage)) throw new Error("container_bypass_coverage_shape_invalid");
  const expectedCoverage = containerBypassBatteryCoverage();
  exactKeys(receipt.coverage, Object.keys(expectedCoverage), "container_bypass_coverage");
  if (canonicalJson(receipt.coverage) !== canonicalJson(expectedCoverage)) {
    throw new Error("container_bypass_coverage_overclaim");
  }
  if (
    receipt.claim_boundary !==
    "five_observed_docker_agent_probes_not_exhaustive_non_bypassability"
  ) {
    throw new Error("container_bypass_claim_boundary_invalid");
  }
  for (const digest of [
    receipt.container_enforcement_receipt_sha256,
    receipt.agent_container_id_sha256,
    receipt.receipt_sha256,
  ]) {
    if (!isSha256(digest)) throw new Error("container_bypass_digest_invalid");
  }
  const { receipt_sha256: _digest, ...body } = receipt;
  if (receipt.receipt_sha256 !== digestCanonical(body)) {
    throw new Error("container_bypass_receipt_digest_mismatch");
  }
  return receipt;
}

function runExpectedProbe(
  docker: string,
  agentContainer: string,
  command: readonly string[],
  label: string,
): void {
  const result = spawnSync(docker, ["exec", agentContainer, ...command], {
    encoding: "utf8",
    stdio: "ignore",
    timeout: 10_000,
  });
  if (result.error || result.status === null) {
    throw new Error(`container_bypass_${label}_probe_unavailable`);
  }
  if (result.status !== 0) throw new Error(`container_bypass_${label}_probe_failed`);
}

function containerBypassBatteryCoverage(): ContainerBypassBatteryCoverage {
  return Object.freeze({
    alternate_client_egress_bypass_observed: false,
    link_local_metadata_bypass_observed: false,
    root_filesystem_write_bypass_observed: false,
    writable_tmp_available: true,
    subprocess_spawn_possible: true,
    spawned_subprocess_egress_bypass_observed: false,
    complete_bypass_exhaustion: false,
    operator_or_docker_daemon_bypass_possible: true,
    full_host_enforcement: false,
  });
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  if (canonicalJson(Object.keys(value).sort()) !== canonicalJson([...expected].sort())) {
    throw new Error(`${label}_keys_invalid`);
  }
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
