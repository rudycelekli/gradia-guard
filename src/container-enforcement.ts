import { execFileSync, spawnSync } from "node:child_process";
import { canonicalJson, digestCanonical, isSha256, sha256 } from "./canonical.js";
import { assertStableId } from "./security.js";

export const CONTAINER_ENFORCEMENT_SCHEMA_VERSION =
  "gradia.guard.container-enforcement-receipt.v1" as const;

const PROVIDER_CREDENTIAL_NAMES = new Set([
  "ANTHROPIC_API_KEY",
  "GEMINI_API_KEY",
  "GOOGLE_API_KEY",
  "OPENAI_API_KEY",
  "XAI_API_KEY",
]);

export interface ContainerSecurityPosture {
  container_id_sha256: string;
  image_id_sha256: string;
  configured_image_sha256: string;
  user: string;
  non_root_user: true;
  read_only_rootfs: true;
  privileged: false;
  cap_drop_all: true;
  no_new_privileges: true;
  host_network: false;
  host_pid: false;
  docker_socket_mounted: false;
  provider_credential_names_present: readonly string[];
  network_id_sha256s: readonly string[];
}

export interface ContainerNetworkEnforcement {
  internal_network_id_sha256: string;
  internal_network_flag: true;
  agent_network_count: 1;
  gateway_network_count: number;
  gateway_dual_homed: true;
  direct_egress_probe: "blocked";
  gateway_reachability_probe: "allowed";
  direct_probe_command_sha256: string;
  gateway_probe_command_sha256: string;
}

export interface ContainerEnforcementCoverage {
  model_network_egress_enforced: true;
  provider_credentials_withheld_from_agent: true;
  agent_root_filesystem_read_only: true;
  unprivileged_workload: true;
  workload_network_bypass_possible: false;
  operator_or_docker_daemon_bypass_possible: true;
  process_spawn_capture_complete: false;
  file_read_capture_complete: false;
  side_effect_capture_complete: false;
  full_world_state_capture: false;
  full_host_enforcement: false;
}

export interface ContainerEnforcementReceiptBody {
  schema_version: typeof CONTAINER_ENFORCEMENT_SCHEMA_VERSION;
  runtime_id: string;
  observed_at: string;
  orchestrator: "docker";
  collector_authority: "docker_daemon_inspection_and_root_launched_probes";
  policy_sha256: string;
  configuration_sha256: string;
  workload_identity_sha256: string;
  agent: ContainerSecurityPosture;
  gateway: ContainerSecurityPosture;
  network: ContainerNetworkEnforcement;
  coverage: ContainerEnforcementCoverage;
}

export interface ContainerEnforcementReceipt extends ContainerEnforcementReceiptBody {
  receipt_sha256: string;
}

export interface DockerContainerEnforcementOptions {
  runtimeId: string;
  agentContainer: string;
  gatewayContainer: string;
  internalNetwork: string;
  policySha256: string;
  configurationSha256: string;
  workloadIdentitySha256: string;
  directEgressProbeCommand: readonly string[];
  gatewayProbeCommand: readonly string[];
  now?: () => Date;
  dockerBinary?: string;
}

interface DockerInspect {
  Id: string;
  Image: string;
  Config: { Image: string; User: string; Env: string[] | null };
  HostConfig: {
    ReadonlyRootfs: boolean;
    Privileged: boolean;
    CapDrop: string[] | null;
    SecurityOpt: string[] | null;
    NetworkMode: string;
    PidMode: string;
  };
  Mounts: { Source: string; Destination: string; Type: string }[];
  NetworkSettings: { Networks: Record<string, { NetworkID: string }> };
}

interface DockerNetworkInspect {
  Id: string;
  Internal: boolean;
}

/**
 * Inspect a running two-container boundary and execute probes from the agent.
 *
 * This proves the model/network/credential subset only.  The receipt keeps
 * process, file-read, side-effect, host, and full-world coverage false rather
 * than allowing a secure network namespace to inflate the rest of G3/G4.
 */
export function collectDockerContainerEnforcement(
  options: DockerContainerEnforcementOptions,
): ContainerEnforcementReceipt {
  const docker = options.dockerBinary ?? "docker";
  assertStableId(options.runtimeId, "container_runtime_id");
  for (const [label, value] of [
    ["policy", options.policySha256],
    ["configuration", options.configurationSha256],
    ["workload_identity", options.workloadIdentitySha256],
  ] as const) {
    if (!isSha256(value)) throw new Error(`container_enforcement_${label}_digest_invalid`);
  }
  assertProbeCommand(options.directEgressProbeCommand, "direct");
  assertProbeCommand(options.gatewayProbeCommand, "gateway");
  const agent = dockerInspect(docker, options.agentContainer);
  const gateway = dockerInspect(docker, options.gatewayContainer);
  const internal = dockerNetworkInspect(docker, options.internalNetwork);
  const agentPosture = securityPosture(agent);
  const gatewayPosture = securityPosture(gateway);
  const internalIdSha256 = sha256(Buffer.from(internal.Id));
  const agentNetworks = agentPosture.network_id_sha256s;
  const gatewayNetworks = gatewayPosture.network_id_sha256s;
  if (!internal.Internal) throw new Error("container_enforcement_network_not_internal");
  if (canonicalJson(agentNetworks) !== canonicalJson([internalIdSha256])) {
    throw new Error("container_enforcement_agent_not_internal_only");
  }
  if (!gatewayNetworks.includes(internalIdSha256) || gatewayNetworks.length < 2) {
    throw new Error("container_enforcement_gateway_not_dual_homed");
  }
  if (agentPosture.provider_credential_names_present.length > 0) {
    throw new Error("container_enforcement_agent_provider_credential_present");
  }
  const direct = spawnSync(docker, ["exec", options.agentContainer, ...options.directEgressProbeCommand], {
    encoding: "utf8",
    stdio: "ignore",
    timeout: 20_000,
  });
  if (direct.error) throw new Error("container_enforcement_direct_probe_unavailable");
  if (direct.status !== 0) throw new Error("container_enforcement_direct_egress_not_blocked");
  const gatewayProbe = spawnSync(
    docker,
    ["exec", options.agentContainer, ...options.gatewayProbeCommand],
    { encoding: "utf8", stdio: "ignore", timeout: 20_000 },
  );
  if (gatewayProbe.error || gatewayProbe.status !== 0) {
    throw new Error("container_enforcement_gateway_not_reachable");
  }
  const body: ContainerEnforcementReceiptBody = {
    schema_version: CONTAINER_ENFORCEMENT_SCHEMA_VERSION,
    runtime_id: options.runtimeId,
    observed_at: (options.now ?? (() => new Date()))().toISOString(),
    orchestrator: "docker",
    collector_authority: "docker_daemon_inspection_and_root_launched_probes",
    policy_sha256: options.policySha256,
    configuration_sha256: options.configurationSha256,
    workload_identity_sha256: options.workloadIdentitySha256,
    agent: agentPosture,
    gateway: gatewayPosture,
    network: {
      internal_network_id_sha256: internalIdSha256,
      internal_network_flag: true,
      agent_network_count: 1,
      gateway_network_count: gatewayNetworks.length,
      gateway_dual_homed: true,
      direct_egress_probe: "blocked",
      gateway_reachability_probe: "allowed",
      direct_probe_command_sha256: digestCanonical(options.directEgressProbeCommand),
      gateway_probe_command_sha256: digestCanonical(options.gatewayProbeCommand),
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
  const receipt = { ...body, receipt_sha256: digestCanonical(body) };
  verifyContainerEnforcementReceipt(receipt);
  return receipt;
}

export function verifyContainerEnforcementReceipt(value: unknown): ContainerEnforcementReceipt {
  if (!isRecord(value)) throw new Error("container_enforcement_receipt_shape_invalid");
  assertExactKeys(
    value,
    [
      "agent",
      "collector_authority",
      "configuration_sha256",
      "coverage",
      "gateway",
      "network",
      "observed_at",
      "orchestrator",
      "policy_sha256",
      "receipt_sha256",
      "runtime_id",
      "schema_version",
      "workload_identity_sha256",
    ],
    "container_enforcement_receipt",
  );
  const receipt = value as unknown as ContainerEnforcementReceipt;
  if (receipt.schema_version !== CONTAINER_ENFORCEMENT_SCHEMA_VERSION) {
    throw new Error("container_enforcement_schema_invalid");
  }
  assertStableId(receipt.runtime_id, "container_runtime_id");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(receipt.observed_at)) {
    throw new Error("container_enforcement_observed_at_invalid");
  }
  if (
    receipt.orchestrator !== "docker" ||
    receipt.collector_authority !== "docker_daemon_inspection_and_root_launched_probes"
  ) {
    throw new Error("container_enforcement_collector_invalid");
  }
  for (const digest of [
    receipt.policy_sha256,
    receipt.configuration_sha256,
    receipt.workload_identity_sha256,
    receipt.receipt_sha256,
  ]) {
    if (!isSha256(digest)) throw new Error("container_enforcement_bound_digest_invalid");
  }
  verifySecurityPosture(receipt.agent, true);
  verifySecurityPosture(receipt.gateway, false);
  assertExactKeys(
    receipt.network as unknown as Record<string, unknown>,
    [
      "agent_network_count",
      "direct_egress_probe",
      "direct_probe_command_sha256",
      "gateway_dual_homed",
      "gateway_network_count",
      "gateway_probe_command_sha256",
      "gateway_reachability_probe",
      "internal_network_flag",
      "internal_network_id_sha256",
    ],
    "container_enforcement_network",
  );
  if (
    receipt.network.internal_network_flag !== true ||
    receipt.network.agent_network_count !== 1 ||
    receipt.network.gateway_network_count < 2 ||
    receipt.network.gateway_dual_homed !== true ||
    receipt.network.direct_egress_probe !== "blocked" ||
    receipt.network.gateway_reachability_probe !== "allowed"
  ) {
    throw new Error("container_enforcement_network_claim_invalid");
  }
  for (const digest of [
    receipt.network.internal_network_id_sha256,
    receipt.network.direct_probe_command_sha256,
    receipt.network.gateway_probe_command_sha256,
  ]) {
    if (!isSha256(digest)) throw new Error("container_enforcement_network_digest_invalid");
  }
  assertExactKeys(
    receipt.coverage as unknown as Record<string, unknown>,
    [
      "agent_root_filesystem_read_only",
      "file_read_capture_complete",
      "full_host_enforcement",
      "full_world_state_capture",
      "model_network_egress_enforced",
      "operator_or_docker_daemon_bypass_possible",
      "process_spawn_capture_complete",
      "provider_credentials_withheld_from_agent",
      "side_effect_capture_complete",
      "unprivileged_workload",
      "workload_network_bypass_possible",
    ],
    "container_enforcement_coverage",
  );
  if (
    receipt.coverage.model_network_egress_enforced !== true ||
    receipt.coverage.provider_credentials_withheld_from_agent !== true ||
    receipt.coverage.agent_root_filesystem_read_only !== true ||
    receipt.coverage.unprivileged_workload !== true ||
    receipt.coverage.workload_network_bypass_possible !== false ||
    receipt.coverage.operator_or_docker_daemon_bypass_possible !== true ||
    receipt.coverage.process_spawn_capture_complete !== false ||
    receipt.coverage.file_read_capture_complete !== false ||
    receipt.coverage.side_effect_capture_complete !== false ||
    receipt.coverage.full_world_state_capture !== false ||
    receipt.coverage.full_host_enforcement !== false
  ) {
    throw new Error("container_enforcement_coverage_overclaim");
  }
  const { receipt_sha256: _digest, ...body } = receipt;
  if (receipt.receipt_sha256 !== digestCanonical(body)) {
    throw new Error("container_enforcement_receipt_digest_mismatch");
  }
  return receipt;
}

function dockerInspect(docker: string, container: string): DockerInspect {
  const parsed = JSON.parse(
    execFileSync(docker, ["inspect", "--type", "container", container], {
      encoding: "utf8",
      maxBuffer: 8 * 1024 * 1024,
    }),
  ) as unknown;
  if (!Array.isArray(parsed) || parsed.length !== 1 || !isRecord(parsed[0])) {
    throw new Error("container_enforcement_docker_inspect_invalid");
  }
  return parsed[0] as unknown as DockerInspect;
}

function dockerNetworkInspect(docker: string, network: string): DockerNetworkInspect {
  const parsed = JSON.parse(
    execFileSync(docker, ["network", "inspect", network], {
      encoding: "utf8",
      maxBuffer: 8 * 1024 * 1024,
    }),
  ) as unknown;
  if (!Array.isArray(parsed) || parsed.length !== 1 || !isRecord(parsed[0])) {
    throw new Error("container_enforcement_network_inspect_invalid");
  }
  return parsed[0] as unknown as DockerNetworkInspect;
}

function securityPosture(value: DockerInspect): ContainerSecurityPosture {
  if (!value.Id || !value.Image || !value.Config?.Image) {
    throw new Error("container_enforcement_identity_missing");
  }
  const networks = Object.values(value.NetworkSettings?.Networks ?? {})
    .map((network) => sha256(Buffer.from(network.NetworkID)))
    .sort();
  const environmentNames = (value.Config.Env ?? [])
    .map((entry) => entry.slice(0, Math.max(0, entry.indexOf("="))))
    .filter((name) => PROVIDER_CREDENTIAL_NAMES.has(name))
    .sort();
  const mounts = value.Mounts ?? [];
  const dockerSocketMounted = mounts.some(
    (mount) =>
      mount.Source === "/var/run/docker.sock" || mount.Destination === "/var/run/docker.sock",
  );
  const posture = {
    container_id_sha256: sha256(Buffer.from(value.Id)),
    image_id_sha256: sha256(Buffer.from(value.Image)),
    configured_image_sha256: sha256(Buffer.from(value.Config.Image)),
    user: value.Config.User,
    non_root_user: value.Config.User !== "" && value.Config.User !== "0" && value.Config.User !== "root",
    read_only_rootfs: value.HostConfig.ReadonlyRootfs,
    privileged: value.HostConfig.Privileged,
    cap_drop_all: (value.HostConfig.CapDrop ?? []).map((item) => item.toUpperCase()).includes("ALL"),
    no_new_privileges: (value.HostConfig.SecurityOpt ?? []).some((item) =>
      item.toLowerCase().startsWith("no-new-privileges"),
    ),
    host_network: value.HostConfig.NetworkMode === "host",
    host_pid: value.HostConfig.PidMode === "host",
    docker_socket_mounted: dockerSocketMounted,
    provider_credential_names_present: environmentNames,
    network_id_sha256s: networks,
  };
  verifySecurityPosture(posture as ContainerSecurityPosture, false);
  return posture as ContainerSecurityPosture;
}

function verifySecurityPosture(value: ContainerSecurityPosture, requireNoCredentials: boolean): void {
  if (!isRecord(value)) throw new Error("container_enforcement_security_shape_invalid");
  assertExactKeys(
    value,
    [
      "cap_drop_all",
      "configured_image_sha256",
      "container_id_sha256",
      "docker_socket_mounted",
      "host_network",
      "host_pid",
      "image_id_sha256",
      "network_id_sha256s",
      "no_new_privileges",
      "non_root_user",
      "privileged",
      "provider_credential_names_present",
      "read_only_rootfs",
      "user",
    ],
    "container_enforcement_security",
  );
  if (
    value.non_root_user !== true ||
    value.read_only_rootfs !== true ||
    value.privileged !== false ||
    value.cap_drop_all !== true ||
    value.no_new_privileges !== true ||
    value.host_network !== false ||
    value.host_pid !== false ||
    value.docker_socket_mounted !== false
  ) {
    throw new Error("container_enforcement_security_posture_invalid");
  }
  for (const digest of [
    value.container_id_sha256,
    value.image_id_sha256,
    value.configured_image_sha256,
    ...value.network_id_sha256s,
  ]) {
    if (!isSha256(digest)) throw new Error("container_enforcement_security_digest_invalid");
  }
  if (
    !Array.isArray(value.provider_credential_names_present) ||
    !value.provider_credential_names_present.every((name) => PROVIDER_CREDENTIAL_NAMES.has(name))
  ) {
    throw new Error("container_enforcement_credential_names_invalid");
  }
  if (requireNoCredentials && value.provider_credential_names_present.length > 0) {
    throw new Error("container_enforcement_agent_provider_credential_present");
  }
}

function assertProbeCommand(value: readonly string[], label: string): void {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    !value.every((part) => typeof part === "string" && part.length > 0 && part.length <= 8_192)
  ) {
    throw new Error(`container_enforcement_${label}_probe_command_invalid`);
  }
}

function assertExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (canonicalJson(actual) !== canonicalJson(wanted)) {
    throw new Error(`${label}_keys_invalid`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
