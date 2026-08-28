import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalJson, digestCanonical, isSha256 } from "./canonical.js";
import {
  frameworkSdkCompatibilityCatalog,
  type FrameworkSdkCompatibilityEntry,
} from "./framework-sdk-compatibility.js";
import { verifyGatewayBundle } from "./gateway-verify.js";
import { assertStableId } from "./security.js";

export const KUBERNETES_ENFORCEMENT_SCHEMA_VERSION =
  "gradia.guard.kubernetes-enforcement-receipt.v1" as const;

export type KubernetesProofFramework = "vercel_ai_sdk" | "langchain";
export type KubernetesProofProvider = "anthropic" | "gemini" | "openai" | "xai";

export interface KubernetesWorkloadPosture {
  deployment_uid_sha256: string;
  pod_uid_sha256: string;
  configured_image_sha256: string;
  running_image_id_sha256: string;
  service_account_name: string;
  automount_service_account_token: false;
  host_network: false;
  host_pid: false;
  host_ipc: false;
  run_as_non_root: true;
  run_as_user: 65532;
  seccomp_profile: "RuntimeDefault";
  allow_privilege_escalation: false;
  privileged: false;
  read_only_root_filesystem: true;
  cap_drop_all: true;
  provider_credential_names_present: readonly string[];
}

export interface KubernetesClusterObservation {
  cluster_provisioner: "kind/v0.33.0";
  kind_node_image_sha256: string;
  kubernetes_git_version: string;
  server_platform: string;
  node_count: number;
  node_uid_sha256s: readonly string[];
  container_runtime_versions: readonly string[];
  namespace_uid_sha256: string;
  namespace_pod_security_enforce: "restricted";
  network_policy_engine_image_id_sha256: string;
  network_policy_engine_ready: true;
}

export interface KubernetesRestartObservation {
  before_pod_uid_sha256: string;
  after_pod_uid_sha256: string;
  replacement_observed: true;
}

export interface KubernetesProjectedIdentityObservation {
  token_sha256: string;
  subject: string;
  audiences: readonly ["gradia-guard-workload-identity"];
  issued_at_unix: number;
  expires_at_unix: number;
  lifetime_seconds: 600;
}

export interface KubernetesAdmissionObservation {
  policy_uid_sha256: string;
  binding_uid_sha256: string;
  failure_policy: "Fail";
  validation_actions: readonly ["Audit", "Deny"];
  type_check_warnings: 0;
  unpinned_image_rejected_by_exact_policy: true;
  writable_root_rejected_by_exact_policy: true;
  agent_provider_credential_rejected_by_exact_policy: true;
}

export interface KubernetesNetworkObservation {
  network_policy_sha256s: Readonly<Record<string, string>>;
  pre_restart_direct_raw_ip_egress: "blocked";
  pre_restart_gateway_reachability: "allowed";
  post_restart_direct_raw_ip_egress: "blocked";
  post_restart_gateway_reachability: "allowed";
  link_local_metadata_raw_ip: "blocked";
  root_filesystem_write: "blocked";
  writable_tmp_round_trip: "allowed";
  spawned_subprocess_raw_ip_egress: "blocked";
  automatic_api_token_present_in_agent: false;
  probe_command_sha256s: Readonly<Record<string, string>>;
}

export interface KubernetesSdkProbeOutput {
  schema_version: "gradia.guard.container-sdk-probe-output.v1";
  runtime_id: string;
  framework: KubernetesProofFramework;
  provider: KubernetesProofProvider;
  framework_core_package: "ai" | "langchain-core";
  framework_core_version: string;
  provider_package: string;
  provider_package_version: string;
  route_id:
    | "anthropic.messages"
    | "gemini.generateContent"
    | "openai.responses"
    | "xai.responses";
  requested_model: string;
  response_text: "ok";
}

export interface KubernetesSdkRouteObservation {
  framework_catalog_sha256: string;
  framework_entry_sha256: string;
  probe_environment_names: readonly string[];
  probe_command_sha256: string;
  probe_output: KubernetesSdkProbeOutput;
  probe_output_sha256: string;
}

export interface KubernetesGatewayObservation {
  session_id: string;
  frame_count: 2;
  chain_head_sha256: string;
  bundle_sha256: string;
  policy_sha256: string;
  configuration_sha256: string;
  guard_workload_identity_sha256: string;
  local_capability_sha256: string;
  accepted_local_requests: 1;
  native_provider_requests: 1;
  unauthorized_local_requests: 0;
  malformed_local_requests: 0;
}

export interface KubernetesEnforcementCoverage {
  observed_standard_network_policy_enforcement: true;
  agent_restart_preserved_observed_policy: true;
  provider_credentials_withheld_from_agent_configuration: true;
  projected_service_account_identity_observed: true;
  guard_dispatch_policy_observed_before_mocked_transport: true;
  exact_framework_provider_route_observed: true;
  live_provider_behavior_proved: false;
  kubernetes_identity_federation_exchange_proved: false;
  network_policy_failure_mode_fail_closed_proved: false;
  cluster_admin_or_node_operator_bypass_possible: true;
  exhaustive_bypass_resistance_proved: false;
  process_capture_complete: false;
  file_read_capture_complete: false;
  side_effect_capture_complete: false;
  full_host_enforcement: false;
  full_world_state_capture: false;
}

export interface KubernetesEnforcementReceiptBody {
  schema_version: typeof KUBERNETES_ENFORCEMENT_SCHEMA_VERSION;
  runtime_id: string;
  observed_at: string;
  orchestrator: "kubernetes";
  collector_authority: "kubectl_admin_inspection_server_dry_run_and_in_pod_probes";
  claim_boundary: "one_ephemeral_cluster_one_exact_framework_provider_cell_not_exhaustive_non_bypassability";
  cluster: KubernetesClusterObservation;
  agent: KubernetesWorkloadPosture;
  gateway: KubernetesWorkloadPosture;
  separate_agent_and_gateway_pods: true;
  restart: KubernetesRestartObservation;
  projected_identity: KubernetesProjectedIdentityObservation;
  admission: KubernetesAdmissionObservation;
  network: KubernetesNetworkObservation;
  sdk_route: KubernetesSdkRouteObservation;
  gateway_evidence: KubernetesGatewayObservation;
  coverage: KubernetesEnforcementCoverage;
}

export interface KubernetesEnforcementReceipt extends KubernetesEnforcementReceiptBody {
  receipt_sha256: string;
}

const POLICY_NAMES = Object.freeze([
  "agent-egress-only-to-guard-gateway",
  "default-deny-all",
  "gateway-ingress-only-from-agent",
  "gateway-standard-egress",
]);

const KIND_NODE_IMAGE_SHA256 =
  "099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed";

const PROVIDER_CREDENTIAL_NAMES = Object.freeze({
  anthropic: "ANTHROPIC_API_KEY",
  gemini: "GEMINI_API_KEY",
  openai: "OPENAI_API_KEY",
  xai: "XAI_API_KEY",
});

const PROVIDER_CASES = Object.freeze({
  anthropic: Object.freeze({ model: "claude-opus-5-20260801", route: "anthropic.messages" }),
  gemini: Object.freeze({ model: "gemini-4-pro", route: "gemini.generateContent" }),
  openai: Object.freeze({ model: "gpt-5.6-2026-08-01", route: "openai.responses" }),
  xai: Object.freeze({ model: "grok-4.6", route: "xai.responses" }),
});

export function createKubernetesEnforcementReceipt(
  body: KubernetesEnforcementReceiptBody,
  gatewayEvidenceDirectory: string,
): KubernetesEnforcementReceipt {
  const receipt = { ...body, receipt_sha256: digestCanonical(body) };
  verifyKubernetesEnforcementReceipt(receipt, gatewayEvidenceDirectory);
  return receipt;
}

export function verifyKubernetesEnforcementReceipt(
  value: unknown,
  gatewayEvidenceDirectory: string,
): KubernetesEnforcementReceipt {
  if (!record(value)) throw new Error("kubernetes_enforcement_receipt_shape_invalid");
  exactKeys(
    value,
    [
      "admission",
      "agent",
      "claim_boundary",
      "cluster",
      "collector_authority",
      "coverage",
      "gateway",
      "gateway_evidence",
      "network",
      "observed_at",
      "orchestrator",
      "projected_identity",
      "receipt_sha256",
      "restart",
      "runtime_id",
      "schema_version",
      "sdk_route",
      "separate_agent_and_gateway_pods",
    ],
    "kubernetes_enforcement_receipt",
  );
  const receipt = value as unknown as KubernetesEnforcementReceipt;
  if (receipt.schema_version !== KUBERNETES_ENFORCEMENT_SCHEMA_VERSION) {
    throw new Error("kubernetes_enforcement_schema_invalid");
  }
  assertStableId(receipt.runtime_id, "kubernetes_runtime_id");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(receipt.observed_at)) {
    throw new Error("kubernetes_enforcement_observed_at_invalid");
  }
  if (
    receipt.orchestrator !== "kubernetes" ||
    receipt.collector_authority !==
      "kubectl_admin_inspection_server_dry_run_and_in_pod_probes" ||
    receipt.claim_boundary !==
      "one_ephemeral_cluster_one_exact_framework_provider_cell_not_exhaustive_non_bypassability" ||
    receipt.separate_agent_and_gateway_pods !== true
  ) {
    throw new Error("kubernetes_enforcement_boundary_invalid");
  }
  verifyCluster(receipt.cluster);
  verifyWorkload(receipt.agent, true);
  verifyWorkload(receipt.gateway, false);
  verifyRestart(receipt.restart, receipt.agent.pod_uid_sha256);
  verifyProjectedIdentity(receipt.projected_identity);
  verifyAdmission(receipt.admission);
  verifyNetwork(receipt.network);
  verifySdkRoute(receipt.sdk_route, receipt.runtime_id);
  const selectedCredential = PROVIDER_CREDENTIAL_NAMES[receipt.sdk_route.probe_output.provider];
  if (
    canonicalJson(receipt.gateway.provider_credential_names_present) !==
    canonicalJson([selectedCredential])
  ) {
    throw new Error("kubernetes_gateway_provider_credential_route_mismatch");
  }
  verifyGateway(receipt.gateway_evidence, receipt.sdk_route, gatewayEvidenceDirectory);
  verifyCoverage(receipt.coverage);
  if (
    receipt.gateway_evidence.guard_workload_identity_sha256 ===
    receipt.projected_identity.token_sha256
  ) {
    throw new Error("kubernetes_enforcement_identity_layers_collapsed");
  }
  if (!isSha256(receipt.receipt_sha256)) {
    throw new Error("kubernetes_enforcement_receipt_digest_invalid");
  }
  const { receipt_sha256: _digest, ...body } = receipt;
  if (receipt.receipt_sha256 !== digestCanonical(body)) {
    throw new Error("kubernetes_enforcement_receipt_digest_mismatch");
  }
  return receipt;
}

function verifyCluster(cluster: KubernetesClusterObservation): void {
  exactKeys(
    cluster as unknown as Record<string, unknown>,
    [
      "container_runtime_versions",
      "cluster_provisioner",
      "kind_node_image_sha256",
      "kubernetes_git_version",
      "namespace_pod_security_enforce",
      "namespace_uid_sha256",
      "network_policy_engine_image_id_sha256",
      "network_policy_engine_ready",
      "node_count",
      "node_uid_sha256s",
      "server_platform",
    ],
    "kubernetes_cluster",
  );
  if (
    !/^v\d+\.\d+\.\d+$/.test(cluster.kubernetes_git_version) ||
    cluster.cluster_provisioner !== "kind/v0.33.0" ||
    cluster.kind_node_image_sha256 !== KIND_NODE_IMAGE_SHA256 ||
    !/^linux\/[a-z0-9_]+$/.test(cluster.server_platform) ||
    !Number.isInteger(cluster.node_count) ||
    cluster.node_count < 1 ||
    cluster.node_uid_sha256s.length !== cluster.node_count ||
    cluster.container_runtime_versions.length !== cluster.node_count ||
    cluster.namespace_pod_security_enforce !== "restricted" ||
    cluster.network_policy_engine_ready !== true
  ) {
    throw new Error("kubernetes_cluster_observation_invalid");
  }
  for (const digest of [
    ...cluster.node_uid_sha256s,
    cluster.kind_node_image_sha256,
    cluster.namespace_uid_sha256,
    cluster.network_policy_engine_image_id_sha256,
  ]) {
    if (!isSha256(digest)) throw new Error("kubernetes_cluster_digest_invalid");
  }
  if (
    canonicalJson([...cluster.node_uid_sha256s].sort()) !== canonicalJson(cluster.node_uid_sha256s) ||
    canonicalJson([...cluster.container_runtime_versions].sort()) !==
      canonicalJson(cluster.container_runtime_versions)
  ) {
    throw new Error("kubernetes_cluster_arrays_noncanonical");
  }
}

function verifyWorkload(workload: KubernetesWorkloadPosture, agent: boolean): void {
  exactKeys(
    workload as unknown as Record<string, unknown>,
    [
      "allow_privilege_escalation",
      "automount_service_account_token",
      "cap_drop_all",
      "configured_image_sha256",
      "deployment_uid_sha256",
      "host_ipc",
      "host_network",
      "host_pid",
      "pod_uid_sha256",
      "privileged",
      "provider_credential_names_present",
      "read_only_root_filesystem",
      "run_as_non_root",
      "run_as_user",
      "running_image_id_sha256",
      "seccomp_profile",
      "service_account_name",
    ],
    "kubernetes_workload",
  );
  for (const digest of [
    workload.deployment_uid_sha256,
    workload.pod_uid_sha256,
    workload.configured_image_sha256,
    workload.running_image_id_sha256,
  ]) {
    if (!isSha256(digest)) throw new Error("kubernetes_workload_digest_invalid");
  }
  if (
    workload.automount_service_account_token !== false ||
    workload.host_network !== false ||
    workload.host_pid !== false ||
    workload.host_ipc !== false ||
    workload.run_as_non_root !== true ||
    workload.run_as_user !== 65532 ||
    workload.seccomp_profile !== "RuntimeDefault" ||
    workload.allow_privilege_escalation !== false ||
    workload.privileged !== false ||
    workload.read_only_root_filesystem !== true ||
    workload.cap_drop_all !== true ||
    !/^gradia-guard-(agent|gateway)$/.test(workload.service_account_name)
  ) {
    throw new Error("kubernetes_workload_posture_invalid");
  }
  if (canonicalJson([...workload.provider_credential_names_present].sort()) !== canonicalJson(workload.provider_credential_names_present)) {
    throw new Error("kubernetes_workload_credentials_noncanonical");
  }
  if (agent && workload.provider_credential_names_present.length !== 0) {
    throw new Error("kubernetes_agent_provider_credential_present");
  }
  if (!agent && workload.provider_credential_names_present.length !== 1) {
    throw new Error("kubernetes_gateway_provider_credential_binding_invalid");
  }
}

function verifyRestart(restart: KubernetesRestartObservation, currentPodDigest: string): void {
  exactKeys(
    restart as unknown as Record<string, unknown>,
    ["after_pod_uid_sha256", "before_pod_uid_sha256", "replacement_observed"],
    "kubernetes_restart",
  );
  if (
    !isSha256(restart.before_pod_uid_sha256) ||
    !isSha256(restart.after_pod_uid_sha256) ||
    restart.before_pod_uid_sha256 === restart.after_pod_uid_sha256 ||
    restart.after_pod_uid_sha256 !== currentPodDigest ||
    restart.replacement_observed !== true
  ) {
    throw new Error("kubernetes_restart_observation_invalid");
  }
}

function verifyProjectedIdentity(identity: KubernetesProjectedIdentityObservation): void {
  exactKeys(
    identity as unknown as Record<string, unknown>,
    ["audiences", "expires_at_unix", "issued_at_unix", "lifetime_seconds", "subject", "token_sha256"],
    "kubernetes_projected_identity",
  );
  if (
    !isSha256(identity.token_sha256) ||
    identity.subject !== "system:serviceaccount:gradia-guard:gradia-guard-gateway" ||
    canonicalJson(identity.audiences) !== canonicalJson(["gradia-guard-workload-identity"]) ||
    !Number.isInteger(identity.issued_at_unix) ||
    !Number.isInteger(identity.expires_at_unix) ||
    identity.expires_at_unix - identity.issued_at_unix !== 600 ||
    identity.lifetime_seconds !== 600
  ) {
    throw new Error("kubernetes_projected_identity_invalid");
  }
}

function verifyAdmission(admission: KubernetesAdmissionObservation): void {
  exactKeys(
    admission as unknown as Record<string, unknown>,
    [
      "agent_provider_credential_rejected_by_exact_policy",
      "binding_uid_sha256",
      "failure_policy",
      "policy_uid_sha256",
      "type_check_warnings",
      "unpinned_image_rejected_by_exact_policy",
      "validation_actions",
      "writable_root_rejected_by_exact_policy",
    ],
    "kubernetes_admission",
  );
  if (
    !isSha256(admission.policy_uid_sha256) ||
    !isSha256(admission.binding_uid_sha256) ||
    admission.failure_policy !== "Fail" ||
    canonicalJson(admission.validation_actions) !== canonicalJson(["Audit", "Deny"]) ||
    admission.type_check_warnings !== 0 ||
    admission.unpinned_image_rejected_by_exact_policy !== true ||
    admission.writable_root_rejected_by_exact_policy !== true ||
    admission.agent_provider_credential_rejected_by_exact_policy !== true
  ) {
    throw new Error("kubernetes_admission_observation_invalid");
  }
}

function verifyNetwork(network: KubernetesNetworkObservation): void {
  exactKeys(
    network as unknown as Record<string, unknown>,
    [
      "automatic_api_token_present_in_agent",
      "link_local_metadata_raw_ip",
      "network_policy_sha256s",
      "post_restart_direct_raw_ip_egress",
      "post_restart_gateway_reachability",
      "pre_restart_direct_raw_ip_egress",
      "pre_restart_gateway_reachability",
      "probe_command_sha256s",
      "root_filesystem_write",
      "spawned_subprocess_raw_ip_egress",
      "writable_tmp_round_trip",
    ],
    "kubernetes_network",
  );
  if (
    canonicalJson(Object.keys(network.network_policy_sha256s).sort()) !== canonicalJson(POLICY_NAMES) ||
    network.pre_restart_direct_raw_ip_egress !== "blocked" ||
    network.pre_restart_gateway_reachability !== "allowed" ||
    network.post_restart_direct_raw_ip_egress !== "blocked" ||
    network.post_restart_gateway_reachability !== "allowed" ||
    network.link_local_metadata_raw_ip !== "blocked" ||
    network.root_filesystem_write !== "blocked" ||
    network.writable_tmp_round_trip !== "allowed" ||
    network.spawned_subprocess_raw_ip_egress !== "blocked" ||
    network.automatic_api_token_present_in_agent !== false
  ) {
    throw new Error("kubernetes_network_observation_invalid");
  }
  const commandNames = [
    "api_token_absence",
    "direct_raw_ip",
    "gateway_health",
    "link_local_raw_ip",
    "root_write",
    "spawned_subprocess_raw_ip",
    "tmp_round_trip",
  ];
  if (canonicalJson(Object.keys(network.probe_command_sha256s).sort()) !== canonicalJson(commandNames)) {
    throw new Error("kubernetes_probe_catalog_invalid");
  }
  for (const digest of [
    ...Object.values(network.network_policy_sha256s),
    ...Object.values(network.probe_command_sha256s),
  ]) {
    if (!isSha256(digest)) throw new Error("kubernetes_network_digest_invalid");
  }
}

function verifySdkRoute(route: KubernetesSdkRouteObservation, runtimeId: string): void {
  exactKeys(
    route as unknown as Record<string, unknown>,
    [
      "framework_catalog_sha256",
      "framework_entry_sha256",
      "probe_command_sha256",
      "probe_environment_names",
      "probe_output",
      "probe_output_sha256",
    ],
    "kubernetes_sdk_route",
  );
  const output = route.probe_output;
  const framework = exactFramework(output.framework);
  const provider = exactProvider(output.provider);
  const catalog = frameworkSdkCompatibilityCatalog();
  const entry = exactFrameworkEntry(catalog.entries, framework, provider);
  const expected = expectedProbeOutput(runtimeId, entry, provider);
  if (
    route.framework_catalog_sha256 !== catalog.catalog_sha256 ||
    route.framework_entry_sha256 !== digestCanonical(entry) ||
    canonicalJson(output) !== canonicalJson(expected) ||
    route.probe_output_sha256 !== digestCanonical(output) ||
    canonicalJson(route.probe_environment_names) !==
      canonicalJson(probeEnvironmentNames(provider)) ||
    route.probe_command_sha256 !== digestCanonical(probeCommand(framework, provider))
  ) {
    throw new Error("kubernetes_sdk_route_binding_invalid");
  }
}

function verifyGateway(
  gateway: KubernetesGatewayObservation,
  route: KubernetesSdkRouteObservation,
  directory: string,
): void {
  exactKeys(
    gateway as unknown as Record<string, unknown>,
    [
      "accepted_local_requests",
      "bundle_sha256",
      "chain_head_sha256",
      "configuration_sha256",
      "frame_count",
      "guard_workload_identity_sha256",
      "local_capability_sha256",
      "malformed_local_requests",
      "native_provider_requests",
      "policy_sha256",
      "session_id",
      "unauthorized_local_requests",
    ],
    "kubernetes_gateway_evidence",
  );
  for (const digest of [
    gateway.bundle_sha256,
    gateway.chain_head_sha256,
    gateway.configuration_sha256,
    gateway.guard_workload_identity_sha256,
    gateway.local_capability_sha256,
    gateway.policy_sha256,
  ]) {
    if (!isSha256(digest)) throw new Error("kubernetes_gateway_digest_invalid");
  }
  if (
    gateway.frame_count !== 2 ||
    gateway.accepted_local_requests !== 1 ||
    gateway.native_provider_requests !== 1 ||
    gateway.unauthorized_local_requests !== 0 ||
    gateway.malformed_local_requests !== 0
  ) {
    throw new Error("kubernetes_gateway_counts_invalid");
  }
  const verification = verifyGatewayBundle(directory);
  if (
    !verification.ok ||
    verification.session_id !== gateway.session_id ||
    verification.frame_count !== gateway.frame_count ||
    verification.chain_head_sha256 !== gateway.chain_head_sha256
  ) {
    throw new Error("kubernetes_gateway_bundle_invalid");
  }
  const bundle = parseJsonFile(join(directory, "bundle.json"));
  if (gateway.bundle_sha256 !== digestCanonical(bundle)) {
    throw new Error("kubernetes_gateway_bundle_digest_mismatch");
  }
  const frames = readFileSync(join(directory, "frames.ndjson"), "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as unknown);
  verifyGatewayBindings(frames, gateway, route.probe_output);
}

function verifyGatewayBindings(
  values: readonly unknown[],
  gateway: KubernetesGatewayObservation,
  output: KubernetesSdkProbeOutput,
): void {
  if (values.length !== 2 || !record(values[0]) || !record(values[1])) {
    throw new Error("kubernetes_gateway_frames_invalid");
  }
  const decision = values[0];
  const action = values[1];
  const policy = decision["policy"];
  if (!record(policy) || !Array.isArray(policy["reason_codes"])) {
    throw new Error("kubernetes_gateway_decision_invalid");
  }
  const reasons = policy["reason_codes"];
  if (
    decision["frame_kind"] !== "decision" ||
    action["frame_kind"] !== "action" ||
    decision["session_id"] !== gateway.session_id ||
    action["session_id"] !== gateway.session_id ||
    policy["policy_sha256"] !== gateway.policy_sha256 ||
    !reasons.includes(`http_configuration_sha256:${gateway.configuration_sha256}`) ||
    !reasons.includes(`workload_identity_sha256:${gateway.guard_workload_identity_sha256}`) ||
    decision["provider"] !== output.provider ||
    action["provider"] !== output.provider ||
    decision["requested_model"] !== output.requested_model ||
    action["requested_model"] !== output.requested_model ||
    action["resolved_model"] !== output.requested_model ||
    action["outcome"] !== "success"
  ) {
    throw new Error("kubernetes_gateway_route_binding_invalid");
  }
}

function verifyCoverage(coverage: KubernetesEnforcementCoverage): void {
  const expected: KubernetesEnforcementCoverage = {
    observed_standard_network_policy_enforcement: true,
    agent_restart_preserved_observed_policy: true,
    provider_credentials_withheld_from_agent_configuration: true,
    projected_service_account_identity_observed: true,
    guard_dispatch_policy_observed_before_mocked_transport: true,
    exact_framework_provider_route_observed: true,
    live_provider_behavior_proved: false,
    kubernetes_identity_federation_exchange_proved: false,
    network_policy_failure_mode_fail_closed_proved: false,
    cluster_admin_or_node_operator_bypass_possible: true,
    exhaustive_bypass_resistance_proved: false,
    process_capture_complete: false,
    file_read_capture_complete: false,
    side_effect_capture_complete: false,
    full_host_enforcement: false,
    full_world_state_capture: false,
  };
  exactKeys(
    coverage as unknown as Record<string, unknown>,
    Object.keys(expected),
    "kubernetes_coverage",
  );
  if (canonicalJson(coverage) !== canonicalJson(expected)) {
    throw new Error("kubernetes_coverage_overclaim");
  }
}

function expectedProbeOutput(
  runtimeId: string,
  entry: FrameworkSdkCompatibilityEntry,
  provider: KubernetesProofProvider,
): KubernetesSdkProbeOutput {
  const candidate = PROVIDER_CASES[provider];
  return {
    schema_version: "gradia.guard.container-sdk-probe-output.v1",
    runtime_id: runtimeId,
    framework: exactFramework(entry.framework),
    provider,
    framework_core_package: entry.framework_core_package,
    framework_core_version: entry.framework_core_version,
    provider_package: entry.provider_package,
    provider_package_version: entry.provider_package_version,
    route_id: candidate.route,
    requested_model: candidate.model,
    response_text: "ok",
  };
}

function probeEnvironmentNames(provider: KubernetesProofProvider): readonly string[] {
  const common = [
    "GRADIA_GUARD_LOCAL_CAPABILITY",
    "GRADIA_GUARD_LOCAL_ORIGIN",
    "GRADIA_GUARD_RUNTIME_ID",
  ];
  const selected = {
    anthropic: ["ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL"],
    gemini: ["GEMINI_API_KEY", "GOOGLE_GEMINI_BASE_URL"],
    openai: ["OPENAI_API_KEY", "OPENAI_BASE_URL"],
    xai: ["XAI_API_KEY", "XAI_BASE_URL"],
  }[provider];
  return [...common, ...selected];
}

function probeCommand(
  framework: KubernetesProofFramework,
  provider: KubernetesProofProvider,
): readonly string[] {
  const path = framework === "vercel_ai_sdk"
    ? "/opt/guard/vercel-provider-probe.mjs"
    : "/opt/guard/langchain-provider-probe.py";
  const executable = framework === "vercel_ai_sdk" ? "node" : "python";
  return [executable, path, provider];
}

function exactFrameworkEntry(
  entries: readonly FrameworkSdkCompatibilityEntry[],
  framework: KubernetesProofFramework,
  provider: KubernetesProofProvider,
): FrameworkSdkCompatibilityEntry {
  const matches = entries.filter(
    (entry) => entry.framework === framework && entry.provider === provider,
  );
  if (matches.length !== 1 || !matches[0]) throw new Error("kubernetes_framework_entry_missing");
  return matches[0];
}

function exactFramework(value: unknown): KubernetesProofFramework {
  if (value !== "vercel_ai_sdk" && value !== "langchain") {
    throw new Error("kubernetes_framework_invalid");
  }
  return value;
}

function exactProvider(value: unknown): KubernetesProofProvider {
  if (value !== "anthropic" && value !== "gemini" && value !== "openai" && value !== "xai") {
    throw new Error("kubernetes_provider_invalid");
  }
  return value;
}

function parseJsonFile(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as unknown;
  } catch {
    throw new Error("kubernetes_gateway_evidence_json_invalid");
  }
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  if (canonicalJson(Object.keys(value).sort()) !== canonicalJson([...keys].sort())) {
    throw new Error(`${label}_keys_invalid`);
  }
}

function record(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
