import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { canonicalJson, digestCanonical, isSha256, sha256 } from "./canonical.js";
import {
  frameworkSdkCompatibilityCatalog,
  type FrameworkSdkCompatibilityEntry,
} from "./framework-sdk-compatibility.js";
import {
  verifyContainerEnforcementReceipt,
  type ContainerEnforcementReceipt,
} from "./container-enforcement.js";
import { verifyGatewayBundle } from "./gateway-verify.js";
import { assertStableId } from "./security.js";

export const CONTAINER_SDK_ROUTE_SCHEMA_VERSION =
  "gradia.guard.container-sdk-route-receipt.v2" as const;

export type ContainerSdkRouteProvider = "anthropic" | "gemini" | "openai" | "xai";
export type ContainerSdkRouteFramework = "vercel_ai_sdk" | "langchain";

const FRAMEWORK_CASES = Object.freeze({
  vercel_ai_sdk: Object.freeze({
    executable: "node" as const,
    probePath: "/opt/guard/vercel-provider-probe.mjs",
  }),
  langchain: Object.freeze({
    executable: "python" as const,
    probePath: "/opt/guard/langchain-provider-probe.py",
  }),
});

const PROVIDER_CASES = Object.freeze({
  anthropic: Object.freeze({
    model: "claude-opus-5-20260801",
    routeId: "anthropic.messages" as const,
  }),
  gemini: Object.freeze({
    model: "gemini-4-pro",
    routeId: "gemini.generateContent" as const,
  }),
  openai: Object.freeze({
    model: "gpt-5.6-2026-08-01",
    routeId: "openai.responses" as const,
  }),
  xai: Object.freeze({
    model: "grok-4.6",
    routeId: "xai.responses" as const,
  }),
});

export interface ContainerSdkRouteProbeOutput {
  schema_version: "gradia.guard.container-sdk-probe-output.v1";
  runtime_id: string;
  framework: ContainerSdkRouteFramework;
  provider: ContainerSdkRouteProvider;
  framework_core_package: "ai" | "langchain-core";
  framework_core_version: string;
  provider_package:
    | "@ai-sdk/anthropic"
    | "@ai-sdk/google"
    | "@ai-sdk/openai"
    | "@ai-sdk/xai"
    | "langchain-anthropic"
    | "langchain-google-genai"
    | "langchain-openai"
    | "langchain-xai";
  provider_package_version: string;
  route_id:
    | "anthropic.messages"
    | "gemini.generateContent"
    | "openai.responses"
    | "xai.responses";
  requested_model: string;
  response_text: "ok";
}

export interface ContainerSdkRouteCoverage {
  exact_pinned_framework_call_observed: true;
  same_measured_agent_container_bound: true;
  routed_through_same_measured_gateway_container: true;
  guard_pre_dispatch_policy_evidence_verified: true;
  direct_egress_blocked_by_bound_container_receipt: true;
  provider_credential_present_in_measured_agent_configuration: false;
  local_capability_used_as_sdk_auth_value: true;
  only_selected_provider_sdk_variables_forwarded: true;
  live_provider_behavior_proved: false;
  arbitrary_framework_version_compatibility_proved: false;
  complete_bypass_exhaustion: false;
  operator_or_docker_daemon_bypass_possible: true;
  full_host_enforcement: false;
  full_world_state_capture: false;
}

export interface ContainerSdkRouteReceiptBody {
  schema_version: typeof CONTAINER_SDK_ROUTE_SCHEMA_VERSION;
  runtime_id: string;
  observed_at: string;
  orchestrator: "docker";
  collector_authority: "docker_daemon_exec_and_gateway_bundle_copy";
  container_enforcement_receipt_sha256: string;
  agent_container_id_sha256: string;
  gateway_container_id_sha256: string;
  framework_catalog_sha256: string;
  framework_entry_sha256: string;
  local_capability_sha256: string;
  local_origin: string;
  local_origin_sha256: string;
  probe_environment_names: readonly string[];
  probe_command_sha256: string;
  probe_output: ContainerSdkRouteProbeOutput;
  probe_output_sha256: string;
  gateway_session_id: string;
  gateway_frame_count: 2;
  gateway_chain_head_sha256: string;
  coverage: ContainerSdkRouteCoverage;
  claim_boundary: "one_exact_pinned_sdk_call_inside_one_measured_docker_boundary";
}

export interface ContainerSdkRouteReceipt extends ContainerSdkRouteReceiptBody {
  receipt_sha256: string;
}

export interface DockerContainerSdkRouteOptions {
  framework: ContainerSdkRouteFramework;
  provider: ContainerSdkRouteProvider;
  agentContainer: string;
  gatewayContainer: string;
  containerEnforcementReceipt: unknown;
  gatewayEvidenceOutputDirectory: string;
  localCapability: string;
  localOrigin: string;
  now?: () => Date;
  dockerBinary?: string;
}

export interface ContainerSdkRouteVerification {
  ok: boolean;
  blockers: readonly string[];
  receipt_sha256: string | null;
  gateway_chain_head_sha256: string | null;
}

/**
 * Execute one exact pinned framework/provider call inside the already measured
 * agent container, then copy and verify the Guard gateway
 * bundle produced by the same gateway container. The result binds successful
 * routed execution to the separate direct-egress refusal; it does not claim a
 * live provider call or exhaustive host non-bypassability.
 */
export function collectDockerContainerSdkRoute(
  options: DockerContainerSdkRouteOptions,
): ContainerSdkRouteReceipt {
  const container = verifyContainerEnforcementReceipt(options.containerEnforcementReceipt);
  assertStableId(options.agentContainer, "container_sdk_agent_container");
  assertStableId(options.gatewayContainer, "container_sdk_gateway_container");
  if (!/^[A-Za-z0-9_-]{24,200}$/.test(options.localCapability)) {
    throw new Error("container_sdk_local_capability_invalid");
  }
  const origin = exactInternalOrigin(options.localOrigin);
  if (existsSync(options.gatewayEvidenceOutputDirectory)) {
    throw new Error("container_sdk_gateway_evidence_directory_exists");
  }
  const docker = options.dockerBinary ?? "docker";
  assertLiveContainerBinding(
    docker,
    options.agentContainer,
    container.agent.container_id_sha256,
    "agent",
  );
  assertLiveContainerBinding(
    docker,
    options.gatewayContainer,
    container.gateway.container_id_sha256,
    "gateway",
  );
  const command = probeCommand(options);
  const result = spawnSync(docker, command, {
    encoding: "utf8",
    env: {
      ...process.env,
      GRADIA_GUARD_LOCAL_CAPABILITY: options.localCapability,
      GRADIA_GUARD_LOCAL_ORIGIN: origin,
      GRADIA_GUARD_RUNTIME_ID: container.runtime_id,
      ANTHROPIC_API_KEY: options.localCapability,
      ANTHROPIC_BASE_URL: `${origin}/anthropic`,
      GEMINI_API_KEY: options.localCapability,
      GOOGLE_API_KEY: options.localCapability,
      GOOGLE_GEMINI_BASE_URL: `${origin}/gemini`,
      OPENAI_API_KEY: options.localCapability,
      OPENAI_BASE_URL: `${origin}/openai/v1`,
      XAI_API_KEY: options.localCapability,
      XAI_BASE_URL: `${origin}/xai/v1`,
    },
    maxBuffer: 1_000_000,
    timeout: 30_000,
  });
  if (result.error || result.status === null) throw new Error("container_sdk_probe_unavailable");
  if (result.status !== 0) throw new Error(`container_sdk_probe_failed:${result.status}`);
  if (result.stderr !== "") throw new Error("container_sdk_probe_stderr_not_empty");
  const output = parseProbeOutput(
    result.stdout,
    container.runtime_id,
    options.framework,
    options.provider,
  );
  const status = waitForFinalizedGatewayStatus(
    docker,
    options.gatewayContainer,
    container,
    options.provider,
  );
  mkdirSync(options.gatewayEvidenceOutputDirectory, { recursive: false, mode: 0o700 });
  for (const name of ["bundle.json", "frames.ndjson"] as const) {
    const contents = readGatewayEvidenceFile(docker, options.gatewayContainer, name);
    writeFileSync(`${options.gatewayEvidenceOutputDirectory}/${name}`, contents, {
      flag: "wx",
      mode: 0o600,
    });
  }
  const gateway = verifyGatewayBundle(options.gatewayEvidenceOutputDirectory);
  if (
    !gateway.ok ||
    gateway.session_id === null ||
    gateway.chain_head_sha256 === null ||
    gateway.frame_count !== 2
  ) {
    throw new Error(`container_sdk_gateway_bundle_invalid:${gateway.blockers.join(",")}`);
  }
  if (
    status.gateway_verification.session_id !== gateway.session_id ||
    status.gateway_verification.chain_head_sha256 !== gateway.chain_head_sha256 ||
    status.gateway_verification.frame_count !== gateway.frame_count
  ) {
    throw new Error("container_sdk_gateway_status_bundle_mismatch");
  }
  const catalog = frameworkSdkCompatibilityCatalog();
  const entry = exactFrameworkEntry(catalog.entries, options.framework, options.provider);
  const body: ContainerSdkRouteReceiptBody = {
    schema_version: CONTAINER_SDK_ROUTE_SCHEMA_VERSION,
    runtime_id: container.runtime_id,
    observed_at: (options.now ?? (() => new Date()))().toISOString(),
    orchestrator: "docker",
    collector_authority: "docker_daemon_exec_and_gateway_bundle_copy",
    container_enforcement_receipt_sha256: container.receipt_sha256,
    agent_container_id_sha256: container.agent.container_id_sha256,
    gateway_container_id_sha256: container.gateway.container_id_sha256,
    framework_catalog_sha256: catalog.catalog_sha256,
    framework_entry_sha256: digestCanonical(entry),
    local_capability_sha256: sha256(Buffer.from(options.localCapability)),
    local_origin: origin,
    local_origin_sha256: sha256(Buffer.from(origin)),
    probe_environment_names: probeEnvironmentNames(options.provider),
    probe_command_sha256: digestCanonical(probeInvocation(options.framework, options.provider)),
    probe_output: output,
    probe_output_sha256: digestCanonical(output),
    gateway_session_id: gateway.session_id,
    gateway_frame_count: 2,
    gateway_chain_head_sha256: gateway.chain_head_sha256,
    coverage: containerSdkRouteCoverage(),
    claim_boundary: "one_exact_pinned_sdk_call_inside_one_measured_docker_boundary",
  };
  const receipt = { ...body, receipt_sha256: digestCanonical(body) };
  const verification = verifyContainerSdkRouteReceipt(
    receipt,
    container,
    options.gatewayEvidenceOutputDirectory,
  );
  if (!verification.ok) {
    throw new Error(`container_sdk_self_verification_failed:${verification.blockers.join(",")}`);
  }
  return receipt;
}

export function verifyContainerSdkRouteReceipt(
  value: unknown,
  containerEnforcementReceipt: unknown,
  gatewayEvidenceDirectory: string,
): ContainerSdkRouteVerification {
  const blockers: string[] = [];
  let receipt: ContainerSdkRouteReceipt | null = null;
  try {
    const container = verifyContainerEnforcementReceipt(containerEnforcementReceipt);
    receipt = parseReceipt(value);
    if (
      receipt.runtime_id !== container.runtime_id ||
      receipt.container_enforcement_receipt_sha256 !== container.receipt_sha256 ||
      receipt.agent_container_id_sha256 !== container.agent.container_id_sha256 ||
      receipt.gateway_container_id_sha256 !== container.gateway.container_id_sha256
    ) {
      throw new Error("container_sdk_enforcement_binding_mismatch");
    }
    if (container.agent.provider_credential_names_present.length !== 0) {
      throw new Error("container_sdk_agent_provider_credential_present");
    }
    const gateway = verifyGatewayBundle(gatewayEvidenceDirectory);
    if (!gateway.ok) throw new Error(`container_sdk_gateway_bundle_invalid:${gateway.blockers.join(",")}`);
    if (
      gateway.session_id !== receipt.gateway_session_id ||
      gateway.frame_count !== receipt.gateway_frame_count ||
      gateway.chain_head_sha256 !== receipt.gateway_chain_head_sha256
    ) {
      throw new Error("container_sdk_gateway_bundle_binding_mismatch");
    }
  } catch (error) {
    blockers.push(error instanceof Error ? error.message : "container_sdk_verification_failed");
  }
  return {
    ok: blockers.length === 0,
    blockers,
    receipt_sha256: blockers.length === 0 ? receipt?.receipt_sha256 ?? null : null,
    gateway_chain_head_sha256:
      blockers.length === 0 ? receipt?.gateway_chain_head_sha256 ?? null : null,
  };
}

function parseReceipt(value: unknown): ContainerSdkRouteReceipt {
  if (!record(value)) throw new Error("container_sdk_receipt_shape_invalid");
  exactKeys(
    value,
    [
      "agent_container_id_sha256",
      "claim_boundary",
      "collector_authority",
      "container_enforcement_receipt_sha256",
      "coverage",
      "framework_catalog_sha256",
      "framework_entry_sha256",
      "gateway_chain_head_sha256",
      "gateway_container_id_sha256",
      "gateway_frame_count",
      "gateway_session_id",
      "local_capability_sha256",
      "local_origin",
      "local_origin_sha256",
      "observed_at",
      "orchestrator",
      "probe_command_sha256",
      "probe_environment_names",
      "probe_output",
      "probe_output_sha256",
      "receipt_sha256",
      "runtime_id",
      "schema_version",
    ],
    "container_sdk_receipt",
  );
  const receipt = value as unknown as ContainerSdkRouteReceipt;
  if (receipt.schema_version !== CONTAINER_SDK_ROUTE_SCHEMA_VERSION) {
    throw new Error("container_sdk_schema_invalid");
  }
  assertStableId(receipt.runtime_id, "container_sdk_runtime_id");
  assertStableId(receipt.gateway_session_id, "container_sdk_gateway_session_id");
  if (!isoTimestamp(receipt.observed_at)) throw new Error("container_sdk_observed_at_invalid");
  if (
    receipt.orchestrator !== "docker" ||
    receipt.collector_authority !== "docker_daemon_exec_and_gateway_bundle_copy" ||
    receipt.claim_boundary !== "one_exact_pinned_sdk_call_inside_one_measured_docker_boundary"
  ) {
    throw new Error("container_sdk_claim_boundary_invalid");
  }
  const catalog = frameworkSdkCompatibilityCatalog();
  const framework = exactFramework(receipt.probe_output.framework);
  const provider = exactProvider(receipt.probe_output.provider);
  const entry = exactFrameworkEntry(catalog.entries, framework, provider);
  if (
    receipt.framework_catalog_sha256 !== catalog.catalog_sha256 ||
    receipt.framework_entry_sha256 !== digestCanonical(entry)
  ) {
    throw new Error("container_sdk_framework_binding_mismatch");
  }
  const output = parseProbeOutput(
    `${canonicalJson(receipt.probe_output)}\n`,
    receipt.runtime_id,
    framework,
    provider,
  );
  if (
    receipt.probe_output_sha256 !== digestCanonical(output) ||
    output.framework_core_version !== entry.framework_core_version ||
    output.provider_package_version !== entry.provider_package_version
  ) {
    throw new Error("container_sdk_probe_output_binding_mismatch");
  }
  if (receipt.local_origin !== exactInternalOrigin(receipt.local_origin)) {
    throw new Error("container_sdk_local_origin_invalid");
  }
  if (receipt.local_origin_sha256 !== sha256(Buffer.from(receipt.local_origin))) {
    throw new Error("container_sdk_local_origin_digest_mismatch");
  }
  if (
    canonicalJson(receipt.probe_environment_names) !==
    canonicalJson(probeEnvironmentNames(provider))
  ) {
    throw new Error("container_sdk_probe_environment_invalid");
  }
  if (!record(receipt.coverage)) throw new Error("container_sdk_coverage_shape_invalid");
  const coverage = containerSdkRouteCoverage();
  exactKeys(receipt.coverage, Object.keys(coverage), "container_sdk_coverage");
  if (canonicalJson(receipt.coverage) !== canonicalJson(coverage)) {
    throw new Error("container_sdk_coverage_overclaim");
  }
  if (receipt.gateway_frame_count !== 2) throw new Error("container_sdk_gateway_frame_count_invalid");
  if (
    receipt.probe_command_sha256 !==
    digestCanonical(probeInvocation(framework, provider))
  ) {
    throw new Error("container_sdk_probe_command_binding_mismatch");
  }
  for (const digest of [
    receipt.container_enforcement_receipt_sha256,
    receipt.agent_container_id_sha256,
    receipt.gateway_container_id_sha256,
    receipt.framework_catalog_sha256,
    receipt.framework_entry_sha256,
    receipt.local_capability_sha256,
    receipt.local_origin_sha256,
    receipt.probe_command_sha256,
    receipt.probe_output_sha256,
    receipt.gateway_chain_head_sha256,
    receipt.receipt_sha256,
  ]) {
    if (!isSha256(digest)) throw new Error("container_sdk_digest_invalid");
  }
  const { receipt_sha256: _digest, ...body } = receipt;
  if (receipt.receipt_sha256 !== digestCanonical(body)) {
    throw new Error("container_sdk_receipt_digest_mismatch");
  }
  return receipt;
}

function probeCommand(
  options: Pick<DockerContainerSdkRouteOptions, "agentContainer" | "framework" | "provider">,
): readonly string[] {
  return [
    "exec",
    ...probeEnvironmentNames(options.provider).flatMap((name) => ["-e", name]),
    options.agentContainer,
    ...probeInvocation(options.framework, options.provider),
  ];
}

function parseProbeOutput(
  text: string,
  runtimeId: string,
  framework: ContainerSdkRouteFramework,
  provider: ContainerSdkRouteProvider,
): ContainerSdkRouteProbeOutput {
  const trimmed = text.trim();
  if (!trimmed || trimmed.includes("\n")) throw new Error("container_sdk_probe_output_invalid");
  let value: unknown;
  try {
    value = JSON.parse(trimmed);
  } catch {
    throw new Error("container_sdk_probe_output_invalid");
  }
  if (!record(value)) throw new Error("container_sdk_probe_output_shape_invalid");
  const candidate = PROVIDER_CASES[provider];
  const entry = exactFrameworkEntry(
    frameworkSdkCompatibilityCatalog().entries,
    framework,
    provider,
  );
  const expected: ContainerSdkRouteProbeOutput = {
    schema_version: "gradia.guard.container-sdk-probe-output.v1",
    runtime_id: runtimeId,
    framework,
    provider,
    framework_core_package: entry.framework_core_package,
    framework_core_version: entry.framework_core_version,
    provider_package: entry.provider_package,
    provider_package_version: entry.provider_package_version,
    route_id: candidate.routeId,
    requested_model: candidate.model,
    response_text: "ok",
  };
  if (canonicalJson(value) !== canonicalJson(expected)) {
    throw new Error("container_sdk_probe_output_mismatch");
  }
  return value as unknown as ContainerSdkRouteProbeOutput;
}

interface GatewayStatus {
  runtime_id: string;
  provider: ContainerSdkRouteProvider;
  policy_sha256: string;
  configuration_sha256: string;
  workload_identity_sha256: string;
  accepted_local_requests: number;
  native_provider_requests: number;
  unauthorized_local_requests: number;
  malformed_local_requests: number;
  finalized: boolean;
  gateway_verification: {
    ok: boolean;
    blockers: readonly string[];
    session_id: string | null;
    frame_count: number;
    chain_head_sha256: string | null;
  } | null;
}

function waitForFinalizedGatewayStatus(
  docker: string,
  gatewayContainer: string,
  container: ContainerEnforcementReceipt,
  provider: ContainerSdkRouteProvider,
): GatewayStatus & { gateway_verification: NonNullable<GatewayStatus["gateway_verification"]> } {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const result = spawnSync(docker, ["exec", gatewayContainer, "cat", "/tmp/guard-status.json"], {
      encoding: "utf8",
      maxBuffer: 1_000_000,
      timeout: 2_000,
    });
    if (result.status === 0) {
      try {
        const status = JSON.parse(result.stdout) as GatewayStatus;
        if (status.finalized && status.gateway_verification !== null) {
          if (
            status.runtime_id !== container.runtime_id ||
            status.provider !== provider ||
            status.policy_sha256 !== container.policy_sha256 ||
            status.configuration_sha256 !== container.configuration_sha256 ||
            status.workload_identity_sha256 !== container.workload_identity_sha256 ||
            status.accepted_local_requests !== 1 ||
            status.native_provider_requests !== 1 ||
            status.unauthorized_local_requests !== 0 ||
            status.malformed_local_requests !== 0 ||
            status.gateway_verification.ok !== true ||
            status.gateway_verification.frame_count !== 2 ||
            status.gateway_verification.session_id === null ||
            status.gateway_verification.chain_head_sha256 === null
          ) {
            throw new Error("container_sdk_gateway_status_invalid");
          }
          return status as GatewayStatus & {
            gateway_verification: NonNullable<GatewayStatus["gateway_verification"]>;
          };
        }
      } catch (error) {
        if (error instanceof Error && error.message === "container_sdk_gateway_status_invalid") {
          throw error;
        }
      }
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
  }
  throw new Error("container_sdk_gateway_finalization_timeout");
}

function assertLiveContainerBinding(
  docker: string,
  containerName: string,
  expectedSha256: string,
  label: string,
): void {
  let identifier: string;
  try {
    identifier = execFileSync(docker, ["inspect", "--format", "{{.Id}}", containerName], {
      encoding: "utf8",
      timeout: 5_000,
    }).trim();
  } catch {
    throw new Error(`container_sdk_${label}_inspect_failed`);
  }
  if (!identifier || sha256(Buffer.from(identifier)) !== expectedSha256) {
    throw new Error(`container_sdk_${label}_container_binding_mismatch`);
  }
}

function readGatewayEvidenceFile(
  docker: string,
  gatewayContainer: string,
  name: "bundle.json" | "frames.ndjson",
): string {
  try {
    const contents = execFileSync(
      docker,
      ["exec", gatewayContainer, "cat", `/tmp/model-gateway/${name}`],
      { encoding: "utf8", timeout: 5_000, maxBuffer: 20_000_000 },
    );
    if (!contents || !contents.endsWith("\n")) {
      throw new Error("container_sdk_gateway_evidence_truncated");
    }
    return contents;
  } catch (error) {
    if (error instanceof Error && error.message === "container_sdk_gateway_evidence_truncated") {
      throw error;
    }
    throw new Error(`container_sdk_gateway_evidence_unreadable:${name}`);
  }
}

function exactFrameworkEntry(
  entries: readonly FrameworkSdkCompatibilityEntry[],
  framework: ContainerSdkRouteFramework,
  provider: ContainerSdkRouteProvider,
): FrameworkSdkCompatibilityEntry {
  const matches = entries.filter(
    (entry) => entry.framework === framework && entry.provider === provider,
  );
  if (matches.length !== 1 || !matches[0]) throw new Error("container_sdk_framework_entry_missing");
  return matches[0];
}

function exactFramework(value: unknown): ContainerSdkRouteFramework {
  if (value !== "vercel_ai_sdk" && value !== "langchain") {
    throw new Error("container_sdk_framework_invalid");
  }
  return value;
}

function probeInvocation(
  framework: ContainerSdkRouteFramework,
  provider: ContainerSdkRouteProvider,
): readonly string[] {
  const candidate = FRAMEWORK_CASES[framework];
  return [candidate.executable, candidate.probePath, provider];
}

function probeEnvironmentNames(provider: ContainerSdkRouteProvider): readonly string[] {
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
  return Object.freeze([...common, ...selected]);
}

function exactProvider(value: unknown): ContainerSdkRouteProvider {
  if (value !== "anthropic" && value !== "gemini" && value !== "openai" && value !== "xai") {
    throw new Error("container_sdk_provider_invalid");
  }
  return value;
}

function exactInternalOrigin(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("container_sdk_local_origin_invalid");
  }
  if (
    url.protocol !== "http:" ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash ||
    url.hostname !== "gateway" ||
    url.port !== "8787"
  ) {
    throw new Error("container_sdk_local_origin_invalid");
  }
  return "http://gateway:8787";
}

function containerSdkRouteCoverage(): ContainerSdkRouteCoverage {
  return Object.freeze({
    exact_pinned_framework_call_observed: true,
    same_measured_agent_container_bound: true,
    routed_through_same_measured_gateway_container: true,
    guard_pre_dispatch_policy_evidence_verified: true,
    direct_egress_blocked_by_bound_container_receipt: true,
    provider_credential_present_in_measured_agent_configuration: false,
    local_capability_used_as_sdk_auth_value: true,
    only_selected_provider_sdk_variables_forwarded: true,
    live_provider_behavior_proved: false,
    arbitrary_framework_version_compatibility_proved: false,
    complete_bypass_exhaustion: false,
    operator_or_docker_daemon_bypass_possible: true,
    full_host_enforcement: false,
    full_world_state_capture: false,
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

function isoTimestamp(value: string): boolean {
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value);
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
