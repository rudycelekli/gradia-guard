import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalJson, digestCanonical, isSha256, sha256 } from "./canonical.js";
import {
  verifyContainerEnforcementReceipt,
  type ContainerEnforcementReceipt,
} from "./container-enforcement.js";
import {
  verifyCredentiallessRuntime,
  type CredentiallessRuntimeReceipt,
} from "./credentialless-runtime.js";
import {
  verifyRuntimeEvidenceBundle,
  type RuntimeEvidenceBundle,
  type RuntimeTerminalStatus,
} from "./runtime-evidence.js";
import { assertStableId } from "./security.js";

export const RUNTIME_COMPOSITION_SCHEMA_VERSION =
  "gradia.guard.runtime-composition-receipt.v1" as const;

export interface RuntimeCompositionCoverage {
  provider_loopback_gateway_receipt_verified: true;
  pre_dispatch_policy_evidence_bound: true;
  workload_identity_digest_bound: true;
  parent_forwarded_provider_credentials_to_child: false;
  known_provider_credential_names_absent_from_measured_agent: true;
  measured_agent_direct_egress_blocked: true;
  measured_agent_gateway_reachable: true;
  agent_root_filesystem_read_only: true;
  unprivileged_workload: true;
  durable_runtime_receipt_chain_verified: true;
  workload_network_bypass_possible: false;
  operator_or_docker_daemon_bypass_possible: true;
  declared_recorder_bypass_possible: true;
  process_spawn_capture_complete: false;
  file_read_capture_complete: false;
  side_effect_capture_complete: false;
  full_host_enforcement: false;
  full_world_state_capture: false;
}

export interface RuntimeCompositionReceiptBody {
  schema_version: typeof RUNTIME_COMPOSITION_SCHEMA_VERSION;
  runtime_id: string;
  runtime_session_id: string;
  created_at: string;
  policy_sha256: string;
  configuration_sha256: string;
  workload_identity_sha256: string;
  credential_policy_sha256: string;
  credentialless_runtime_receipt_sha256: string;
  container_enforcement_receipt_sha256: string;
  runtime_evidence_bundle_sha256: string;
  runtime_evidence_header_sha256: string;
  runtime_evidence_finalization_sha256: string;
  runtime_evidence_anchor_sha256: string;
  runtime_terminal_status: RuntimeTerminalStatus;
  coverage: RuntimeCompositionCoverage;
  claim_boundary: "same_runtime_binding_with_measured_container_egress_and_declared_g3_observation";
}

export interface RuntimeCompositionReceipt extends RuntimeCompositionReceiptBody {
  receipt_sha256: string;
}

export interface RuntimeCompositionSources {
  credentiallessRuntimeDirectory: string;
  containerEnforcementReceipt: unknown;
  runtimeEvidenceBundle: unknown;
  createdAt: string;
}

export interface RuntimeCompositionVerification {
  ok: boolean;
  blockers: readonly string[];
  receipt_sha256: string | null;
  runtime_id: string | null;
  runtime_session_id: string | null;
  coverage: RuntimeCompositionCoverage | null;
  claim_boundary:
    | "same_runtime_binding_with_measured_container_egress_and_declared_g3_observation"
    | null;
}

/**
 * Bind independently verified local-runtime, container-enforcement, and G3
 * evidence to one runtime. This strengthens source attribution; it cannot turn
 * a declared recorder or Docker operator boundary into full-host enforcement.
 */
export function composeRuntimeEvidence(
  sources: RuntimeCompositionSources,
): RuntimeCompositionReceipt {
  const source = verifiedSources(sources);
  const body: RuntimeCompositionReceiptBody = {
    schema_version: RUNTIME_COMPOSITION_SCHEMA_VERSION,
    runtime_id: source.credentialless.runtime_id,
    runtime_session_id: source.runtimeBundle.header.session_id,
    created_at: sources.createdAt,
    policy_sha256: source.credentialless.policy_sha256,
    configuration_sha256: source.credentialless.configuration_sha256,
    workload_identity_sha256: source.credentialless.workload_identity_sha256,
    credential_policy_sha256: source.runtimeBundle.header.credential_policy_sha256,
    credentialless_runtime_receipt_sha256: source.credentialless.receipt_sha256,
    container_enforcement_receipt_sha256: source.container.receipt_sha256,
    runtime_evidence_bundle_sha256: source.runtimeBundleSha256,
    runtime_evidence_header_sha256: source.runtimeBundle.header.header_sha256,
    runtime_evidence_finalization_sha256:
      source.runtimeBundle.finalization.finalization_sha256,
    runtime_evidence_anchor_sha256: source.runtimeBundle.anchor_receipt.anchor_sha256,
    runtime_terminal_status: source.runtimeBundle.finalization.terminal_status,
    coverage: runtimeCompositionCoverage(),
    claim_boundary:
      "same_runtime_binding_with_measured_container_egress_and_declared_g3_observation",
  };
  const receipt = { ...body, receipt_sha256: digestCanonical(body) };
  const verification = verifyRuntimeCompositionReceipt(receipt, sources);
  if (!verification.ok) {
    throw new Error(`runtime_composition_self_verification_failed:${verification.blockers.join(",")}`);
  }
  return receipt;
}

export function verifyRuntimeCompositionReceipt(
  value: unknown,
  sources: RuntimeCompositionSources,
): RuntimeCompositionVerification {
  try {
    const receipt = parseReceipt(value);
    const expected = composeWithoutRecursiveVerification(sources);
    if (canonicalJson(receipt) !== canonicalJson(expected)) {
      throw new Error("runtime_composition_source_binding_mismatch");
    }
    return {
      ok: true,
      blockers: [],
      receipt_sha256: receipt.receipt_sha256,
      runtime_id: receipt.runtime_id,
      runtime_session_id: receipt.runtime_session_id,
      coverage: receipt.coverage,
      claim_boundary: receipt.claim_boundary,
    };
  } catch (error) {
    return {
      ok: false,
      blockers: [
        error instanceof Error ? error.message : "runtime_composition_verification_failed",
      ],
      receipt_sha256: null,
      runtime_id: null,
      runtime_session_id: null,
      coverage: null,
      claim_boundary: null,
    };
  }
}

function composeWithoutRecursiveVerification(
  sources: RuntimeCompositionSources,
): RuntimeCompositionReceipt {
  const source = verifiedSources(sources);
  const body: RuntimeCompositionReceiptBody = {
    schema_version: RUNTIME_COMPOSITION_SCHEMA_VERSION,
    runtime_id: source.credentialless.runtime_id,
    runtime_session_id: source.runtimeBundle.header.session_id,
    created_at: sources.createdAt,
    policy_sha256: source.credentialless.policy_sha256,
    configuration_sha256: source.credentialless.configuration_sha256,
    workload_identity_sha256: source.credentialless.workload_identity_sha256,
    credential_policy_sha256: source.runtimeBundle.header.credential_policy_sha256,
    credentialless_runtime_receipt_sha256: source.credentialless.receipt_sha256,
    container_enforcement_receipt_sha256: source.container.receipt_sha256,
    runtime_evidence_bundle_sha256: source.runtimeBundleSha256,
    runtime_evidence_header_sha256: source.runtimeBundle.header.header_sha256,
    runtime_evidence_finalization_sha256:
      source.runtimeBundle.finalization.finalization_sha256,
    runtime_evidence_anchor_sha256: source.runtimeBundle.anchor_receipt.anchor_sha256,
    runtime_terminal_status: source.runtimeBundle.finalization.terminal_status,
    coverage: runtimeCompositionCoverage(),
    claim_boundary:
      "same_runtime_binding_with_measured_container_egress_and_declared_g3_observation",
  };
  return { ...body, receipt_sha256: digestCanonical(body) };
}

function verifiedSources(sources: RuntimeCompositionSources): {
  credentialless: CredentiallessRuntimeReceipt;
  container: ContainerEnforcementReceipt;
  runtimeBundle: RuntimeEvidenceBundle;
  runtimeBundleSha256: string;
} {
  if (!isoTimestamp(sources.createdAt)) throw new Error("runtime_composition_created_at_invalid");
  const credentiallessVerification = verifyCredentiallessRuntime(
    sources.credentiallessRuntimeDirectory,
  );
  if (!credentiallessVerification.ok) {
    throw new Error(
      `runtime_composition_credentialless_invalid:${credentiallessVerification.blockers.join(",")}`,
    );
  }
  let credentialless: CredentiallessRuntimeReceipt;
  try {
    credentialless = JSON.parse(
      readFileSync(join(sources.credentiallessRuntimeDirectory, "runtime.json"), "utf8"),
    ) as CredentiallessRuntimeReceipt;
  } catch {
    throw new Error("runtime_composition_credentialless_unreadable");
  }
  const container = verifyContainerEnforcementReceipt(sources.containerEnforcementReceipt);
  const runtimeVerification = verifyRuntimeEvidenceBundle(sources.runtimeEvidenceBundle);
  if (
    !runtimeVerification.ok ||
    runtimeVerification.bundle_sha256 === null ||
    runtimeVerification.terminal_status === null
  ) {
    throw new Error(
      `runtime_composition_g3_invalid:${runtimeVerification.blockers.join(",")}`,
    );
  }
  const runtimeBundle = sources.runtimeEvidenceBundle as RuntimeEvidenceBundle;
  assertStableId(credentialless.runtime_id, "runtime_composition_runtime_id");
  if (container.runtime_id !== credentialless.runtime_id) {
    throw new Error("runtime_composition_container_runtime_mismatch");
  }
  const expectedRuntimeIdentitySha256 = sha256(Buffer.from(credentialless.runtime_id));
  if (runtimeBundle.header.runtime_identity_sha256 !== expectedRuntimeIdentitySha256) {
    throw new Error("runtime_composition_g3_runtime_identity_mismatch");
  }
  if (
    container.policy_sha256 !== credentialless.policy_sha256 ||
    runtimeBundle.header.policy_sha256 !== credentialless.policy_sha256
  ) {
    throw new Error("runtime_composition_policy_mismatch");
  }
  if (container.configuration_sha256 !== credentialless.configuration_sha256) {
    throw new Error("runtime_composition_configuration_mismatch");
  }
  if (container.workload_identity_sha256 !== credentialless.workload_identity_sha256) {
    throw new Error("runtime_composition_workload_identity_mismatch");
  }
  return {
    credentialless,
    container,
    runtimeBundle,
    runtimeBundleSha256: runtimeVerification.bundle_sha256,
  };
}

function parseReceipt(value: unknown): RuntimeCompositionReceipt {
  if (!record(value)) throw new Error("runtime_composition_receipt_shape_invalid");
  exactKeys(
    value,
    [
      "claim_boundary",
      "configuration_sha256",
      "container_enforcement_receipt_sha256",
      "coverage",
      "created_at",
      "credential_policy_sha256",
      "credentialless_runtime_receipt_sha256",
      "policy_sha256",
      "receipt_sha256",
      "runtime_evidence_anchor_sha256",
      "runtime_evidence_bundle_sha256",
      "runtime_evidence_finalization_sha256",
      "runtime_evidence_header_sha256",
      "runtime_id",
      "runtime_session_id",
      "runtime_terminal_status",
      "schema_version",
      "workload_identity_sha256",
    ],
    "runtime_composition_receipt",
  );
  const receipt = value as unknown as RuntimeCompositionReceipt;
  if (receipt.schema_version !== RUNTIME_COMPOSITION_SCHEMA_VERSION) {
    throw new Error("runtime_composition_schema_invalid");
  }
  assertStableId(receipt.runtime_id, "runtime_composition_runtime_id");
  assertStableId(receipt.runtime_session_id, "runtime_composition_session_id");
  if (!isoTimestamp(receipt.created_at)) throw new Error("runtime_composition_created_at_invalid");
  if (!record(receipt.coverage)) throw new Error("runtime_composition_coverage_shape_invalid");
  exactKeys(
    receipt.coverage,
    Object.keys(runtimeCompositionCoverage()),
    "runtime_composition_coverage",
  );
  if (canonicalJson(receipt.coverage) !== canonicalJson(runtimeCompositionCoverage())) {
    throw new Error("runtime_composition_coverage_overclaim");
  }
  if (
    receipt.claim_boundary !==
    "same_runtime_binding_with_measured_container_egress_and_declared_g3_observation"
  ) {
    throw new Error("runtime_composition_claim_boundary_invalid");
  }
  for (const digest of [
    receipt.policy_sha256,
    receipt.configuration_sha256,
    receipt.workload_identity_sha256,
    receipt.credential_policy_sha256,
    receipt.credentialless_runtime_receipt_sha256,
    receipt.container_enforcement_receipt_sha256,
    receipt.runtime_evidence_bundle_sha256,
    receipt.runtime_evidence_header_sha256,
    receipt.runtime_evidence_finalization_sha256,
    receipt.runtime_evidence_anchor_sha256,
    receipt.receipt_sha256,
  ]) {
    if (!isSha256(digest)) throw new Error("runtime_composition_digest_invalid");
  }
  const { receipt_sha256: _digest, ...body } = receipt;
  if (receipt.receipt_sha256 !== digestCanonical(body)) {
    throw new Error("runtime_composition_receipt_digest_mismatch");
  }
  return receipt;
}

function runtimeCompositionCoverage(): RuntimeCompositionCoverage {
  return Object.freeze({
    provider_loopback_gateway_receipt_verified: true,
    pre_dispatch_policy_evidence_bound: true,
    workload_identity_digest_bound: true,
    parent_forwarded_provider_credentials_to_child: false,
    known_provider_credential_names_absent_from_measured_agent: true,
    measured_agent_direct_egress_blocked: true,
    measured_agent_gateway_reachable: true,
    agent_root_filesystem_read_only: true,
    unprivileged_workload: true,
    durable_runtime_receipt_chain_verified: true,
    workload_network_bypass_possible: false,
    operator_or_docker_daemon_bypass_possible: true,
    declared_recorder_bypass_possible: true,
    process_spawn_capture_complete: false,
    file_read_capture_complete: false,
    side_effect_capture_complete: false,
    full_host_enforcement: false,
    full_world_state_capture: false,
  });
}

function isoTimestamp(value: string): boolean {
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value);
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
