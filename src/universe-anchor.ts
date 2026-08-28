import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { canonicalJson, isSha256 } from "./canonical.js";
import { assertStableId } from "./security.js";

export const UNIVERSE_ANCHOR_SCHEMA_VERSION = "gradia.guard.universe-anchor.v1" as const;

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface UniverseAnchorAttestation {
  schema_version: typeof UNIVERSE_ANCHOR_SCHEMA_VERSION;
  anchor_scope: "verified_durable_observatory_prefix";
  project_id: string;
  run_id: string;
  episode_id: string;
  task_id: string;
  scenario_version_id: string;
  scenario_digest: string;
  run_status: string;
  episode_status: string;
  completed_at: string;
  frame_count: number;
  visible_frame_count: number;
  event_frame_count: number;
  restore_frame_count: number;
  root_chain_head_sha256: string;
  agent_chain_head_sha256: string;
  terminal_world_root_sha256: string;
  world_state_root_chain_verified: true;
  agent_projection_chain_verified: true;
  visibility_boundary_verified: true;
  evolution_witness_binding_verified: boolean;
  snapshot_restore_verified: boolean;
  counterfactual_pair_verified: false;
  full_host_enforcement_proved: false;
  raw_payload_included: false;
  retention_execution_proved: false;
}

export interface UniverseAnchor {
  attestation: UniverseAnchorAttestation;
  signature_ed25519: string;
  public_key_ed25519: string;
  public_key_id: string;
}

export interface UniverseAnchorExpectation {
  projectId: string;
  runId: string;
  episodeId: string;
  taskId?: string;
  scenarioDigest?: string;
  pinnedPublicKeyId?: string;
  pinnedPublicKeyEd25519?: string;
}

export interface UniverseAnchorVerification {
  ok: true;
  anchorSha256: string;
  publicKeyId: string;
  coverage: {
    evolutionWitness: boolean;
    snapshotRestore: boolean;
    counterfactualPair: false;
    fullHostEnforcement: false;
  };
}

/** Verify a payload-free Gradia Universe proof head without a Gradia account. */
export function verifyUniverseAnchor(
  value: unknown,
  expected: UniverseAnchorExpectation,
): UniverseAnchorVerification {
  if (!isRecord(value)) throw new Error("universe_anchor_shape_invalid");
  assertExactKeys(
    value,
    ["attestation", "public_key_ed25519", "public_key_id", "signature_ed25519"],
    "universe_anchor",
  );
  if (!isRecord(value["attestation"])) throw new Error("universe_anchor_attestation_invalid");
  const attestation = value["attestation"];
  assertExactKeys(
    attestation,
    [
      "agent_chain_head_sha256",
      "agent_projection_chain_verified",
      "anchor_scope",
      "completed_at",
      "counterfactual_pair_verified",
      "episode_id",
      "episode_status",
      "event_frame_count",
      "evolution_witness_binding_verified",
      "frame_count",
      "full_host_enforcement_proved",
      "project_id",
      "raw_payload_included",
      "restore_frame_count",
      "retention_execution_proved",
      "root_chain_head_sha256",
      "run_id",
      "run_status",
      "scenario_digest",
      "scenario_version_id",
      "schema_version",
      "snapshot_restore_verified",
      "task_id",
      "terminal_world_root_sha256",
      "visibility_boundary_verified",
      "visible_frame_count",
      "world_state_root_chain_verified",
    ],
    "universe_anchor_attestation",
  );
  if (attestation["schema_version"] !== UNIVERSE_ANCHOR_SCHEMA_VERSION) {
    throw new Error("universe_anchor_schema_invalid");
  }
  if (attestation["anchor_scope"] !== "verified_durable_observatory_prefix") {
    throw new Error("universe_anchor_scope_invalid");
  }
  for (const [field, wanted] of Object.entries({
    project_id: expected.projectId,
    run_id: expected.runId,
    episode_id: expected.episodeId,
    ...(expected.taskId ? { task_id: expected.taskId } : {}),
    ...(expected.scenarioDigest ? { scenario_digest: expected.scenarioDigest } : {}),
  })) {
    if (attestation[field] !== wanted) throw new Error(`universe_anchor_binding_mismatch:${field}`);
  }
  for (const field of [
    "project_id",
    "run_id",
    "episode_id",
    "task_id",
    "scenario_version_id",
    "run_status",
    "episode_status",
  ] as const) {
    if (typeof attestation[field] !== "string") {
      throw new Error(`universe_anchor_identity_invalid:${field}`);
    }
    assertStableId(attestation[field], field);
  }
  for (const field of [
    "scenario_digest",
    "root_chain_head_sha256",
    "agent_chain_head_sha256",
    "terminal_world_root_sha256",
  ] as const) {
    if (!isSha256(attestation[field])) throw new Error(`universe_anchor_digest_invalid:${field}`);
  }
  if (
    typeof attestation["completed_at"] !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?\+00:00$/.test(
      attestation["completed_at"],
    )
  ) {
    throw new Error("universe_anchor_completed_at_invalid");
  }
  const frameCount = integer(attestation["frame_count"], "frame_count", 1);
  const visibleCount = integer(attestation["visible_frame_count"], "visible_frame_count", 1);
  const eventCount = integer(attestation["event_frame_count"], "event_frame_count", 0);
  const restoreCount = integer(attestation["restore_frame_count"], "restore_frame_count", 0);
  if (visibleCount > frameCount || eventCount > frameCount || restoreCount > frameCount) {
    throw new Error("universe_anchor_count_invalid");
  }
  if (
    attestation["world_state_root_chain_verified"] !== true ||
    attestation["agent_projection_chain_verified"] !== true ||
    attestation["visibility_boundary_verified"] !== true ||
    attestation["evolution_witness_binding_verified"] !== (eventCount > 0) ||
    attestation["snapshot_restore_verified"] !== (restoreCount > 0) ||
    attestation["counterfactual_pair_verified"] !== false ||
    attestation["full_host_enforcement_proved"] !== false ||
    attestation["raw_payload_included"] !== false ||
    attestation["retention_execution_proved"] !== false
  ) {
    throw new Error("universe_anchor_coverage_overclaim");
  }
  const publicKey = value["public_key_ed25519"];
  const publicKeyId = value["public_key_id"];
  const signature = value["signature_ed25519"];
  if (typeof publicKey !== "string" || !/^[0-9a-f]{64}$/.test(publicKey)) {
    throw new Error("universe_anchor_public_key_invalid");
  }
  if (
    expected.pinnedPublicKeyEd25519 !== undefined &&
    !/^[0-9a-f]{64}$/.test(expected.pinnedPublicKeyEd25519)
  ) {
    throw new Error("universe_anchor_pinned_public_key_invalid");
  }
  if (
    expected.pinnedPublicKeyEd25519 !== undefined &&
    publicKey !== expected.pinnedPublicKeyEd25519
  ) {
    throw new Error("universe_anchor_unpinned_public_key");
  }
  if (typeof publicKeyId !== "string" || !/^[0-9a-f]{16}$/.test(publicKeyId)) {
    throw new Error("universe_anchor_public_key_id_invalid");
  }
  const derivedKeyId = createHash("sha256")
    .update(Buffer.from(publicKey, "hex"))
    .digest("hex")
    .slice(0, 16);
  if (derivedKeyId !== publicKeyId) throw new Error("universe_anchor_public_key_id_mismatch");
  if (expected.pinnedPublicKeyId && expected.pinnedPublicKeyId !== publicKeyId) {
    throw new Error("universe_anchor_unpinned_key");
  }
  if (typeof signature !== "string" || !/^[0-9a-f]{128}$/.test(signature)) {
    throw new Error("universe_anchor_signature_invalid");
  }
  const key = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKey, "hex")]),
    format: "der",
    type: "spki",
  });
  if (
    !verifySignature(
      null,
      Buffer.from(canonicalJson(attestation), "utf8"),
      key,
      Buffer.from(signature, "hex"),
    )
  ) {
    throw new Error("universe_anchor_signature_mismatch");
  }
  return {
    ok: true,
    anchorSha256: createHash("sha256").update(canonicalJson(value)).digest("hex"),
    publicKeyId,
    coverage: {
      evolutionWitness: eventCount > 0,
      snapshotRestore: restoreCount > 0,
      counterfactualPair: false,
      fullHostEnforcement: false,
    },
  };
}

function integer(value: unknown, field: string, minimum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    throw new Error(`universe_anchor_count_invalid:${field}`);
  }
  return value as number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function assertExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  if (canonicalJson(Object.keys(value).sort()) !== canonicalJson([...expected].sort())) {
    throw new Error(`${label}_keys_invalid`);
  }
}
