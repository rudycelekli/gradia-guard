import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { canonicalJson, isSha256 } from "./canonical.js";
import { assertStableId } from "./security.js";

export const REMOTE_ANCHOR_SCHEMA_VERSION = "gradia.guard.remote-anchor.v1" as const;

const HEX_128 = /^[0-9a-f]{128}$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface GuardRemoteAnchorAttestation {
  schema_version: typeof REMOTE_ANCHOR_SCHEMA_VERSION;
  anchor_scope: "admitted_edition_and_retention_declaration";
  guard_evidence_edition_id: string;
  org_id: string;
  project_id: string;
  session_id: string;
  bundle_sha256: string;
  edition_sha256: string;
  verification_sha256: string;
  retention_policy_id: string;
  retention_execution_proved: false;
  deletion_proved: false;
  storage_residency_proved: false;
  created_by: string;
  created_at: string;
}

export interface GuardRemoteAnchor {
  attestation: GuardRemoteAnchorAttestation;
  signature_ed25519: string;
  public_key_ed25519: string;
  public_key_id: string;
}

export interface GuardRemoteAnchorExpectation {
  guardEvidenceEditionId: string;
  projectId: string;
  sessionId: string;
  bundleSha256: string;
  editionSha256: string;
  retentionPolicyId: string;
  createdBy: string;
  pinnedPublicKeyId?: string;
  pinnedPublicKeyEd25519?: string;
}

export interface GuardRemoteAnchorVerification {
  ok: true;
  anchorSha256: string;
  publicKeyId: string;
}

/** Verify the server witness without a Gradia account, network, or secret. */
export function verifyGuardRemoteAnchor(
  value: unknown,
  expected: GuardRemoteAnchorExpectation,
): GuardRemoteAnchorVerification {
  if (!isRecord(value)) throw new Error("guard_remote_anchor_shape_invalid");
  assertExactKeys(
    value,
    ["attestation", "public_key_ed25519", "public_key_id", "signature_ed25519"],
    "guard_remote_anchor",
  );
  if (!isRecord(value["attestation"])) {
    throw new Error("guard_remote_anchor_attestation_shape_invalid");
  }
  const attestation = value["attestation"];
  assertExactKeys(
    attestation,
    [
      "anchor_scope",
      "bundle_sha256",
      "created_at",
      "created_by",
      "deletion_proved",
      "edition_sha256",
      "guard_evidence_edition_id",
      "org_id",
      "project_id",
      "retention_execution_proved",
      "retention_policy_id",
      "schema_version",
      "session_id",
      "storage_residency_proved",
      "verification_sha256",
    ],
    "guard_remote_anchor_attestation",
  );
  if (attestation["schema_version"] !== REMOTE_ANCHOR_SCHEMA_VERSION) {
    throw new Error("guard_remote_anchor_schema_invalid");
  }
  if (attestation["anchor_scope"] !== "admitted_edition_and_retention_declaration") {
    throw new Error("guard_remote_anchor_scope_invalid");
  }
  if (
    attestation["retention_execution_proved"] !== false ||
    attestation["deletion_proved"] !== false ||
    attestation["storage_residency_proved"] !== false
  ) {
    throw new Error("guard_remote_anchor_retention_overclaim");
  }
  for (const [field, wanted] of Object.entries({
    guard_evidence_edition_id: expected.guardEvidenceEditionId,
    project_id: expected.projectId,
    session_id: expected.sessionId,
    bundle_sha256: expected.bundleSha256,
    edition_sha256: expected.editionSha256,
    retention_policy_id: expected.retentionPolicyId,
    created_by: expected.createdBy,
  })) {
    if (attestation[field] !== wanted) {
      throw new Error(`guard_remote_anchor_binding_mismatch:${field}`);
    }
  }
  for (const field of ["org_id", "guard_evidence_edition_id", "project_id", "session_id", "retention_policy_id", "created_by"] as const) {
    if (typeof attestation[field] !== "string") {
      throw new Error(`guard_remote_anchor_identity_invalid:${field}`);
    }
    assertStableId(attestation[field], field);
  }
  for (const field of ["bundle_sha256", "edition_sha256", "verification_sha256"] as const) {
    if (typeof attestation[field] !== "string" || !isSha256(attestation[field])) {
      throw new Error(`guard_remote_anchor_digest_invalid:${field}`);
    }
  }
  if (
    typeof attestation["created_at"] !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?\+00:00$/.test(attestation["created_at"])
  ) {
    throw new Error("guard_remote_anchor_created_at_invalid");
  }
  const publicKey = value["public_key_ed25519"];
  const publicKeyId = value["public_key_id"];
  const signature = value["signature_ed25519"];
  if (typeof publicKey !== "string" || !/^[0-9a-f]{64}$/.test(publicKey)) {
    throw new Error("guard_remote_anchor_public_key_invalid");
  }
  if (
    expected.pinnedPublicKeyEd25519 !== undefined &&
    !/^[0-9a-f]{64}$/.test(expected.pinnedPublicKeyEd25519)
  ) {
    throw new Error("guard_remote_anchor_pinned_public_key_invalid");
  }
  if (
    expected.pinnedPublicKeyEd25519 !== undefined &&
    publicKey !== expected.pinnedPublicKeyEd25519
  ) {
    throw new Error("guard_remote_anchor_unpinned_public_key");
  }
  if (typeof publicKeyId !== "string" || !/^[0-9a-f]{16}$/.test(publicKeyId)) {
    throw new Error("guard_remote_anchor_public_key_id_invalid");
  }
  const derivedPublicKeyId = createHash("sha256")
    .update(Buffer.from(publicKey, "hex"))
    .digest("hex")
    .slice(0, 16);
  if (publicKeyId !== derivedPublicKeyId) {
    throw new Error("guard_remote_anchor_public_key_id_mismatch");
  }
  if (expected.pinnedPublicKeyId && publicKeyId !== expected.pinnedPublicKeyId) {
    throw new Error("guard_remote_anchor_unpinned_key");
  }
  if (typeof signature !== "string" || !HEX_128.test(signature)) {
    throw new Error("guard_remote_anchor_signature_invalid");
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
    throw new Error("guard_remote_anchor_signature_mismatch");
  }
  return {
    ok: true,
    anchorSha256: createHash("sha256").update(canonicalJson(value)).digest("hex"),
    publicKeyId,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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
