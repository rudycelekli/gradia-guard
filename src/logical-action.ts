import { digestCanonical, isSha256 } from "./canonical.js";
import {
  verifyRuntimeEvidenceBundle,
  type RuntimeEvidenceBundle,
  type RuntimeEvidenceReceipt,
} from "./runtime-evidence.js";
import { assertStableId } from "./security.js";
import type { SdkEvidenceFrame } from "./types.js";

export const LOGICAL_ACTION_COORDINATES_SCHEMA_VERSION =
  "gradia.logical-action-coordinates.v1" as const;
export const LOGICAL_ACTION_IDENTITY_SCHEMA_VERSION =
  "gradia.logical-action-identity.v1" as const;

export interface LogicalActionCoordinates {
  schema_version: typeof LOGICAL_ACTION_COORDINATES_SCHEMA_VERSION;
  action_namespace_id: string;
  actor_id: string;
  logical_operation_id: string;
  attempt_number: number;
}

export interface LogicalActionIdentity {
  schema_version: typeof LOGICAL_ACTION_IDENTITY_SCHEMA_VERSION;
  coordinates: LogicalActionCoordinates;
  coordinates_sha256: string;
  occurrence_id: string;
  claim_boundary:
    "same_declared_action_coordinates_not_semantic_equivalence_causality_or_capture_completeness";
}

/**
 * Create the provider/runtime-neutral identity for one logical action attempt.
 *
 * Every participating surface must receive the same namespace, actor,
 * operation and attempt before execution. Equal output means only that those
 * declared coordinates are equal; it does not prove that two collectors saw
 * the same bytes, that an action caused an effect, or that capture was
 * complete.
 */
export function createLogicalActionIdentity(
  coordinates: LogicalActionCoordinates,
): LogicalActionIdentity {
  verifyLogicalActionCoordinates(coordinates);
  const coordinatesSha256 = digestCanonical(coordinates);
  return {
    schema_version: LOGICAL_ACTION_IDENTITY_SCHEMA_VERSION,
    coordinates: { ...coordinates },
    coordinates_sha256: coordinatesSha256,
    occurrence_id: `logical-action.${coordinatesSha256}`,
    claim_boundary:
      "same_declared_action_coordinates_not_semantic_equivalence_causality_or_capture_completeness",
  };
}

export function verifyLogicalActionIdentity(value: unknown): LogicalActionIdentity {
  if (!record(value)) throw new Error("logical_action_identity_shape_invalid");
  exactKeys(value, [
    "claim_boundary",
    "coordinates",
    "coordinates_sha256",
    "occurrence_id",
    "schema_version",
  ], "logical_action_identity");
  if (value["schema_version"] !== LOGICAL_ACTION_IDENTITY_SCHEMA_VERSION) {
    throw new Error("logical_action_identity_schema_invalid");
  }
  const coordinates = value["coordinates"];
  verifyLogicalActionCoordinates(coordinates);
  const expected = createLogicalActionIdentity(coordinates);
  if (
    value["coordinates_sha256"] !== expected.coordinates_sha256 ||
    value["occurrence_id"] !== expected.occurrence_id ||
    value["claim_boundary"] !== expected.claim_boundary
  ) {
    throw new Error("logical_action_identity_binding_invalid");
  }
  return expected;
}

/** Derive the shared coordinates already carried by every strict G2 frame. */
export function logicalActionIdentityForSdkFrame(
  frame: SdkEvidenceFrame,
): LogicalActionIdentity {
  return createLogicalActionIdentity({
    schema_version: LOGICAL_ACTION_COORDINATES_SCHEMA_VERSION,
    action_namespace_id: frame.session_id,
    actor_id: frame.actor_id,
    logical_operation_id: frame.logical_operation_id,
    attempt_number: frame.attempt_number,
  });
}

/**
 * Locate one logical action inside a fully verified G3 runtime bundle.
 *
 * Verification happens before any receipt is returned.  The namespace must be
 * the runtime session and the occurrence must be the canonical logical-action
 * identifier.  This still proves only shared declared coordinates plus the
 * G3 bundle's own observation claims; it does not infer causality or capture
 * completeness.
 */
export function verifiedRuntimeReceiptForLogicalAction(
  bundleValue: unknown,
  identityValue: unknown,
): RuntimeEvidenceReceipt {
  const identity = verifyLogicalActionIdentity(identityValue);
  const verification = verifyRuntimeEvidenceBundle(bundleValue);
  if (!verification.ok) {
    throw new Error(`logical_action_runtime_bundle_unverified:${verification.blockers.join(",")}`);
  }
  const bundle = bundleValue as RuntimeEvidenceBundle;
  if (bundle.header.session_id !== identity.coordinates.action_namespace_id) {
    throw new Error("logical_action_runtime_namespace_mismatch");
  }
  const matches = bundle.receipts.filter(
    (receipt) => receipt.occurrence_id === identity.occurrence_id,
  );
  if (matches.length !== 1) {
    throw new Error("logical_action_runtime_occurrence_missing");
  }
  return matches[0]!;
}

export function verifyLogicalActionCoordinates(
  value: unknown,
): asserts value is LogicalActionCoordinates {
  if (!record(value)) throw new Error("logical_action_coordinates_shape_invalid");
  exactKeys(value, [
    "action_namespace_id",
    "actor_id",
    "attempt_number",
    "logical_operation_id",
    "schema_version",
  ], "logical_action_coordinates");
  if (value["schema_version"] !== LOGICAL_ACTION_COORDINATES_SCHEMA_VERSION) {
    throw new Error("logical_action_coordinates_schema_invalid");
  }
  for (const [field, code] of [
    ["action_namespace_id", "logical_action_namespace_id"],
    ["actor_id", "logical_action_actor_id"],
    ["logical_operation_id", "logical_action_operation_id"],
  ] as const) {
    if (typeof value[field] !== "string") throw new Error(`${code}_invalid`);
    assertStableId(value[field], code);
  }
  if (!Number.isSafeInteger(value["attempt_number"]) || Number(value["attempt_number"]) < 1) {
    throw new Error("logical_action_attempt_number_invalid");
  }
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label}_keys_invalid`);
  }
}

export function isLogicalActionOccurrenceId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.startsWith("logical-action.") &&
    isSha256(value.slice("logical-action.".length))
  );
}
