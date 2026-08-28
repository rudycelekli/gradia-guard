import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalJson, isSha256 } from "./canonical.js";
import { coverageBlockers } from "./coverage.js";
import { gatewayFrameBlockers } from "./gateway.js";
import { assertStableId } from "./security.js";
import {
  GATEWAY_BUNDLE_SCHEMA_VERSION,
  GENESIS_SHA256,
  type GatewayActionFrame,
  type GatewayDecisionFrame,
  type GatewayEvidenceBundleManifest,
  type GatewayEvidenceFrame,
  type VerificationResult,
} from "./types.js";

interface AttemptPair {
  decision: GatewayDecisionFrame | null;
  action: GatewayActionFrame | null;
  decisionIndex: number | null;
  actionIndex: number | null;
}

export function verifyGatewayBundle(directory: string): VerificationResult {
  const blockers: string[] = [];
  let manifest: GatewayEvidenceBundleManifest;
  try {
    manifest = JSON.parse(
      readFileSync(join(directory, "bundle.json"), "utf8"),
    ) as GatewayEvidenceBundleManifest;
  } catch {
    return result(["gateway_bundle_manifest_unreadable"], null, 0, null, 0);
  }
  try {
    blockers.push(...gatewayManifestBlockers(manifest));
  } catch {
    blockers.push("gateway_bundle_manifest_shape_invalid");
  }

  let frames: GatewayEvidenceFrame[] = [];
  try {
    const text = readFileSync(join(directory, "frames.ndjson"), "utf8");
    if (text && !text.endsWith("\n")) blockers.push("gateway_frame_log_truncated");
    frames = text
      .split("\n")
      .filter((line) => line.length > 0)
      .map((line, index) => {
        try {
          return JSON.parse(line) as GatewayEvidenceFrame;
        } catch {
          blockers.push(`gateway_frame_json_invalid:${index}`);
          return null;
        }
      })
      .filter((frame): frame is GatewayEvidenceFrame => frame !== null);
  } catch {
    blockers.push("gateway_frame_log_unreadable");
  }

  let head: string = GENESIS_SHA256;
  let previousObservedAt: string | null = null;
  const pairs = new Map<string, AttemptPair>();
  const logicalAttempts = new Map<string, Map<number, string>>();
  const contentIdentities = new Set<string>();

  frames.forEach((frame, index) => {
    try {
      blockers.push(...gatewayFrameBlockers(frame).map((item) => `${item}:${index}`));
      if (frame.session_id !== manifest.session_id) blockers.push(`gateway_frame_session_mismatch:${index}`);
      if (canonicalJson(frame.coverage) !== canonicalJson(manifest.coverage)) {
        blockers.push(`gateway_frame_bundle_coverage_mismatch:${index}`);
      }
      if (frame.sequence !== index) blockers.push(`gateway_frame_sequence_gap:${index}`);
      if (frame.previous_frame_sha256 !== head) blockers.push(`gateway_frame_previous_hash_mismatch:${index}`);
      if (isSha256(frame.frame_sha256)) head = frame.frame_sha256;
      if (previousObservedAt !== null && frame.observed_at < previousObservedAt) {
        blockers.push(`gateway_frame_timestamp_regressed:${index}`);
      }
      previousObservedAt = frame.observed_at;
      addContentIdentity(contentIdentities, frame.request);
      if (frame.frame_kind === "action" && frame.response !== null) {
        addContentIdentity(contentIdentities, frame.response);
      }
      const pair = pairs.get(frame.occurrence_sha256) ?? {
        decision: null,
        action: null,
        decisionIndex: null,
        actionIndex: null,
      };
      if (frame.frame_kind === "decision") {
        if (pair.decision !== null) blockers.push(`gateway_decision_duplicate:${frame.occurrence_sha256}`);
        pair.decision = frame;
        pair.decisionIndex = index;
        const attempts = logicalAttempts.get(frame.logical_request_id) ?? new Map<number, string>();
        if (attempts.has(frame.attempt_number)) {
          blockers.push(`gateway_logical_attempt_duplicate:${frame.logical_request_id}:${frame.attempt_number}`);
        }
        attempts.set(frame.attempt_number, frame.occurrence_sha256);
        logicalAttempts.set(frame.logical_request_id, attempts);
      } else {
        if (pair.action !== null) blockers.push(`gateway_action_duplicate:${frame.occurrence_sha256}`);
        pair.action = frame;
        pair.actionIndex = index;
        if (frame.outcome === "identity_mismatch") {
          blockers.push(`gateway_identity_mismatch_recorded:${frame.occurrence_sha256}`);
        }
      }
      pairs.set(frame.occurrence_sha256, pair);
    } catch {
      blockers.push(`gateway_frame_shape_unreadable:${index}`);
    }
  });

  for (const [occurrence, pair] of pairs) {
    if (pair.decision === null) {
      blockers.push(`gateway_decision_missing:${occurrence}`);
      continue;
    }
    if (pair.action === null) {
      blockers.push(`gateway_action_missing:${occurrence}`);
      continue;
    }
    if ((pair.actionIndex ?? -1) <= (pair.decisionIndex ?? -1)) {
      blockers.push(`gateway_action_precedes_decision:${occurrence}`);
    }
    if (
      pair.action.provider !== pair.decision.provider ||
      pair.action.requested_model !== pair.decision.requested_model ||
      pair.action.logical_request_id !== pair.decision.logical_request_id ||
      pair.action.attempt_number !== pair.decision.attempt_number ||
      pair.action.retry_of_occurrence_sha256 !== pair.decision.retry_of_occurrence_sha256 ||
      canonicalJson(pair.action.request) !== canonicalJson(pair.decision.request)
    ) {
      blockers.push(`gateway_attempt_pair_binding_mismatch:${occurrence}`);
    }
    if (pair.action.policy_receipt_sha256 !== pair.decision.policy.receipt_sha256) {
      blockers.push(`gateway_action_policy_binding_mismatch:${occurrence}`);
    }
    const expectedCensor =
      pair.decision.policy.decision === "blocked"
        ? pair.decision.policy.censor_kind === "budget"
          ? "budget_censored"
          : "policy_censored"
        : null;
    if (
      (expectedCensor !== null && pair.action.outcome !== expectedCensor) ||
      (expectedCensor === null && ["budget_censored", "policy_censored"].includes(pair.action.outcome))
    ) {
      blockers.push(`gateway_policy_outcome_mismatch:${occurrence}`);
    }
    if (
      expectedCensor !== null &&
      pair.action.failure_code !== null &&
      !pair.decision.policy.reason_codes.includes(pair.action.failure_code)
    ) {
      blockers.push(`gateway_censor_reason_not_in_policy:${occurrence}`);
    }
    if (
      pair.action.dispatch_started_at !== null &&
      pair.decision.policy.evaluated_at > pair.action.dispatch_started_at
    ) {
      blockers.push(`gateway_policy_not_pre_dispatch:${occurrence}`);
    }
  }

  for (const [logicalId, attempts] of logicalAttempts) {
    for (const [attemptNumber, occurrence] of attempts) {
      const decision = pairs.get(occurrence)?.decision;
      if (!decision) continue;
      if (attemptNumber > 1) {
        const expectedParent = attempts.get(attemptNumber - 1);
        if (!expectedParent) blockers.push(`gateway_retry_predecessor_missing:${logicalId}:${attemptNumber}`);
        else if (decision.retry_of_occurrence_sha256 !== expectedParent) {
          blockers.push(`gateway_retry_predecessor_mismatch:${logicalId}:${attemptNumber}`);
        }
      }
    }
  }

  if (manifest.frame_count !== frames.length) blockers.push("gateway_manifest_frame_count_mismatch");
  if (manifest.attempt_count !== [...pairs.values()].filter((pair) => pair.action !== null).length) {
    blockers.push("gateway_manifest_attempt_count_mismatch");
  }
  if (manifest.chain_head_sha256 !== head) blockers.push("gateway_manifest_chain_head_mismatch");
  if (manifest.status !== "finalized") blockers.push("gateway_bundle_not_finalized");
  if (frames.length === 0) blockers.push("gateway_frame_log_empty");
  const terminalObservedAt = frames.at(-1)?.observed_at;
  if (manifest.finalized_at && terminalObservedAt && manifest.finalized_at < terminalObservedAt) {
    blockers.push("gateway_bundle_finalized_before_last_frame");
  }
  const firstObservedAt = frames[0]?.observed_at;
  if (firstObservedAt && manifest.created_at > firstObservedAt) {
    blockers.push("gateway_bundle_created_after_first_frame");
  }
  return result(blockers, manifest.session_id, frames.length, isSha256(head) ? head : null, contentIdentities.size);
}

function gatewayManifestBlockers(manifest: GatewayEvidenceBundleManifest): string[] {
  const blockers: string[] = [];
  const expected = [
    "attempt_count",
    "bypass_declaration",
    "bypass_possible",
    "capture_boundary",
    "capture_mode",
    "chain_head_sha256",
    "coverage",
    "created_at",
    "finalized_at",
    "frame_count",
    "guard_version",
    "schema_version",
    "session_id",
    "status",
  ].sort();
  const actual = Object.keys(manifest).sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    blockers.push("gateway_bundle_fields_invalid");
  }
  if (manifest.schema_version !== GATEWAY_BUNDLE_SCHEMA_VERSION) blockers.push("gateway_bundle_schema_invalid");
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(manifest.guard_version)) {
    blockers.push("gateway_bundle_guard_version_invalid");
  }
  try {
    assertStableId(manifest.session_id, "session_id");
  } catch {
    blockers.push("gateway_bundle_session_id_invalid");
  }
  if (manifest.capture_mode !== "digest-only") blockers.push("gateway_bundle_raw_retention_refused");
  if (manifest.capture_boundary !== "explicit_recorder") blockers.push("gateway_bundle_boundary_invalid");
  if (
    manifest.bypass_possible !== true ||
    manifest.bypass_declaration !== "calls_outside_this_recorder_are_not_observed"
  ) {
    blockers.push("gateway_bundle_bypass_declaration_invalid");
  }
  const coverageKeys = Object.keys(manifest.coverage).sort();
  const expectedCoverageKeys = [
    "full_world_capture",
    "isolation_enforced",
    "observed_surfaces",
    "schema_version",
    "tier",
    "unobserved_surfaces",
    "visibility_boundary_enforced",
  ].sort();
  if (
    coverageKeys.length !== expectedCoverageKeys.length ||
    coverageKeys.some((key, index) => key !== expectedCoverageKeys[index])
  ) {
    blockers.push("gateway_bundle_coverage_fields_invalid");
  }
  blockers.push(...coverageBlockers(manifest.coverage));
  if (manifest.coverage.tier !== "gateway") blockers.push("gateway_bundle_coverage_tier_invalid");
  if (!Number.isSafeInteger(manifest.frame_count) || manifest.frame_count < 0) {
    blockers.push("gateway_bundle_frame_count_invalid");
  }
  if (!Number.isSafeInteger(manifest.attempt_count) || manifest.attempt_count < 0) {
    blockers.push("gateway_bundle_attempt_count_invalid");
  }
  if (!isSha256(manifest.chain_head_sha256)) blockers.push("gateway_bundle_chain_head_invalid");
  if (!validTimestamp(manifest.created_at)) blockers.push("gateway_bundle_created_at_invalid");
  if (
    manifest.finalized_at !== null &&
    (!validTimestamp(manifest.finalized_at) || manifest.finalized_at < manifest.created_at)
  ) {
    blockers.push("gateway_bundle_finalized_at_invalid");
  }
  if (!["recording", "finalized"].includes(manifest.status)) blockers.push("gateway_bundle_status_invalid");
  if (manifest.status === "recording" && manifest.finalized_at !== null) {
    blockers.push("gateway_bundle_recording_finalized_conflict");
  }
  if (manifest.status === "finalized" && manifest.finalized_at === null) {
    blockers.push("gateway_bundle_finalization_incomplete");
  }
  return blockers;
}

function addContentIdentity(
  identities: Set<string>,
  reference: { plaintext_sha256: string; byte_length: number; media_type: string },
): void {
  identities.add(`${reference.plaintext_sha256}:${reference.byte_length}:${reference.media_type}`);
}

function validTimestamp(value: string): boolean {
  return Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}

function result(
  blockers: readonly string[],
  sessionId: string | null,
  frameCount: number,
  chainHead: string | null,
  unavailable: number,
): VerificationResult {
  return {
    ok: blockers.length === 0,
    blockers: [...new Set(blockers)].sort(),
    session_id: sessionId,
    frame_count: frameCount,
    chain_head_sha256: chainHead,
    payloads_checked: 0,
    payloads_unavailable: unavailable,
  };
}
