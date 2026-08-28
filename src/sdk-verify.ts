import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalJson, isSha256 } from "./canonical.js";
import { coverageBlockers } from "./coverage.js";
import { assertStableId } from "./security.js";
import { sdkFrameBlockers } from "./sdk.js";
import {
  GENESIS_SHA256,
  SDK_BUNDLE_SCHEMA_VERSION,
  type ContentReference,
  type SdkActionFrame,
  type SdkDecisionFrame,
  type SdkEvidenceBundleManifest,
  type SdkEvidenceFrame,
  type VerificationResult,
} from "./types.js";

interface OperationPair {
  decision: SdkDecisionFrame | null;
  action: SdkActionFrame | null;
  decisionIndex: number | null;
  actionIndex: number | null;
}

export function verifySdkBundle(directory: string): VerificationResult {
  const blockers: string[] = [];
  let manifest: SdkEvidenceBundleManifest;
  try {
    manifest = JSON.parse(readFileSync(join(directory, "bundle.json"), "utf8")) as SdkEvidenceBundleManifest;
  } catch {
    return result(["sdk_bundle_manifest_unreadable"], null, 0, null, 0);
  }
  try {
    blockers.push(...sdkManifestBlockers(manifest));
  } catch {
    blockers.push("sdk_bundle_manifest_shape_invalid");
  }

  let frames: SdkEvidenceFrame[] = [];
  try {
    const text = readFileSync(join(directory, "frames.ndjson"), "utf8");
    if (text && !text.endsWith("\n")) blockers.push("sdk_frame_log_truncated");
    frames = text
      .split("\n")
      .filter((line) => line.length > 0)
      .map((line, index) => {
        try {
          return JSON.parse(line) as SdkEvidenceFrame;
        } catch {
          blockers.push(`sdk_frame_json_invalid:${index}`);
          return null;
        }
      })
      .filter((frame): frame is SdkEvidenceFrame => frame !== null);
  } catch {
    blockers.push("sdk_frame_log_unreadable");
  }

  let head: string = GENESIS_SHA256;
  let previousObservedAt: string | null = null;
  const pairs = new Map<string, OperationPair>();
  const logicalAttempts = new Map<string, Map<number, SdkDecisionFrame>>();
  const decisionIndices = new Map<string, number>();
  const contentIdentities = new Set<string>();

  frames.forEach((frame, index) => {
    try {
      blockers.push(...sdkFrameBlockers(frame).map((item) => `${item}:${index}`));
      if (frame.session_id !== manifest.session_id) blockers.push(`sdk_frame_session_mismatch:${index}`);
      if (canonicalJson(frame.coverage) !== canonicalJson(manifest.coverage)) {
        blockers.push(`sdk_frame_bundle_coverage_mismatch:${index}`);
      }
      if (frame.sequence !== index) blockers.push(`sdk_frame_sequence_gap:${index}`);
      if (frame.previous_frame_sha256 !== head) blockers.push(`sdk_frame_previous_hash_mismatch:${index}`);
      if (isSha256(frame.frame_sha256)) head = frame.frame_sha256;
      if (previousObservedAt !== null && frame.observed_at < previousObservedAt) {
        blockers.push(`sdk_frame_timestamp_regressed:${index}`);
      }
      previousObservedAt = frame.observed_at;
      addContentIdentity(contentIdentities, operationInput(frame));
      if (frame.frame_kind === "action") {
        const output = operationOutput(frame);
        if (output !== null) addContentIdentity(contentIdentities, output);
      }
      const pair = pairs.get(frame.occurrence_sha256) ?? emptyPair();
      if (frame.frame_kind === "decision") {
        if (pair.decision !== null) blockers.push(`sdk_decision_duplicate:${frame.occurrence_sha256}`);
        pair.decision = frame;
        pair.decisionIndex = index;
        decisionIndices.set(frame.occurrence_sha256, index);
        const attempts = logicalAttempts.get(frame.logical_operation_id) ?? new Map<number, SdkDecisionFrame>();
        if (attempts.has(frame.attempt_number)) {
          blockers.push(`sdk_logical_attempt_duplicate:${frame.logical_operation_id}:${frame.attempt_number}`);
        }
        attempts.set(frame.attempt_number, frame);
        logicalAttempts.set(frame.logical_operation_id, attempts);
      } else {
        if (pair.action !== null) blockers.push(`sdk_action_duplicate:${frame.occurrence_sha256}`);
        pair.action = frame;
        pair.actionIndex = index;
        if (frame.outcome === "identity_mismatch") {
          blockers.push(`sdk_identity_mismatch_recorded:${frame.occurrence_sha256}`);
        }
      }
      pairs.set(frame.occurrence_sha256, pair);
    } catch {
      blockers.push(`sdk_frame_shape_unreadable:${index}`);
    }
  });

  for (const [occurrence, pair] of pairs) {
    if (pair.decision === null) {
      blockers.push(`sdk_decision_missing:${occurrence}`);
      continue;
    }
    if (pair.action === null) {
      blockers.push(`sdk_action_missing:${occurrence}`);
      continue;
    }
    if ((pair.actionIndex ?? -1) <= (pair.decisionIndex ?? -1)) {
      blockers.push(`sdk_action_precedes_decision:${occurrence}`);
    }
    if (!pairBindingsMatch(pair.decision, pair.action)) {
      blockers.push(`sdk_operation_pair_binding_mismatch:${occurrence}`);
    }
    if (pair.action.policy_receipt_sha256 !== pair.decision.policy.receipt_sha256) {
      blockers.push(`sdk_action_policy_binding_mismatch:${occurrence}`);
    }
    const expectedCensor =
      pair.decision.policy.decision === "blocked"
        ? pair.decision.policy.censor_kind === "budget"
          ? "budget_censored"
          : pair.decision.policy.censor_kind === "authority"
            ? "authority_censored"
            : "policy_censored"
        : null;
    if (
      (expectedCensor !== null && pair.action.outcome !== expectedCensor) ||
      (expectedCensor === null && ["budget_censored", "authority_censored", "policy_censored"].includes(pair.action.outcome))
    ) {
      blockers.push(`sdk_policy_outcome_mismatch:${occurrence}`);
    }
    if (
      expectedCensor !== null &&
      pair.action.failure_code !== null &&
      !pair.decision.policy.reason_codes.includes(pair.action.failure_code)
    ) {
      blockers.push(`sdk_censor_reason_not_in_policy:${occurrence}`);
    }
    if (
      pair.action.dispatch_started_at !== null &&
      pair.decision.policy.evaluated_at > pair.action.dispatch_started_at
    ) {
      blockers.push(`sdk_policy_not_pre_dispatch:${occurrence}`);
    }
    if (pair.decision.parent_occurrence_sha256 !== null) {
      const parentIndex = decisionIndices.get(pair.decision.parent_occurrence_sha256);
      if (parentIndex === undefined) blockers.push(`sdk_parent_occurrence_missing:${occurrence}`);
      else if (parentIndex >= (pair.decisionIndex ?? -1)) blockers.push(`sdk_parent_not_prior:${occurrence}`);
    }
  }

  for (const [logicalId, attempts] of logicalAttempts) {
    for (const [attemptNumber, decision] of attempts) {
      if (attemptNumber === 1) continue;
      const predecessor = attempts.get(attemptNumber - 1);
      if (!predecessor) blockers.push(`sdk_retry_predecessor_missing:${logicalId}:${attemptNumber}`);
      else {
        if (decision.retry_of_occurrence_sha256 !== predecessor.occurrence_sha256) {
          blockers.push(`sdk_retry_predecessor_mismatch:${logicalId}:${attemptNumber}`);
        }
        if (!retryContextMatches(predecessor, decision)) {
          blockers.push(`sdk_retry_identity_context_mismatch:${logicalId}:${attemptNumber}`);
        }
      }
    }
  }

  if (manifest.frame_count !== frames.length) blockers.push("sdk_manifest_frame_count_mismatch");
  if (manifest.operation_count !== [...pairs.values()].filter((pair) => pair.action !== null).length) {
    blockers.push("sdk_manifest_operation_count_mismatch");
  }
  if (manifest.chain_head_sha256 !== head) blockers.push("sdk_manifest_chain_head_mismatch");
  if (manifest.status !== "finalized") blockers.push("sdk_bundle_not_finalized");
  if (frames.length === 0) blockers.push("sdk_frame_log_empty");
  const terminalObservedAt = frames.at(-1)?.observed_at;
  if (manifest.finalized_at && terminalObservedAt && manifest.finalized_at < terminalObservedAt) {
    blockers.push("sdk_bundle_finalized_before_last_frame");
  }
  const firstObservedAt = frames[0]?.observed_at;
  if (firstObservedAt && manifest.created_at > firstObservedAt) {
    blockers.push("sdk_bundle_created_after_first_frame");
  }
  return result(blockers, manifest.session_id, frames.length, isSha256(head) ? head : null, contentIdentities.size);
}

function sdkManifestBlockers(manifest: SdkEvidenceBundleManifest): string[] {
  const blockers: string[] = [];
  const expected = [
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
    "operation_count",
    "schema_version",
    "session_id",
    "status",
  ].sort();
  const actual = Object.keys(manifest).sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    blockers.push("sdk_bundle_fields_invalid");
  }
  if (manifest.schema_version !== SDK_BUNDLE_SCHEMA_VERSION) blockers.push("sdk_bundle_schema_invalid");
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(manifest.guard_version)) {
    blockers.push("sdk_bundle_guard_version_invalid");
  }
  try {
    assertStableId(manifest.session_id, "session_id");
  } catch {
    blockers.push("sdk_bundle_session_id_invalid");
  }
  if (manifest.capture_mode !== "digest-only") blockers.push("sdk_bundle_raw_retention_refused");
  if (manifest.capture_boundary !== "explicit_sdk") blockers.push("sdk_bundle_boundary_invalid");
  if (
    manifest.bypass_possible !== true ||
    manifest.bypass_declaration !== "uninstrumented_or_direct_io_is_not_observed"
  ) {
    blockers.push("sdk_bundle_bypass_declaration_invalid");
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
    blockers.push("sdk_bundle_coverage_fields_invalid");
  }
  blockers.push(...coverageBlockers(manifest.coverage));
  if (manifest.coverage.tier !== "sdk") blockers.push("sdk_bundle_coverage_tier_invalid");
  if (!Number.isSafeInteger(manifest.frame_count) || manifest.frame_count < 0) {
    blockers.push("sdk_bundle_frame_count_invalid");
  }
  if (!Number.isSafeInteger(manifest.operation_count) || manifest.operation_count < 0) {
    blockers.push("sdk_bundle_operation_count_invalid");
  }
  if (!isSha256(manifest.chain_head_sha256)) blockers.push("sdk_bundle_chain_head_invalid");
  if (!validTimestamp(manifest.created_at)) blockers.push("sdk_bundle_created_at_invalid");
  if (
    manifest.finalized_at !== null &&
    (!validTimestamp(manifest.finalized_at) || manifest.finalized_at < manifest.created_at)
  ) {
    blockers.push("sdk_bundle_finalized_at_invalid");
  }
  if (!["recording", "finalized"].includes(manifest.status)) blockers.push("sdk_bundle_status_invalid");
  if (manifest.status === "recording" && manifest.finalized_at !== null) {
    blockers.push("sdk_bundle_recording_finalized_conflict");
  }
  if (manifest.status === "finalized" && manifest.finalized_at === null) {
    blockers.push("sdk_bundle_finalization_incomplete");
  }
  return blockers;
}

function pairBindingsMatch(decision: SdkDecisionFrame, action: SdkActionFrame): boolean {
  if (
    decision.operation_kind !== action.operation_kind ||
    decision.actor_id !== action.actor_id ||
    decision.principal_id !== action.principal_id ||
    canonicalJson(decision.authority_scope_ids) !== canonicalJson(action.authority_scope_ids) ||
    decision.logical_operation_id !== action.logical_operation_id ||
    decision.attempt_number !== action.attempt_number ||
    decision.retry_of_occurrence_sha256 !== action.retry_of_occurrence_sha256 ||
    decision.parent_occurrence_sha256 !== action.parent_occurrence_sha256 ||
    canonicalJson(decision.state_root_before) !== canonicalJson(action.state_root_before)
  ) {
    return false;
  }
  if (decision.operation_kind === "application_decision" && action.operation_kind === "application_decision") {
    return (
      canonicalJson(decision.decision_identity) === canonicalJson(action.decision_identity) &&
      canonicalJson(decision.decision_input) === canonicalJson(action.decision_input)
    );
  }
  if (decision.operation_kind === "registered_tool_call" && action.operation_kind === "registered_tool_call") {
    return (
      canonicalJson(decision.tool_identity) === canonicalJson(action.tool_identity) &&
      canonicalJson(decision.tool_request) === canonicalJson(action.tool_request)
    );
  }
  return false;
}

function retryContextMatches(first: SdkDecisionFrame, second: SdkDecisionFrame): boolean {
  if (
    first.operation_kind !== second.operation_kind ||
    first.actor_id !== second.actor_id ||
    first.principal_id !== second.principal_id ||
    canonicalJson(first.authority_scope_ids) !== canonicalJson(second.authority_scope_ids)
  ) {
    return false;
  }
  if (first.operation_kind === "application_decision" && second.operation_kind === "application_decision") {
    return canonicalJson(first.decision_identity) === canonicalJson(second.decision_identity);
  }
  if (first.operation_kind === "registered_tool_call" && second.operation_kind === "registered_tool_call") {
    return canonicalJson(first.tool_identity) === canonicalJson(second.tool_identity);
  }
  return false;
}

function operationInput(frame: SdkEvidenceFrame): ContentReference {
  return frame.operation_kind === "application_decision" ? frame.decision_input : frame.tool_request;
}

function operationOutput(frame: SdkActionFrame): ContentReference | null {
  return frame.operation_kind === "application_decision" ? frame.decision_output : frame.tool_result;
}

function addContentIdentity(identities: Set<string>, reference: ContentReference): void {
  identities.add(`${reference.plaintext_sha256}:${reference.byte_length}:${reference.media_type}`);
}

function emptyPair(): OperationPair {
  return { decision: null, action: null, decisionIndex: null, actionIndex: null };
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
