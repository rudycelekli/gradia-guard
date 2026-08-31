import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalJson, compareCanonicalStrings, digestCanonical } from "./canonical.js";
import { sdkFrameBlockers } from "./sdk.js";
import { verifySdkBundle } from "./sdk-verify.js";
import {
  GENESIS_SHA256,
  type SdkActionFrame,
  type SdkDecisionFrame,
  type SdkEvidenceFrame,
  type SdkOutcome,
  type VerificationResult,
} from "./types.js";

export const SDK_ACTOR_GRAPH_SCHEMA_VERSION = "gradia.guard.sdk-actor-graph.v1" as const;

export interface SdkActorGraphActor {
  actor_id: string;
  declared_principal_ids: readonly string[];
  declared_principal_count: number;
  operation_count: number;
  dispatched_operation_count: number;
  root_operation_count: number;
  inbound_cross_actor_edge_count: number;
  outbound_cross_actor_edge_count: number;
  maximum_declared_parent_depth: number;
}

export interface SdkActorGraphEdge {
  parent_occurrence_sha256: string;
  child_occurrence_sha256: string;
  source_actor_id: string;
  target_actor_id: string;
  cross_actor: boolean;
  parent_dispatch_occurred: boolean;
  parent_outcome: SdkOutcome;
  parent_terminal_preceded_child_decision: boolean;
}

export interface SdkActorGraphReportBody {
  schema_version: typeof SDK_ACTOR_GRAPH_SCHEMA_VERSION;
  claim_boundary: "application_declared_parentage_only_no_delegation_causal_contribution_or_quality_claim";
  identity_boundary: "actor_and_principal_ids_are_application_declared_not_authenticated";
  metadata_boundary: "payload_bytes_absent_actor_and_principal_ids_emitted_as_plaintext_metadata";
  session_id: string;
  bundle_chain_head_sha256: string;
  actor_count: number;
  operation_count: number;
  root_operation_count: number;
  parent_edge_count: number;
  cross_actor_edge_count: number;
  maximum_declared_parent_depth: number;
  actors: readonly SdkActorGraphActor[];
  edges: readonly SdkActorGraphEdge[];
}

export interface SdkActorGraphReport extends SdkActorGraphReportBody {
  report_sha256: string;
}

/**
 * Verify an SDK bundle, then derive a payload-free actor/parentage graph.
 *
 * This is intentionally useful in the account-free edition: a team can see
 * which actor and principal labels the application declared and how it linked
 * operations without uploading prompts or outputs. These labels are not
 * authenticated by G2, and a parent link proves neither delegation nor causal
 * contribution. Raw actor/principal labels remain plaintext metadata.
 */
export function analyzeSdkActorGraph(directory: string): SdkActorGraphReport {
  const verification = verifySdkBundle(directory);
  if (!verification.ok || verification.session_id === null || verification.chain_head_sha256 === null) {
    throw new Error(`sdk_actor_graph_bundle_unverified:${verification.blockers.join(",")}`);
  }
  const frames = readSdkFrames(directory);
  assertFrameSnapshotMatchesVerification(frames, verification);
  const decisions = frames.filter((frame): frame is SdkDecisionFrame => frame.frame_kind === "decision");
  const byOccurrence = new Map(decisions.map((row) => [row.occurrence_sha256, row] as const));
  const actionsByOccurrence = new Map(
    frames
      .filter((frame): frame is SdkActionFrame => frame.frame_kind === "action")
      .map((row) => [row.occurrence_sha256, row] as const),
  );
  const frameIndices = new Map(
    frames.map((row, index) => [`${row.frame_kind}:${row.occurrence_sha256}`, index] as const),
  );
  const depths = new Map<string, number>();
  const edges: SdkActorGraphEdge[] = [];
  const actorRows = new Map<
    string,
    {
      principals: Set<string>;
      operations: number;
      dispatched: number;
      roots: number;
      inbound: number;
      outbound: number;
      maximumDepth: number;
    }
  >();
  const actor = (actorId: string) => {
    const current = actorRows.get(actorId) ?? {
      principals: new Set<string>(),
      operations: 0,
      dispatched: 0,
      roots: 0,
      inbound: 0,
      outbound: 0,
      maximumDepth: 0,
    };
    actorRows.set(actorId, current);
    return current;
  };

  for (const decision of decisions) {
    const current = actor(decision.actor_id);
    current.principals.add(decision.principal_id);
    current.operations += 1;
    const action = actionsByOccurrence.get(decision.occurrence_sha256);
    if (!action) throw new Error("sdk_actor_graph_action_missing_after_verification");
    if (action.dispatch_occurred) current.dispatched += 1;
    let depth = 0;
    if (decision.parent_occurrence_sha256 === null) {
      current.roots += 1;
    } else {
      const parent = byOccurrence.get(decision.parent_occurrence_sha256);
      if (!parent) throw new Error("sdk_actor_graph_parent_missing_after_verification");
      const parentDepth = depths.get(parent.occurrence_sha256);
      if (parentDepth === undefined) {
        throw new Error("sdk_actor_graph_parent_not_prior_after_verification");
      }
      const parentAction = actionsByOccurrence.get(parent.occurrence_sha256);
      if (!parentAction) throw new Error("sdk_actor_graph_parent_action_missing_after_verification");
      const parentActionIndex = frameIndices.get(`action:${parent.occurrence_sha256}`);
      const childDecisionIndex = frameIndices.get(`decision:${decision.occurrence_sha256}`);
      if (parentActionIndex === undefined || childDecisionIndex === undefined) {
        throw new Error("sdk_actor_graph_frame_index_missing_after_verification");
      }
      depth = parentDepth + 1;
      const crossActor = parent.actor_id !== decision.actor_id;
      if (crossActor) {
        actor(parent.actor_id).outbound += 1;
        current.inbound += 1;
      }
      edges.push({
        parent_occurrence_sha256: parent.occurrence_sha256,
        child_occurrence_sha256: decision.occurrence_sha256,
        source_actor_id: parent.actor_id,
        target_actor_id: decision.actor_id,
        cross_actor: crossActor,
        parent_dispatch_occurred: parentAction.dispatch_occurred,
        parent_outcome: parentAction.outcome,
        parent_terminal_preceded_child_decision: parentActionIndex < childDecisionIndex,
      });
    }
    depths.set(decision.occurrence_sha256, depth);
    current.maximumDepth = Math.max(current.maximumDepth, depth);
  }

  const actors = [...actorRows.entries()]
    .sort(([left], [right]) => compareCanonicalStrings(left, right))
    .map(([actorId, row]): SdkActorGraphActor => ({
      actor_id: actorId,
      declared_principal_ids: [...row.principals].sort(),
      declared_principal_count: row.principals.size,
      operation_count: row.operations,
      dispatched_operation_count: row.dispatched,
      root_operation_count: row.roots,
      inbound_cross_actor_edge_count: row.inbound,
      outbound_cross_actor_edge_count: row.outbound,
      maximum_declared_parent_depth: row.maximumDepth,
    }));
  edges.sort((left, right) =>
    compareCanonicalStrings(left.child_occurrence_sha256, right.child_occurrence_sha256),
  );
  const body: SdkActorGraphReportBody = {
    schema_version: SDK_ACTOR_GRAPH_SCHEMA_VERSION,
    claim_boundary:
      "application_declared_parentage_only_no_delegation_causal_contribution_or_quality_claim",
    identity_boundary: "actor_and_principal_ids_are_application_declared_not_authenticated",
    metadata_boundary:
      "payload_bytes_absent_actor_and_principal_ids_emitted_as_plaintext_metadata",
    session_id: verification.session_id,
    bundle_chain_head_sha256: verification.chain_head_sha256,
    actor_count: actors.length,
    operation_count: decisions.length,
    root_operation_count: decisions.filter((row) => row.parent_occurrence_sha256 === null).length,
    parent_edge_count: edges.length,
    cross_actor_edge_count: edges.filter((row) => row.cross_actor).length,
    maximum_declared_parent_depth: Math.max(0, ...depths.values()),
    actors,
    edges,
  };
  return { ...body, report_sha256: digestCanonical(body) };
}

export function canonicalSdkActorGraph(report: SdkActorGraphReport): string {
  return `${canonicalJson(report)}\n`;
}

export function formatSdkActorGraph(report: SdkActorGraphReport): string {
  const lines = [
    "Gradia Guard SDK declared-actor graph: SOURCE BUNDLE VERIFIED",
    `Session: ${report.session_id}`,
    `Actors: ${report.actor_count}`,
    `Operations: ${report.operation_count}`,
    `Declared parent links: ${report.parent_edge_count}`,
    `Cross-actor declared parent links: ${report.cross_actor_edge_count}`,
    `Maximum declared-parent depth: ${report.maximum_declared_parent_depth}`,
    "Declared actors:",
    ...report.actors.map(
      (row) =>
        `  - ${row.actor_id}: principals=${row.declared_principal_count}, operations=${row.operation_count}, dispatched=${row.dispatched_operation_count}, inbound=${row.inbound_cross_actor_edge_count}, outbound=${row.outbound_cross_actor_edge_count}, parent_depth=${row.maximum_declared_parent_depth}`,
    ),
    "Identity boundary: actor and principal IDs are application-declared, not authenticated by this graph.",
    "Metadata boundary: payload bytes are absent; actor and principal IDs remain plaintext metadata.",
    "Claim boundary: declared parent links only; no delegation, causal contribution, competence, or quality claim.",
    `Report SHA-256: ${report.report_sha256}`,
  ];
  return `${lines.join("\n")}\n`;
}

function readSdkFrames(directory: string): SdkEvidenceFrame[] {
  const text = readFileSync(join(directory, "frames.ndjson"), "utf8");
  return text
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as SdkEvidenceFrame);
}

/**
 * The verifier and analyzer intentionally read separately. Re-bind the exact
 * in-memory snapshot used for analysis to the verified frame count and chain
 * head so a concurrent file replacement cannot contribute unverified labels.
 */
function assertFrameSnapshotMatchesVerification(
  frames: readonly SdkEvidenceFrame[],
  verification: VerificationResult,
): void {
  if (frames.length !== verification.frame_count) {
    throw new Error("sdk_actor_graph_snapshot_frame_count_mismatch");
  }
  let head: string = GENESIS_SHA256;
  for (const [index, frame] of frames.entries()) {
    const blockers = sdkFrameBlockers(frame);
    if (blockers.length > 0) {
      throw new Error(`sdk_actor_graph_snapshot_frame_invalid:${index}:${blockers.join(",")}`);
    }
    if (frame.sequence !== index || frame.previous_frame_sha256 !== head) {
      throw new Error(`sdk_actor_graph_snapshot_chain_invalid:${index}`);
    }
    if (frame.session_id !== verification.session_id) {
      throw new Error(`sdk_actor_graph_snapshot_session_mismatch:${index}`);
    }
    head = frame.frame_sha256;
  }
  if (head !== verification.chain_head_sha256) {
    throw new Error("sdk_actor_graph_snapshot_chain_head_mismatch");
  }
}
