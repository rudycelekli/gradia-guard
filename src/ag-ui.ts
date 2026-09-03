import { EventSchemas } from "@ag-ui/core";
import { canonicalJson, digestCanonical, isSha256 } from "./canonical.js";

export const PROOF_BOUND_AG_UI_SCHEMA_VERSION = "proof-bound-ag-ui.v1" as const;
export const AG_UI_PYTHON_UPSTREAM_VERSION = "0.1.22" as const;
export const AG_UI_TYPESCRIPT_UPSTREAM_VERSION = "0.0.59" as const;
export const AG_UI_UPSTREAM_COMMIT =
  "3f38925d0e6c19bf1f19502ee12e410e772ac142" as const;
const MAX_AG_UI_SSE_FRAME_BYTES = 1_048_576;

export type ProofBoundAguiProjection = "agent" | "auditor";
export type ProofBoundAguiProposalKind =
  | "message"
  | "tool_call"
  | "approval"
  | "steer"
  | "cancel"
  | "state_patch";

export interface ProofBoundAguiProposalValue {
  schemaVersion: typeof PROOF_BOUND_AG_UI_SCHEMA_VERSION;
  proposalId: string;
  kind: ProofBoundAguiProposalKind;
  threadId: string;
  runId: string;
  projection: "agent";
  payload: Record<string, unknown>;
  contentSha256: string;
  requestedActionSha256?: string;
}

export interface ProofBoundAguiProposal {
  type: "CUSTOM";
  name: "gradia.proposal.v1";
  value: ProofBoundAguiProposalValue;
}

export interface VerifiedProofBoundAguiProposal {
  proposal: ProofBoundAguiProposal;
  proposalSha256: string;
  requestedActionSha256?: string;
}

export interface ProofBoundAguiSseEvent {
  id: string;
  event: Record<string, unknown>;
}

export interface ProofBoundAguiActionReceipt {
  schemaVersion: typeof PROOF_BOUND_AG_UI_SCHEMA_VERSION;
  receiptId: string;
  orgId: string;
  projectId: string;
  runId: string;
  proposalId: string;
  proposalSha256: string;
  requestedActionSha256: string;
  kind: "steer" | "cancel";
  decision: "approved" | "rejected";
  rationale: string;
  decidedBy: string;
  decidedAt: string;
  canonicalActionPersisted: boolean;
  externalEffectProved: false;
  effectStatus:
    | "rejected_no_effect"
    | "steering_signal_pending"
    | "job_cancel_requested"
    | "job_cancelled_before_start";
  effectReferenceType: "scenario_operator_signal" | "job" | null;
  effectReferenceId: string | null;
  effectSha256: string | null;
  claimBoundary: typeof AG_UI_ACTION_RECEIPT_CLAIM_BOUNDARY;
  receiptSha256: string;
}

export const AG_UI_ACTION_RECEIPT_CLAIM_BOUNDARY =
  "human_decision_and_local_canonical_action_persistence_not_external_effect_delivery_or_business_outcome" as const;

const PROPOSAL_KINDS = new Set<ProofBoundAguiProposalKind>([
  "message",
  "tool_call",
  "approval",
  "steer",
  "cancel",
  "state_patch",
]);

const EVENT_KEYS: Readonly<Record<string, readonly string[]>> = {
  RUN_STARTED: ["metadata", "runId", "threadId", "timestamp", "type"],
  RUN_FINISHED: ["metadata", "outcome", "result", "runId", "threadId", "timestamp", "type"],
  RUN_ERROR: ["code", "message", "metadata", "timestamp", "type"],
  STATE_SNAPSHOT: ["metadata", "snapshot", "timestamp", "type"],
  CUSTOM: ["metadata", "name", "timestamp", "type", "value"],
  TOOL_CALL_START: ["metadata", "timestamp", "toolCallId", "toolCallName", "type"],
  TOOL_CALL_ARGS: ["delta", "metadata", "timestamp", "toolCallId", "type"],
  TOOL_CALL_END: ["metadata", "timestamp", "toolCallId", "type"],
  TOOL_CALL_RESULT: [
    "content",
    "messageId",
    "metadata",
    "role",
    "timestamp",
    "toolCallId",
    "type",
  ],
};

const FRAME_BOUND_EVENT_TYPES = new Set([
  "STATE_SNAPSHOT",
  "CUSTOM",
  "TOOL_CALL_START",
  "TOOL_CALL_ARGS",
  "TOOL_CALL_END",
  "TOOL_CALL_RESULT",
]);

const BINDING_KEYS = [
  "authoritativeProjection",
  "episodeId",
  "logicalAct",
  "projection",
  "rawChainOfThoughtIncluded",
  "runId",
  "schemaVersion",
  "sideEffectFreeReplay",
  "source",
  "sourceFrameSha256",
  "sourceProjectionSha256",
  "sourceSequence",
  "taskId",
  "upstreamCommit",
  "upstreamVersion",
  "wireOrdinal",
] as const;

const FORBIDDEN_PROPOSAL_KEYS = new Set([
  "api_key",
  "apikey",
  "authorization",
  "authority",
  "bearer",
  "credential",
  "credentials",
  "password",
  "private_key",
  "receipt",
  "receipts",
  "root_auditor",
  "rootauditor",
  "secret",
  "signing_key",
  "token",
  "world_root",
  "worldroot",
]);

export function proofBoundAguiRequestedActionSha256(
  kind: Exclude<ProofBoundAguiProposalKind, "message">,
  payload: Record<string, unknown>,
): string {
  return digestCanonical({ kind, payload });
}

export function createProofBoundAguiProposal(input: {
  proposalId: string;
  kind: ProofBoundAguiProposalKind;
  runId: string;
  payload: Record<string, unknown>;
}): ProofBoundAguiProposal {
  assertBoundedId(input.proposalId, "ag_ui_proposal_id");
  assertBoundedId(input.runId, "ag_ui_run_id", 300);
  assertSafeProposalPayload(input.payload);
  const threadId = `gradia:${input.runId}`;
  const actionSha256 =
    input.kind === "message"
      ? undefined
      : proofBoundAguiRequestedActionSha256(input.kind, input.payload);
  const identity: Record<string, unknown> = {
    kind: input.kind,
    payload: input.payload,
    run_id: input.runId,
    thread_id: threadId,
  };
  if (actionSha256 !== undefined) identity["requested_action_sha256"] = actionSha256;
  const common = {
    schemaVersion: PROOF_BOUND_AG_UI_SCHEMA_VERSION,
    proposalId: input.proposalId,
    kind: input.kind,
    threadId,
    runId: input.runId,
    projection: "agent" as const,
    payload: input.payload,
    contentSha256: digestCanonical(identity),
  };
  return {
    type: "CUSTOM",
    name: "gradia.proposal.v1",
    value:
      actionSha256 === undefined
        ? common
        : { ...common, requestedActionSha256: actionSha256 },
  };
}

export function verifyProofBoundAguiProposal(
  value: unknown,
  expectedRunId: string,
): VerifiedProofBoundAguiProposal {
  if (!record(value)) throw new Error("ag_ui_proposal_shape_invalid");
  exactKeys(value, ["name", "type", "value"], "ag_ui_proposal");
  if (value["type"] !== "CUSTOM" || value["name"] !== "gradia.proposal.v1") {
    throw new Error("ag_ui_proposal_event_type_invalid");
  }
  const parsedEvent = EventSchemas.safeParse(value);
  if (!parsedEvent.success) throw new Error("ag_ui_proposal_upstream_event_invalid");
  const raw = value["value"];
  if (!record(raw)) throw new Error("ag_ui_proposal_value_invalid");
  const hasAction = Object.hasOwn(raw, "requestedActionSha256");
  exactKeys(
    raw,
    [
      "contentSha256",
      "kind",
      "payload",
      "projection",
      "proposalId",
      ...(hasAction ? ["requestedActionSha256"] : []),
      "runId",
      "schemaVersion",
      "threadId",
    ],
    "ag_ui_proposal_value",
  );
  if (raw["schemaVersion"] !== PROOF_BOUND_AG_UI_SCHEMA_VERSION) {
    throw new Error("ag_ui_proposal_schema_invalid");
  }
  if (typeof raw["kind"] !== "string" || !PROPOSAL_KINDS.has(raw["kind"] as ProofBoundAguiProposalKind)) {
    throw new Error("ag_ui_proposal_kind_invalid");
  }
  const kind = raw["kind"] as ProofBoundAguiProposalKind;
  for (const [field, limit] of [
    ["proposalId", 200],
    ["runId", 300],
    ["threadId", 300],
  ] as const) {
    if (typeof raw[field] !== "string") throw new Error(`ag_ui_${field}_invalid`);
    assertBoundedId(raw[field], `ag_ui_${field}`, limit);
  }
  if (raw["runId"] !== expectedRunId) throw new Error("ag_ui_proposal_run_mismatch");
  if (raw["threadId"] !== `gradia:${expectedRunId}`) {
    throw new Error("ag_ui_proposal_thread_mismatch");
  }
  if (raw["projection"] !== "agent") throw new Error("ag_ui_proposal_projection_invalid");
  if (!record(raw["payload"])) throw new Error("ag_ui_proposal_payload_invalid");
  assertSafeProposalPayload(raw["payload"]);
  if (!isSha256(raw["contentSha256"])) throw new Error("ag_ui_proposal_content_digest_invalid");
  const proposalId = raw["proposalId"] as string;
  const runId = raw["runId"] as string;
  const threadId = raw["threadId"] as string;

  let requestedActionSha256: string | undefined;
  if (kind === "message") {
    if (hasAction) throw new Error("ag_ui_proposal_action_digest_unexpected");
  } else {
    if (!isSha256(raw["requestedActionSha256"])) {
      throw new Error("ag_ui_proposal_action_digest_required");
    }
    requestedActionSha256 = raw["requestedActionSha256"];
    const expected = proofBoundAguiRequestedActionSha256(kind, raw["payload"]);
    if (requestedActionSha256 !== expected) {
      throw new Error("ag_ui_proposal_action_digest_mismatch");
    }
  }
  const identity: Record<string, unknown> = {
    kind,
    payload: raw["payload"],
    run_id: runId,
    thread_id: threadId,
  };
  if (requestedActionSha256 !== undefined) {
    identity["requested_action_sha256"] = requestedActionSha256;
  }
  if (raw["contentSha256"] !== digestCanonical(identity)) {
    throw new Error("ag_ui_proposal_content_digest_mismatch");
  }
  const proposal = createProofBoundAguiProposal({
    proposalId,
    kind,
    runId,
    payload: raw["payload"],
  });
  if (canonicalJson(proposal) !== canonicalJson(value)) {
    throw new Error("ag_ui_proposal_noncanonical_shape");
  }
  return {
    proposal,
    proposalSha256: digestCanonical(proposal),
    ...(requestedActionSha256 === undefined ? {} : { requestedActionSha256 }),
  };
}

export function verifyProofBoundAguiActionReceipt(
  value: unknown,
  expected: {
    runId: string;
    proposal: ProofBoundAguiProposal;
    decision?: "approved" | "rejected";
  },
): ProofBoundAguiActionReceipt {
  if (!record(value)) throw new Error("ag_ui_action_receipt_shape_invalid");
  exactKeys(
    value,
    [
      "canonicalActionPersisted",
      "claimBoundary",
      "decidedAt",
      "decidedBy",
      "decision",
      "effectReferenceId",
      "effectReferenceType",
      "effectSha256",
      "effectStatus",
      "externalEffectProved",
      "kind",
      "orgId",
      "projectId",
      "proposalId",
      "proposalSha256",
      "rationale",
      "receiptId",
      "receiptSha256",
      "requestedActionSha256",
      "runId",
      "schemaVersion",
    ],
    "ag_ui_action_receipt",
  );
  if (value["schemaVersion"] !== PROOF_BOUND_AG_UI_SCHEMA_VERSION) {
    throw new Error("ag_ui_action_receipt_schema_invalid");
  }
  if (value["claimBoundary"] !== AG_UI_ACTION_RECEIPT_CLAIM_BOUNDARY) {
    throw new Error("ag_ui_action_receipt_claim_boundary_invalid");
  }
  if (value["externalEffectProved"] !== false) {
    throw new Error("ag_ui_action_receipt_external_effect_overclaim");
  }
  for (const [field, limit] of [
    ["receiptId", 32],
    ["orgId", 32],
    ["projectId", 32],
    ["runId", 32],
    ["proposalId", 200],
    ["decidedBy", 32],
  ] as const) {
    if (typeof value[field] !== "string") throw new Error(`ag_ui_action_receipt_${field}_invalid`);
    assertBoundedId(value[field], `ag_ui_action_receipt_${field}`, limit);
  }
  if (value["runId"] !== expected.runId) throw new Error("ag_ui_action_receipt_run_mismatch");
  if (typeof value["rationale"] !== "string" || value["rationale"].length < 3 || value["rationale"].length > 4_000) {
    throw new Error("ag_ui_action_receipt_rationale_invalid");
  }
  if (
    typeof value["decidedAt"] !== "string" ||
    !/(?:Z|[+-]\d{2}:\d{2})$/.test(value["decidedAt"]) ||
    Number.isNaN(Date.parse(value["decidedAt"]))
  ) {
    throw new Error("ag_ui_action_receipt_decided_at_invalid");
  }
  for (const field of ["proposalSha256", "requestedActionSha256", "receiptSha256"] as const) {
    if (!isSha256(value[field])) throw new Error(`ag_ui_action_receipt_${field}_invalid`);
  }
  const verifiedProposal = verifyProofBoundAguiProposal(expected.proposal, expected.runId);
  if (
    value["proposalId"] !== verifiedProposal.proposal.value.proposalId ||
    value["proposalSha256"] !== verifiedProposal.proposalSha256 ||
    value["requestedActionSha256"] !== verifiedProposal.requestedActionSha256 ||
    value["kind"] !== verifiedProposal.proposal.value.kind
  ) {
    throw new Error("ag_ui_action_receipt_proposal_binding_mismatch");
  }
  if (value["kind"] !== "steer" && value["kind"] !== "cancel") {
    throw new Error("ag_ui_action_receipt_kind_invalid");
  }
  if (value["decision"] !== "approved" && value["decision"] !== "rejected") {
    throw new Error("ag_ui_action_receipt_decision_invalid");
  }
  if (expected.decision !== undefined && value["decision"] !== expected.decision) {
    throw new Error("ag_ui_action_receipt_decision_mismatch");
  }
  const references = [
    value["effectReferenceType"],
    value["effectReferenceId"],
    value["effectSha256"],
  ];
  const hasReferences = references.every((item) => item !== null);
  const hasNoReferences = references.every((item) => item === null);
  if (value["decision"] === "rejected") {
    if (
      value["canonicalActionPersisted"] !== false ||
      value["effectStatus"] !== "rejected_no_effect" ||
      !hasNoReferences
    ) {
      throw new Error("ag_ui_rejected_action_claims_effect");
    }
  } else {
    if (value["canonicalActionPersisted"] !== true || !hasReferences) {
      throw new Error("ag_ui_approved_action_missing_effect_reference");
    }
    if (typeof value["effectReferenceId"] !== "string" || !isSha256(value["effectSha256"])) {
      throw new Error("ag_ui_action_receipt_effect_reference_invalid");
    }
    assertBoundedId(value["effectReferenceId"], "ag_ui_action_receipt_effect_reference_id", 32);
    if (
      value["kind"] === "steer" &&
      (value["effectReferenceType"] !== "scenario_operator_signal" ||
        value["effectStatus"] !== "steering_signal_pending")
    ) {
      throw new Error("ag_ui_steering_effect_mismatch");
    }
    if (
      value["kind"] === "cancel" &&
      (value["effectReferenceType"] !== "job" ||
        (value["effectStatus"] !== "job_cancel_requested" &&
          value["effectStatus"] !== "job_cancelled_before_start"))
    ) {
      throw new Error("ag_ui_cancellation_effect_mismatch");
    }
  }
  const identity = { ...value };
  delete identity["receiptSha256"];
  if (value["receiptSha256"] !== digestCanonical(identity)) {
    throw new Error("ag_ui_action_receipt_digest_mismatch");
  }
  return value as unknown as ProofBoundAguiActionReceipt;
}

export function verifyProofBoundAguiEvent(value: unknown): Record<string, unknown> {
  if (!record(value)) throw new Error("ag_ui_event_shape_invalid");
  const type = value["type"];
  if (typeof type !== "string") throw new Error("ag_ui_event_type_invalid");
  if (type.startsWith("REASONING_") || type.startsWith("THINKING_")) {
    throw new Error("ag_ui_reasoning_event_forbidden");
  }
  const allowed = EVENT_KEYS[type];
  if (allowed === undefined) throw new Error("ag_ui_event_type_not_admitted");
  exactSubsetKeys(value, allowed, "ag_ui_event");
  if (Object.hasOwn(value, "rawEvent")) throw new Error("ag_ui_raw_event_forbidden");
  const parsed = EventSchemas.safeParse(value);
  if (!parsed.success) throw new Error("ag_ui_upstream_event_invalid");
  const metadata = value["metadata"];
  if (!record(metadata)) throw new Error("ag_ui_gradia_binding_missing");
  exactKeys(metadata, ["gradia"], "ag_ui_metadata");
  const binding = metadata["gradia"];
  if (!record(binding)) throw new Error("ag_ui_gradia_binding_missing");
  exactSubsetKeys(binding, BINDING_KEYS, "ag_ui_binding");
  for (const key of ["schemaVersion", "upstreamVersion", "upstreamCommit", "source", "projection", "runId"] as const) {
    if (typeof binding[key] !== "string") throw new Error(`ag_ui_binding_${key}_invalid`);
  }
  if (
    binding["schemaVersion"] !== PROOF_BOUND_AG_UI_SCHEMA_VERSION ||
    binding["upstreamVersion"] !== AG_UI_PYTHON_UPSTREAM_VERSION ||
    binding["upstreamCommit"] !== AG_UI_UPSTREAM_COMMIT
  ) {
    throw new Error("ag_ui_binding_upstream_invalid");
  }
  if (binding["source"] !== "verified_observatory" && binding["source"] !== "verification_refusal") {
    throw new Error("ag_ui_binding_source_invalid");
  }
  if (binding["projection"] !== "agent" && binding["projection"] !== "auditor") {
    throw new Error("ag_ui_binding_projection_invalid");
  }
  if (
    binding["authoritativeProjection"] !== true ||
    binding["sideEffectFreeReplay"] !== true ||
    binding["rawChainOfThoughtIncluded"] !== false ||
    !Number.isSafeInteger(binding["wireOrdinal"]) ||
    Number(binding["wireOrdinal"]) < 0
  ) {
    throw new Error("ag_ui_binding_claim_invalid");
  }
  const frameFields = [
    "episodeId",
    "logicalAct",
    "sourceFrameSha256",
    "sourceProjectionSha256",
    "sourceSequence",
    "taskId",
  ] as const;
  const populated = frameFields.map((key) => Object.hasOwn(binding, key));
  if (populated.some(Boolean) && !populated.every(Boolean)) {
    throw new Error("ag_ui_source_frame_binding_partial");
  }
  const frameBound = populated.every(Boolean);
  if (frameBound) {
    if (!isSha256(binding["sourceFrameSha256"]) || !isSha256(binding["sourceProjectionSha256"])) {
      throw new Error("ag_ui_source_frame_digest_invalid");
    }
    for (const key of ["logicalAct", "sourceSequence"] as const) {
      if (!Number.isSafeInteger(binding[key]) || Number(binding[key]) < 0) {
        throw new Error("ag_ui_source_frame_sequence_invalid");
      }
    }
  }
  if (FRAME_BOUND_EVENT_TYPES.has(type) && !frameBound) {
    throw new Error("ag_ui_source_frame_binding_missing");
  }
  if ((type === "RUN_STARTED" || type === "RUN_FINISHED") && frameBound) {
    throw new Error("ag_ui_run_boundary_claims_source_frame");
  }
  if (binding["source"] === "verification_refusal" && type !== "RUN_ERROR") {
    throw new Error("ag_ui_refusal_event_type_invalid");
  }
  return value;
}

export function parseProofBoundAguiSse(value: string): readonly ProofBoundAguiSseEvent[] {
  const output: ProofBoundAguiSseEvent[] = [];
  const ids = new Set<string>();
  for (const rawBlock of value.replaceAll("\r\n", "\n").split("\n\n")) {
    const block = rawBlock.trim();
    if (block === "" || block.startsWith(":")) continue;
    output.push(parseProofBoundAguiSseBlock(block, ids));
  }
  return output;
}

export async function* parseProofBoundAguiSseStream(
  chunks: AsyncIterable<Uint8Array | string>,
): AsyncGenerator<ProofBoundAguiSseEvent> {
  const decoder = new TextDecoder();
  const ids = new Set<string>();
  let buffer = "";
  for await (const chunk of chunks) {
    buffer += typeof chunk === "string" ? chunk : decoder.decode(chunk, { stream: true });
    buffer = buffer.replaceAll("\r\n", "\n");
    let boundary = buffer.indexOf("\n\n");
    while (boundary >= 0) {
      const block = buffer.slice(0, boundary).trim();
      buffer = buffer.slice(boundary + 2);
      if (block !== "" && !block.startsWith(":")) {
        yield parseProofBoundAguiSseBlock(block, ids);
      }
      boundary = buffer.indexOf("\n\n");
    }
    if (new TextEncoder().encode(buffer).byteLength > MAX_AG_UI_SSE_FRAME_BYTES) {
      throw new Error("ag_ui_sse_frame_too_large");
    }
  }
  buffer += decoder.decode();
  const trailing = buffer.replaceAll("\r\n", "\n").trim();
  if (trailing !== "" && !trailing.startsWith(":")) {
    yield parseProofBoundAguiSseBlock(trailing, ids);
  }
}

function parseProofBoundAguiSseBlock(
  block: string,
  ids: Set<string>,
): ProofBoundAguiSseEvent {
  if (new TextEncoder().encode(block).byteLength > MAX_AG_UI_SSE_FRAME_BYTES) {
    throw new Error("ag_ui_sse_frame_too_large");
  }
  const lines = block.split("\n");
  const idLines = lines.filter((line) => line.startsWith("id: "));
  const dataLines = lines.filter((line) => line.startsWith("data: "));
  if (idLines.length !== 1 || dataLines.length !== 1 || lines.length !== 2) {
    throw new Error("ag_ui_sse_frame_shape_invalid");
  }
  const id = idLines[0]!.slice(4);
  if (id === "" || id.includes("\r") || id.includes("\n")) {
    throw new Error("ag_ui_event_id_invalid");
  }
  if (ids.has(id)) throw new Error("ag_ui_event_id_duplicate");
  ids.add(id);
  let event: unknown;
  try {
    event = JSON.parse(dataLines[0]!.slice(6)) as unknown;
  } catch {
    throw new Error("ag_ui_sse_json_invalid");
  }
  return { id, event: verifyProofBoundAguiEvent(event) };
}

function assertBoundedId(value: string, code: string, limit = 200): void {
  if (value.length < 1 || value.length > limit || /[\r\n]/.test(value)) {
    throw new Error(`${code}_invalid`);
  }
}

function assertSafeProposalPayload(value: unknown, path = "$"): void {
  if (Array.isArray(value)) {
    value.forEach((child, index) => assertSafeProposalPayload(child, `${path}[${index}]`));
    return;
  }
  if (!record(value)) return;
  for (const [key, child] of Object.entries(value)) {
    const normalized = key
      .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
      .replaceAll("-", "_")
      .toLowerCase();
    const sensitive = normalized
      .split("_")
      .some((part) => ["authorization", "bearer", "credential", "credentials", "password", "secret", "token"].includes(part));
    if (FORBIDDEN_PROPOSAL_KEYS.has(normalized) || sensitive) {
      throw new Error(`ag_ui_proposal_forbidden_authority_field:${path}.${key}`);
    }
    assertSafeProposalPayload(child, `${path}.${key}`);
  }
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], code: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${code}_keys_invalid`);
  }
}

function exactSubsetKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  code: string,
): void {
  const permitted = new Set(allowed);
  if (Object.keys(value).some((key) => !permitted.has(key))) {
    throw new Error(`${code}_keys_invalid`);
  }
}
