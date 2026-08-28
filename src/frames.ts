import { randomUUID } from "node:crypto";
import { digestCanonical, isSha256 } from "./canonical.js";
import { coverageBlockers } from "./coverage.js";
import { assertEvidenceSafe, assertStableId } from "./security.js";
import {
  FRAME_SCHEMA_VERSION,
  GENESIS_SHA256,
  type ActionFrame,
  type ContentReference,
  type CoverageAttestation,
  type DecisionFrame,
  type EvidenceFrame,
  type FrameSubject,
} from "./types.js";

export interface FrameChainOptions {
  sessionId?: string;
  now?: () => Date;
}

export type DecisionInput = Omit<
  DecisionFrame,
  | "schema_version"
  | "session_id"
  | "sequence"
  | "frame_kind"
  | "observed_at"
  | "previous_frame_sha256"
  | "frame_sha256"
>;
export type ActionInput = Omit<
  ActionFrame,
  | "schema_version"
  | "session_id"
  | "sequence"
  | "frame_kind"
  | "observed_at"
  | "previous_frame_sha256"
  | "frame_sha256"
>;

export class FrameChain {
  readonly sessionId: string;
  private readonly now: () => Date;
  private sequence = 0;
  private head: string = GENESIS_SHA256;

  constructor(options: FrameChainOptions = {}) {
    this.sessionId = options.sessionId ?? randomUUID();
    assertStableId(this.sessionId, "session_id");
    this.now = options.now ?? (() => new Date());
  }

  get length(): number {
    return this.sequence;
  }

  get chainHead(): string {
    return this.head;
  }

  decision(input: DecisionInput): DecisionFrame {
    return this.append({ ...input, frame_kind: "decision" }) as DecisionFrame;
  }

  action(input: ActionInput): ActionFrame {
    return this.append({ ...input, frame_kind: "action" }) as ActionFrame;
  }

  private append(
    input:
      | (DecisionInput & { frame_kind: "decision" })
      | (ActionInput & { frame_kind: "action" }),
  ): EvidenceFrame {
    assertEvidenceSafe(input);
    const body = {
      schema_version: FRAME_SCHEMA_VERSION,
      session_id: this.sessionId,
      sequence: this.sequence,
      observed_at: this.now().toISOString(),
      ...input,
      previous_frame_sha256: this.head,
    };
    const frame = { ...body, frame_sha256: digestCanonical(body) } as EvidenceFrame;
    const blockers = frameBlockers(frame);
    if (blockers.length) throw new Error(blockers.join(","));
    this.sequence += 1;
    this.head = frame.frame_sha256;
    return frame;
  }
}

export function frameBlockers(frame: EvidenceFrame): string[] {
  const blockers: string[] = [];
  blockers.push(
    ...exactKeyBlockers(
      frame,
      frame.frame_kind === "decision"
        ? [
            "authority_scope_ids",
            "coverage",
            "decision",
            "frame_kind",
            "frame_sha256",
            "inputs",
            "observed_at",
            "outputs",
            "policy_sha256",
            "previous_frame_sha256",
            "schema_version",
            "sequence",
            "session_id",
            "subject",
          ]
        : [
            "action",
            "authority_scope_ids",
            "coverage",
            "frame_kind",
            "frame_sha256",
            "inputs",
            "observed_at",
            "outputs",
            "policy_sha256",
            "previous_frame_sha256",
            "schema_version",
            "sequence",
            "session_id",
            "subject",
          ],
      "frame",
    ),
  );
  if (frame.schema_version !== FRAME_SCHEMA_VERSION) blockers.push("frame_schema_invalid");
  try {
    assertStableId(frame.session_id, "session_id");
  } catch {
    blockers.push("frame_session_id_invalid");
  }
  if (!Number.isSafeInteger(frame.sequence) || frame.sequence < 0) blockers.push("frame_sequence_invalid");
  if (
    !Number.isFinite(Date.parse(frame.observed_at)) ||
    new Date(frame.observed_at).toISOString() !== frame.observed_at
  ) {
    blockers.push("frame_timestamp_invalid");
  }
  blockers.push(
    ...exactKeyBlockers(
      frame.coverage,
      [
        "full_world_capture",
        "isolation_enforced",
        "observed_surfaces",
        "schema_version",
        "tier",
        "unobserved_surfaces",
        "visibility_boundary_enforced",
      ],
      "coverage",
    ),
  );
  blockers.push(...coverageBlockers(frame.coverage));
  blockers.push(...exactKeyBlockers(frame.subject, ["identity_sha256", "kind"], "subject"));
  blockers.push(...subjectBlockers(frame.subject));
  if (!isSortedUnique(frame.authority_scope_ids)) blockers.push("frame_authority_scopes_not_canonical");
  for (const scope of frame.authority_scope_ids) {
    try {
      assertStableId(scope, "authority_scope_id");
    } catch {
      blockers.push("frame_authority_scope_invalid");
    }
  }
  if (frame.policy_sha256 !== null && !isSha256(frame.policy_sha256)) blockers.push("frame_policy_digest_invalid");
  if (!isSha256(frame.previous_frame_sha256)) blockers.push("frame_previous_digest_invalid");
  if (!isSha256(frame.frame_sha256)) blockers.push("frame_digest_invalid");
  [...frame.inputs, ...frame.outputs].forEach((reference, index) => {
    blockers.push(...contentReferenceBlockers(reference).map((item) => `frame_content_${index}:${item}`));
  });
  if (!Array.isArray(frame.inputs) || !Array.isArray(frame.outputs)) blockers.push("frame_content_lists_invalid");
  if (frame.frame_kind === "decision") {
    blockers.push(
      ...exactKeyBlockers(frame.decision, ["kind", "reason_codes", "verdict"], "decision"),
    );
    if (!["process_dispatch", "model_dispatch", "tool_dispatch", "policy_evaluation"].includes(frame.decision.kind)) {
      blockers.push("decision_kind_invalid");
    }
    if (!["allowed", "blocked", "observed_violation"].includes(frame.decision.verdict)) {
      blockers.push("decision_verdict_invalid");
    }
    if (!isSortedUnique(frame.decision.reason_codes)) blockers.push("decision_reason_codes_not_canonical");
    blockers.push(...stableIdListBlockers(frame.decision.reason_codes, "decision_reason_code"));
  } else if (frame.frame_kind === "action") {
    blockers.push(
      ...exactKeyBlockers(
        frame.action,
        ["disposition", "exit_code", "kind", "reason_codes", "signal"],
        "action",
      ),
    );
    if (
      ![
        "process_started",
        "stdout_chunk",
        "stderr_chunk",
        "process_terminal",
        "wrapper_failure",
        "model_response",
        "tool_result",
        "world_transition",
      ].includes(frame.action.kind)
    ) {
      blockers.push("action_kind_invalid");
    }
    if (!["running", "completed", "failed", "signaled", "blocked"].includes(frame.action.disposition)) {
      blockers.push("action_disposition_invalid");
    }
    if (!isSortedUnique(frame.action.reason_codes)) blockers.push("action_reason_codes_not_canonical");
    blockers.push(...stableIdListBlockers(frame.action.reason_codes, "action_reason_code"));
    if (frame.action.exit_code !== null && !Number.isSafeInteger(frame.action.exit_code)) {
      blockers.push("action_exit_code_invalid");
    }
    if (frame.action.signal !== null && !/^SIG[A-Z0-9]+$/.test(frame.action.signal)) {
      blockers.push("action_signal_invalid");
    }
    if (frame.action.disposition === "running" && (frame.action.exit_code !== null || frame.action.signal !== null)) {
      blockers.push("action_running_has_terminal_status");
    }
    if (frame.action.disposition === "completed" && (frame.action.exit_code !== 0 || frame.action.signal !== null)) {
      blockers.push("action_completed_status_invalid");
    }
    if (frame.action.disposition === "signaled" && frame.action.signal === null) {
      blockers.push("action_signaled_without_signal");
    }
  } else blockers.push("frame_kind_invalid");
  try {
    assertEvidenceSafe(frame);
  } catch (error) {
    blockers.push(error instanceof Error ? error.message : "frame_evidence_unsafe");
  }
  return blockers;
}

function subjectBlockers(subject: FrameSubject): string[] {
  const blockers = isSha256(subject.identity_sha256) ? [] : ["frame_subject_digest_invalid"];
  if (!["process", "model_call", "tool_call", "decision", "world_transition"].includes(subject.kind)) {
    blockers.push("frame_subject_kind_invalid");
  }
  return blockers;
}

export function contentReferenceBlockers(reference: ContentReference): string[] {
  const blockers: string[] = [];
  blockers.push(
    ...exactKeyBlockers(
      reference,
      [
        "byte_length",
        "ciphertext_ref",
        "ciphertext_sha256",
        "key_id",
        "media_type",
        "plaintext_sha256",
        "schema_version",
        "storage",
      ],
      "content",
    ),
  );
  if (reference.schema_version !== "gradia.guard.content-ref.v1") blockers.push("content_schema_invalid");
  if (!/^[\x20-\x7e]{1,200}$/.test(reference.media_type)) blockers.push("content_media_type_invalid");
  if (!Number.isSafeInteger(reference.byte_length) || reference.byte_length < 0) blockers.push("content_length_invalid");
  if (!isSha256(reference.plaintext_sha256)) blockers.push("content_plaintext_digest_invalid");
  if (reference.storage === "digest-only") {
    if (reference.ciphertext_ref !== null || reference.ciphertext_sha256 !== null || reference.key_id !== null) {
      blockers.push("digest_only_content_has_storage_fields");
    }
  } else if (reference.storage === "aes-256-gcm") {
    if (!reference.ciphertext_ref || !/^[0-9a-f]{64}\.bin$/.test(reference.ciphertext_ref)) {
      blockers.push("encrypted_content_ref_invalid");
    }
    if (!isSha256(reference.ciphertext_sha256)) blockers.push("encrypted_content_digest_invalid");
    if (!reference.key_id) blockers.push("encrypted_content_key_id_missing");
    else {
      try {
        assertStableId(reference.key_id, "key_id");
      } catch {
        blockers.push("encrypted_content_key_id_invalid");
      }
    }
  } else blockers.push("content_storage_invalid");
  return blockers;
}

function isSortedUnique(values: readonly string[]): boolean {
  return values.every((value, index) =>
    index === 0 ? true : (values[index - 1] as string).localeCompare(value) < 0,
  );
}

function exactKeyBlockers(value: object, expected: readonly string[], label: string): string[] {
  const actual = Object.keys(value).sort();
  const canonicalExpected = [...expected].sort();
  return actual.length === canonicalExpected.length && actual.every((key, index) => key === canonicalExpected[index])
    ? []
    : [`${label}_fields_invalid`];
}

function stableIdListBlockers(values: readonly string[], label: string): string[] {
  const blockers: string[] = [];
  for (const value of values) {
    try {
      assertStableId(value, label);
    } catch {
      blockers.push(`${label}_invalid`);
    }
  }
  return blockers;
}

export function recomputeFrameDigest(frame: EvidenceFrame): string {
  const { frame_sha256: _digest, ...body } = frame;
  return digestCanonical(body);
}
