import { randomUUID } from "node:crypto";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import {
  canonicalJson,
  digestCanonical,
  isSha256,
  isStrictCanonicalStringOrder,
  sha256,
} from "./canonical.js";
import { contentReferenceBlockers } from "./frames.js";
import { coverageBlockers, sdkCoverage } from "./coverage.js";
import { assertEvidenceSafe, assertStableId } from "./security.js";
import {
  GENESIS_SHA256,
  SDK_BUNDLE_SCHEMA_VERSION,
  SDK_FRAME_SCHEMA_VERSION,
  type ContentReference,
  type SdkActionFrame,
  type SdkApplicationActionFrame,
  type SdkApplicationDecisionFrame,
  type SdkDecisionFrame,
  type SdkDecisionIdentity,
  type SdkEvidenceBundleManifest,
  type SdkEvidenceFrame,
  type SdkOperationKind,
  type SdkOutcome,
  type SdkPolicyReceipt,
  type SdkStateRootIdentity,
  type SdkToolActionFrame,
  type SdkToolDecisionFrame,
  type SdkToolIdentity,
} from "./types.js";

const GUARD_VERSION = "0.1.0";

export interface SdkPolicyDecisionInput {
  decision: "allowed" | "blocked";
  censorKind: "policy" | "budget" | "authority" | null;
  reasonCodes: readonly string[];
  policySha256: string;
}

interface SdkOperationContextInput {
  actorId: string;
  principalId: string;
  authorityScopeIds: readonly string[];
  logicalOperationId: string;
  attemptNumber: number;
  retryOfOccurrenceSha256: string | null;
  parentOccurrenceSha256: string | null;
  stateRootBefore: SdkStateRootIdentity | null;
  policy: SdkPolicyDecisionInput;
}

export interface BeginApplicationDecisionInput extends SdkOperationContextInput {
  decisionIdentity: SdkDecisionIdentity;
  decisionInputBody: Uint8Array;
  decisionInputMediaType: string;
}

export interface BeginRegisteredToolCallInput extends SdkOperationContextInput {
  toolIdentity: SdkToolIdentity;
  toolRequestBody: Uint8Array;
  toolRequestMediaType: string;
}

export interface ApplicationDecisionSuccessInput {
  resolvedDecisionIdentity: SdkDecisionIdentity;
  decisionOutputBody: Uint8Array;
  decisionOutputMediaType: string;
  stateRootAfter: SdkStateRootIdentity | null;
}

export interface RegisteredToolSuccessInput {
  resolvedToolIdentity: SdkToolIdentity;
  toolResultBody: Uint8Array;
  toolResultMediaType: string;
  stateRootAfter: SdkStateRootIdentity | null;
}

export interface ApplicationDecisionFailureInput {
  outcome: "decision_failure" | "protocol_failure";
  resolvedDecisionIdentity: SdkDecisionIdentity | null;
  decisionOutputBody: Uint8Array | null;
  decisionOutputMediaType: string | null;
  stateRootAfter: SdkStateRootIdentity | null;
  failureCode: string;
}

export interface RegisteredToolFailureInput {
  outcome: "tool_failure" | "protocol_failure";
  resolvedToolIdentity: SdkToolIdentity | null;
  toolResultBody: Uint8Array | null;
  toolResultMediaType: string | null;
  stateRootAfter: SdkStateRootIdentity | null;
  failureCode: string;
}

export interface SdkRecorderOptions {
  directory: string;
  sessionId?: string;
  now?: () => Date;
  monotonicMs?: () => number;
}

export class SdkIdentityMismatchError extends Error {
  readonly frame: SdkActionFrame;

  constructor(frame: SdkActionFrame) {
    super("sdk_resolved_identity_mismatch");
    this.name = "SdkIdentityMismatchError";
    this.frame = frame;
  }
}

abstract class SdkOperation<TDecision extends SdkDecisionFrame> {
  readonly occurrenceSha256: string;
  readonly censored: boolean;
  protected readonly recorder: SdkRecorder;
  protected readonly decisionFrame: TDecision;
  private dispatchStartedAt: string | null = null;
  private dispatchMonotonicMs: number | null = null;
  private closed: boolean;

  constructor(recorder: SdkRecorder, frame: TDecision, censored: boolean) {
    this.recorder = recorder;
    this.decisionFrame = frame;
    this.occurrenceSha256 = frame.occurrence_sha256;
    this.censored = censored;
    this.closed = censored;
  }

  markDispatched(): void {
    if (this.censored) throw new Error("sdk_censored_operation_cannot_dispatch");
    if (this.closed) throw new Error("sdk_operation_already_closed");
    if (this.dispatchStartedAt !== null) throw new Error("sdk_operation_already_dispatched");
    this.dispatchStartedAt = this.recorder.wallTime();
    this.dispatchMonotonicMs = this.recorder.monotonicTime();
  }

  protected terminalTiming(): {
    dispatchStartedAt: string;
    terminalObservedAt: string;
    latencyMs: number;
  } {
    if (this.closed) throw new Error("sdk_operation_already_closed");
    if (this.dispatchStartedAt === null || this.dispatchMonotonicMs === null) {
      throw new Error("sdk_operation_not_marked_dispatched");
    }
    this.closed = true;
    const terminalObservedAt = this.recorder.wallTime();
    return {
      dispatchStartedAt: this.dispatchStartedAt,
      terminalObservedAt,
      latencyMs: Math.max(0, Math.round(this.recorder.monotonicTime() - this.dispatchMonotonicMs)),
    };
  }
}

export class ApplicationDecisionOperation extends SdkOperation<SdkApplicationDecisionFrame> {
  succeed(input: ApplicationDecisionSuccessInput): SdkApplicationActionFrame {
    assertExactKeys(
      input,
      ["decisionOutputBody", "decisionOutputMediaType", "resolvedDecisionIdentity", "stateRootAfter"],
      "sdk_decision_success_input",
    );
    validateDecisionIdentity(input.resolvedDecisionIdentity);
    validateStateRoot(input.stateRootAfter);
    const output = sdkContentReference(input.decisionOutputBody, input.decisionOutputMediaType);
    const identityMatch =
      canonicalJson(input.resolvedDecisionIdentity) === canonicalJson(this.decisionFrame.decision_identity);
    const timing = this.terminalTiming();
    const frame = this.recorder.closeDecision(this.decisionFrame, {
      outcome: identityMatch ? "success" : "identity_mismatch",
      dispatch_occurred: true,
      resolved_decision_identity: input.resolvedDecisionIdentity,
      decision_output: output,
      state_root_after: cloneStateRoot(input.stateRootAfter),
      dispatch_started_at: timing.dispatchStartedAt,
      terminal_observed_at: timing.terminalObservedAt,
      latency_ms: timing.latencyMs,
      failure_code: identityMatch ? null : "resolved_decision_identity_mismatch",
    });
    if (!identityMatch) throw new SdkIdentityMismatchError(frame);
    return frame;
  }

  fail(input: ApplicationDecisionFailureInput): SdkApplicationActionFrame {
    assertExactKeys(
      input,
      [
        "decisionOutputBody",
        "decisionOutputMediaType",
        "failureCode",
        "outcome",
        "resolvedDecisionIdentity",
        "stateRootAfter",
      ],
      "sdk_decision_failure_input",
    );
    if (!["decision_failure", "protocol_failure"].includes(input.outcome)) {
      throw new Error("sdk_decision_failure_outcome_invalid");
    }
    assertStableId(input.failureCode, "failure_code");
    validateStateRoot(input.stateRootAfter);
    const output = optionalContentReference(
      input.decisionOutputBody,
      input.decisionOutputMediaType,
      "sdk_decision_failure_output",
    );
    if (input.resolvedDecisionIdentity !== null) validateDecisionIdentity(input.resolvedDecisionIdentity);
    const identityMatch =
      input.resolvedDecisionIdentity === null ||
      canonicalJson(input.resolvedDecisionIdentity) === canonicalJson(this.decisionFrame.decision_identity);
    const timing = this.terminalTiming();
    const frame = this.recorder.closeDecision(this.decisionFrame, {
      outcome: identityMatch ? input.outcome : "identity_mismatch",
      dispatch_occurred: true,
      resolved_decision_identity: input.resolvedDecisionIdentity,
      decision_output: output,
      state_root_after: cloneStateRoot(input.stateRootAfter),
      dispatch_started_at: timing.dispatchStartedAt,
      terminal_observed_at: timing.terminalObservedAt,
      latency_ms: timing.latencyMs,
      failure_code: identityMatch ? input.failureCode : "resolved_decision_identity_mismatch",
    });
    if (!identityMatch) throw new SdkIdentityMismatchError(frame);
    return frame;
  }
}

export class RegisteredToolCallOperation extends SdkOperation<SdkToolDecisionFrame> {
  succeed(input: RegisteredToolSuccessInput): SdkToolActionFrame {
    assertExactKeys(
      input,
      ["resolvedToolIdentity", "stateRootAfter", "toolResultBody", "toolResultMediaType"],
      "sdk_tool_success_input",
    );
    validateToolIdentity(input.resolvedToolIdentity);
    validateStateRoot(input.stateRootAfter);
    const result = sdkContentReference(input.toolResultBody, input.toolResultMediaType);
    const identityMatch = canonicalJson(input.resolvedToolIdentity) === canonicalJson(this.decisionFrame.tool_identity);
    const timing = this.terminalTiming();
    const frame = this.recorder.closeTool(this.decisionFrame, {
      outcome: identityMatch ? "success" : "identity_mismatch",
      dispatch_occurred: true,
      resolved_tool_identity: input.resolvedToolIdentity,
      tool_result: result,
      state_root_after: cloneStateRoot(input.stateRootAfter),
      dispatch_started_at: timing.dispatchStartedAt,
      terminal_observed_at: timing.terminalObservedAt,
      latency_ms: timing.latencyMs,
      failure_code: identityMatch ? null : "resolved_tool_identity_mismatch",
    });
    if (!identityMatch) throw new SdkIdentityMismatchError(frame);
    return frame;
  }

  fail(input: RegisteredToolFailureInput): SdkToolActionFrame {
    assertExactKeys(
      input,
      [
        "failureCode",
        "outcome",
        "resolvedToolIdentity",
        "stateRootAfter",
        "toolResultBody",
        "toolResultMediaType",
      ],
      "sdk_tool_failure_input",
    );
    if (!["tool_failure", "protocol_failure"].includes(input.outcome)) {
      throw new Error("sdk_tool_failure_outcome_invalid");
    }
    assertStableId(input.failureCode, "failure_code");
    validateStateRoot(input.stateRootAfter);
    const result = optionalContentReference(
      input.toolResultBody,
      input.toolResultMediaType,
      "sdk_tool_failure_result",
    );
    if (input.resolvedToolIdentity !== null) validateToolIdentity(input.resolvedToolIdentity);
    const identityMatch =
      input.resolvedToolIdentity === null ||
      canonicalJson(input.resolvedToolIdentity) === canonicalJson(this.decisionFrame.tool_identity);
    const timing = this.terminalTiming();
    const frame = this.recorder.closeTool(this.decisionFrame, {
      outcome: identityMatch ? input.outcome : "identity_mismatch",
      dispatch_occurred: true,
      resolved_tool_identity: input.resolvedToolIdentity,
      tool_result: result,
      state_root_after: cloneStateRoot(input.stateRootAfter),
      dispatch_started_at: timing.dispatchStartedAt,
      terminal_observed_at: timing.terminalObservedAt,
      latency_ms: timing.latencyMs,
      failure_code: identityMatch ? input.failureCode : "resolved_tool_identity_mismatch",
    });
    if (!identityMatch) throw new SdkIdentityMismatchError(frame);
    return frame;
  }
}

export class SdkRecorder {
  readonly directory: string;
  readonly sessionId: string;
  private readonly now: () => Date;
  private readonly monotonicMs: () => number;
  private readonly frameChain: SdkFrameChain;
  private readonly framesPath: string;
  private readonly manifestPath: string;
  private manifest: SdkEvidenceBundleManifest;
  private openOperations = 0;
  private readonly logicalOccurrences = new Map<string, Map<number, SdkDecisionFrame>>();
  private readonly knownOccurrences = new Set<string>();

  constructor(options: SdkRecorderOptions) {
    assertExactKeys(options, ["directory", "monotonicMs", "now", "sessionId"], "sdk_recorder_options", true);
    this.now = options.now ?? (() => new Date());
    this.monotonicMs = options.monotonicMs ?? (() => Number(process.hrtime.bigint() / 1_000_000n));
    this.sessionId = options.sessionId ?? randomUUID();
    assertStableId(this.sessionId, "session_id");
    this.directory = resolve(options.directory);
    if (existsSync(this.directory)) throw new Error("sdk_bundle_directory_exists");
    mkdirSync(this.directory, { recursive: true, mode: 0o700 });
    this.framesPath = join(this.directory, "frames.ndjson");
    this.manifestPath = join(this.directory, "bundle.json");
    writeFileSync(this.framesPath, "", { mode: 0o600, flag: "wx" });
    const coverage = sdkCoverage();
    this.frameChain = new SdkFrameChain(this.sessionId, coverage, () => this.wallTime());
    this.manifest = {
      schema_version: SDK_BUNDLE_SCHEMA_VERSION,
      guard_version: GUARD_VERSION,
      session_id: this.sessionId,
      created_at: this.wallTime(),
      finalized_at: null,
      status: "recording",
      capture_mode: "digest-only",
      coverage,
      capture_boundary: "explicit_sdk",
      bypass_possible: true,
      bypass_declaration: "uninstrumented_or_direct_io_is_not_observed",
      frame_count: 0,
      operation_count: 0,
      chain_head_sha256: GENESIS_SHA256,
    };
    this.writeManifest();
  }

  beginApplicationDecision(input: BeginApplicationDecisionInput): ApplicationDecisionOperation {
    assertExactKeys(
      input,
      [
        "actorId",
        "attemptNumber",
        "authorityScopeIds",
        "decisionIdentity",
        "decisionInputBody",
        "decisionInputMediaType",
        "logicalOperationId",
        "parentOccurrenceSha256",
        "policy",
        "principalId",
        "retryOfOccurrenceSha256",
        "stateRootBefore",
      ],
      "sdk_begin_decision_input",
    );
    validateDecisionIdentity(input.decisionIdentity);
    const decisionInput = sdkContentReference(input.decisionInputBody, input.decisionInputMediaType);
    const common = this.prepareCommon("application_decision", input, input.decisionIdentity, decisionInput);
    const decision = this.frameChain.applicationDecision({
      ...common.frame,
      decision_identity: cloneDecisionIdentity(input.decisionIdentity),
      decision_input: decisionInput,
      policy: common.policy,
    });
    return this.admitDecision(decision, common.censored, (value) => new ApplicationDecisionOperation(this, value, common.censored));
  }

  beginRegisteredToolCall(input: BeginRegisteredToolCallInput): RegisteredToolCallOperation {
    assertExactKeys(
      input,
      [
        "actorId",
        "attemptNumber",
        "authorityScopeIds",
        "logicalOperationId",
        "parentOccurrenceSha256",
        "policy",
        "principalId",
        "retryOfOccurrenceSha256",
        "stateRootBefore",
        "toolIdentity",
        "toolRequestBody",
        "toolRequestMediaType",
      ],
      "sdk_begin_tool_input",
    );
    validateToolIdentity(input.toolIdentity);
    const toolRequest = sdkContentReference(input.toolRequestBody, input.toolRequestMediaType);
    const common = this.prepareCommon("registered_tool_call", input, input.toolIdentity, toolRequest);
    const decision = this.frameChain.toolDecision({
      ...common.frame,
      tool_identity: cloneToolIdentity(input.toolIdentity),
      tool_request: toolRequest,
      policy: common.policy,
    });
    return this.admitDecision(decision, common.censored, (value) => new RegisteredToolCallOperation(this, value, common.censored));
  }

  finalize(): void {
    if (this.manifest.status !== "recording") return;
    if (this.openOperations !== 0) throw new Error("sdk_open_operations_prevent_finalization");
    if (this.manifest.operation_count === 0) throw new Error("sdk_empty_bundle_cannot_finalize");
    this.manifest.status = "finalized";
    this.manifest.finalized_at = this.wallTime();
    this.writeManifest();
  }

  wallTime(): string {
    return this.now().toISOString();
  }

  monotonicTime(): number {
    const value = this.monotonicMs();
    if (!Number.isFinite(value) || value < 0) throw new Error("sdk_monotonic_clock_invalid");
    return value;
  }

  closeDecision(
    decision: SdkApplicationDecisionFrame,
    terminal: Pick<
      SdkApplicationActionFrame,
      | "outcome"
      | "dispatch_occurred"
      | "resolved_decision_identity"
      | "decision_output"
      | "state_root_after"
      | "dispatch_started_at"
      | "terminal_observed_at"
      | "latency_ms"
      | "failure_code"
    >,
  ): SdkApplicationActionFrame {
    const action = this.frameChain.applicationAction({ decision, ...terminal });
    return this.closeOperation(action);
  }

  closeTool(
    decision: SdkToolDecisionFrame,
    terminal: Pick<
      SdkToolActionFrame,
      | "outcome"
      | "dispatch_occurred"
      | "resolved_tool_identity"
      | "tool_result"
      | "state_root_after"
      | "dispatch_started_at"
      | "terminal_observed_at"
      | "latency_ms"
      | "failure_code"
    >,
  ): SdkToolActionFrame {
    const action = this.frameChain.toolAction({ decision, ...terminal });
    return this.closeOperation(action);
  }

  private prepareCommon(
    operationKind: SdkOperationKind,
    input: SdkOperationContextInput,
    identity: SdkDecisionIdentity | SdkToolIdentity,
    content: ContentReference,
  ): {
    frame: Omit<
      SdkDecisionFrame,
      | "schema_version"
      | "session_id"
      | "sequence"
      | "frame_kind"
      | "operation_kind"
      | "observed_at"
      | "coverage"
      | "previous_frame_sha256"
      | "frame_sha256"
      | "decision_identity"
      | "decision_input"
      | "tool_identity"
      | "tool_request"
      | "policy"
    >;
    policy: SdkPolicyReceipt;
    censored: boolean;
  } {
    if (this.manifest.status !== "recording") throw new Error("sdk_recorder_finalized");
    assertExactKeys(input.policy, ["censorKind", "decision", "policySha256", "reasonCodes"], "sdk_policy_input");
    assertStableId(input.actorId, "actor_id");
    assertStableId(input.principalId, "principal_id");
    assertSortedStableIds(input.authorityScopeIds, "authority_scope_ids");
    assertStableId(input.logicalOperationId, "logical_operation_id");
    validateStateRoot(input.stateRootBefore);
    if (!Number.isSafeInteger(input.attemptNumber) || input.attemptNumber < 1) {
      throw new Error("sdk_attempt_number_invalid");
    }
    if (input.attemptNumber === 1 && input.retryOfOccurrenceSha256 !== null) {
      throw new Error("sdk_first_attempt_has_retry_parent");
    }
    if (input.attemptNumber > 1 && !isSha256(input.retryOfOccurrenceSha256)) {
      throw new Error("sdk_retry_parent_missing");
    }
    if (input.parentOccurrenceSha256 !== null && !isSha256(input.parentOccurrenceSha256)) {
      throw new Error("sdk_parent_occurrence_invalid");
    }
    if (input.parentOccurrenceSha256 !== null && !this.knownOccurrences.has(input.parentOccurrenceSha256)) {
      throw new Error("sdk_parent_occurrence_not_recorded");
    }
    if (!isSha256(input.policy.policySha256)) throw new Error("sdk_policy_digest_invalid");
    assertSortedStableIds(input.policy.reasonCodes, "sdk_policy_reason_codes");
    validatePolicyDecision(input.policy);
    const occurrenceBody = {
      schema_version: "gradia.guard.sdk-occurrence.v1",
      operation_kind: operationKind,
      actor_id: input.actorId,
      principal_id: input.principalId,
      authority_scope_ids: [...input.authorityScopeIds],
      logical_operation_id: input.logicalOperationId,
      attempt_number: input.attemptNumber,
      retry_of_occurrence_sha256: input.retryOfOccurrenceSha256,
      parent_occurrence_sha256: input.parentOccurrenceSha256,
      state_root_before: cloneStateRoot(input.stateRootBefore),
      identity,
      input_sha256: content.plaintext_sha256,
    };
    const occurrenceSha256 = digestCanonical(occurrenceBody);
    const prior = this.logicalOccurrences.get(input.logicalOperationId) ?? new Map<number, SdkDecisionFrame>();
    if (prior.has(input.attemptNumber)) throw new Error("sdk_logical_attempt_duplicate");
    if (input.attemptNumber > 1) {
      const predecessor = prior.get(input.attemptNumber - 1);
      if (!predecessor || predecessor.occurrence_sha256 !== input.retryOfOccurrenceSha256) {
        throw new Error("sdk_retry_parent_not_recorded");
      }
      if (
        predecessor.operation_kind !== operationKind ||
        predecessor.actor_id !== input.actorId ||
        predecessor.principal_id !== input.principalId ||
        canonicalJson(predecessor.authority_scope_ids) !== canonicalJson(input.authorityScopeIds) ||
        canonicalJson(operationIdentity(predecessor)) !== canonicalJson(identity)
      ) {
        throw new Error("sdk_retry_identity_context_mismatch");
      }
    }
    const evaluatedAt = this.wallTime();
    const policyBody = {
      schema_version: "gradia.guard.sdk-policy-receipt.v1",
      operation_kind: operationKind,
      occurrence_sha256: occurrenceSha256,
      actor_id: input.actorId,
      principal_id: input.principalId,
      authority_scope_ids: [...input.authorityScopeIds],
      decision: input.policy.decision,
      censor_kind: input.policy.censorKind,
      reason_codes: [...input.policy.reasonCodes],
      policy_sha256: input.policy.policySha256,
      evaluated_at: evaluatedAt,
    } as const;
    const policy: SdkPolicyReceipt = { ...policyBody, receipt_sha256: digestCanonical(policyBody) };
    return {
      frame: {
        actor_id: input.actorId,
        principal_id: input.principalId,
        authority_scope_ids: [...input.authorityScopeIds],
        logical_operation_id: input.logicalOperationId,
        attempt_number: input.attemptNumber,
        retry_of_occurrence_sha256: input.retryOfOccurrenceSha256,
        parent_occurrence_sha256: input.parentOccurrenceSha256,
        occurrence_sha256: occurrenceSha256,
        state_root_before: cloneStateRoot(input.stateRootBefore),
      },
      policy,
      censored: policy.decision === "blocked",
    };
  }

  private admitDecision<T extends SdkDecisionFrame, O extends SdkOperation<T>>(
    decision: T,
    censored: boolean,
    factory: (frame: T) => O,
  ): O {
    this.append(decision);
    const attempts = this.logicalOccurrences.get(decision.logical_operation_id) ?? new Map<number, SdkDecisionFrame>();
    attempts.set(decision.attempt_number, decision);
    this.logicalOccurrences.set(decision.logical_operation_id, attempts);
    this.knownOccurrences.add(decision.occurrence_sha256);
    if (censored) {
      const common = {
        outcome: censorOutcome(decision.policy),
        dispatch_occurred: false,
        state_root_after: cloneStateRoot(decision.state_root_before),
        dispatch_started_at: null,
        terminal_observed_at: null,
        latency_ms: null,
        failure_code: decision.policy.reason_codes[0] ?? "pre_dispatch_censored",
      } as const;
      const action =
        decision.operation_kind === "application_decision"
          ? this.frameChain.applicationAction({
              decision,
              ...common,
              resolved_decision_identity: null,
              decision_output: null,
            })
          : this.frameChain.toolAction({
              decision,
              ...common,
              resolved_tool_identity: null,
              tool_result: null,
            });
      this.append(action);
      this.manifest.operation_count += 1;
      this.writeManifest();
    } else {
      this.openOperations += 1;
    }
    return factory(decision);
  }

  private closeOperation<T extends SdkActionFrame>(action: T): T {
    if (this.openOperations < 1) throw new Error("sdk_open_operation_accounting_invalid");
    this.append(action);
    this.openOperations -= 1;
    this.manifest.operation_count += 1;
    this.writeManifest();
    return action;
  }

  private append(frame: SdkEvidenceFrame): void {
    const blockers = sdkFrameBlockers(frame);
    if (blockers.length) throw new Error(blockers.join(","));
    if (frame.session_id !== this.manifest.session_id) throw new Error("sdk_spool_session_mismatch");
    if (frame.sequence !== this.manifest.frame_count) throw new Error("sdk_spool_sequence_mismatch");
    if (frame.previous_frame_sha256 !== this.manifest.chain_head_sha256) {
      throw new Error("sdk_spool_previous_hash_mismatch");
    }
    appendFileSync(this.framesPath, `${canonicalJson(frame)}\n`, { encoding: "utf8", mode: 0o600 });
    this.manifest.frame_count += 1;
    this.manifest.chain_head_sha256 = frame.frame_sha256;
    this.writeManifest();
  }

  private writeManifest(): void {
    const temporary = `${this.manifestPath}.tmp`;
    writeFileSync(temporary, `${canonicalJson(this.manifest)}\n`, { encoding: "utf8", mode: 0o600 });
    renameSync(temporary, this.manifestPath);
  }
}

class SdkFrameChain {
  private sequence = 0;
  private head: string = GENESIS_SHA256;

  constructor(
    private readonly sessionId: string,
    private readonly coverage: ReturnType<typeof sdkCoverage>,
    private readonly now: () => string,
  ) {}

  applicationDecision(
    input: Omit<
      SdkApplicationDecisionFrame,
      | "schema_version"
      | "session_id"
      | "sequence"
      | "frame_kind"
      | "operation_kind"
      | "observed_at"
      | "coverage"
      | "previous_frame_sha256"
      | "frame_sha256"
    >,
  ): SdkApplicationDecisionFrame {
    return this.append({ ...input, frame_kind: "decision", operation_kind: "application_decision" }) as SdkApplicationDecisionFrame;
  }

  toolDecision(
    input: Omit<
      SdkToolDecisionFrame,
      | "schema_version"
      | "session_id"
      | "sequence"
      | "frame_kind"
      | "operation_kind"
      | "observed_at"
      | "coverage"
      | "previous_frame_sha256"
      | "frame_sha256"
    >,
  ): SdkToolDecisionFrame {
    return this.append({ ...input, frame_kind: "decision", operation_kind: "registered_tool_call" }) as SdkToolDecisionFrame;
  }

  applicationAction(
    input: {
      decision: SdkApplicationDecisionFrame;
    } & Pick<
      SdkApplicationActionFrame,
      | "outcome"
      | "dispatch_occurred"
      | "resolved_decision_identity"
      | "decision_output"
      | "state_root_after"
      | "dispatch_started_at"
      | "terminal_observed_at"
      | "latency_ms"
      | "failure_code"
    >,
  ): SdkApplicationActionFrame {
    const { decision, ...terminal } = input;
    return this.append({
      frame_kind: "action",
      operation_kind: "application_decision",
      actor_id: decision.actor_id,
      principal_id: decision.principal_id,
      authority_scope_ids: decision.authority_scope_ids,
      logical_operation_id: decision.logical_operation_id,
      attempt_number: decision.attempt_number,
      retry_of_occurrence_sha256: decision.retry_of_occurrence_sha256,
      parent_occurrence_sha256: decision.parent_occurrence_sha256,
      occurrence_sha256: decision.occurrence_sha256,
      state_root_before: decision.state_root_before,
      decision_identity: decision.decision_identity,
      resolved_decision_identity: terminal.resolved_decision_identity,
      decision_input: decision.decision_input,
      decision_output: terminal.decision_output,
      policy_receipt_sha256: decision.policy.receipt_sha256,
      outcome: terminal.outcome,
      dispatch_occurred: terminal.dispatch_occurred,
      state_root_after: terminal.state_root_after,
      dispatch_started_at: terminal.dispatch_started_at,
      terminal_observed_at: terminal.terminal_observed_at,
      latency_ms: terminal.latency_ms,
      failure_code: terminal.failure_code,
    }) as SdkApplicationActionFrame;
  }

  toolAction(
    input: {
      decision: SdkToolDecisionFrame;
    } & Pick<
      SdkToolActionFrame,
      | "outcome"
      | "dispatch_occurred"
      | "resolved_tool_identity"
      | "tool_result"
      | "state_root_after"
      | "dispatch_started_at"
      | "terminal_observed_at"
      | "latency_ms"
      | "failure_code"
    >,
  ): SdkToolActionFrame {
    const { decision, ...terminal } = input;
    return this.append({
      frame_kind: "action",
      operation_kind: "registered_tool_call",
      actor_id: decision.actor_id,
      principal_id: decision.principal_id,
      authority_scope_ids: decision.authority_scope_ids,
      logical_operation_id: decision.logical_operation_id,
      attempt_number: decision.attempt_number,
      retry_of_occurrence_sha256: decision.retry_of_occurrence_sha256,
      parent_occurrence_sha256: decision.parent_occurrence_sha256,
      occurrence_sha256: decision.occurrence_sha256,
      state_root_before: decision.state_root_before,
      tool_identity: decision.tool_identity,
      resolved_tool_identity: terminal.resolved_tool_identity,
      tool_request: decision.tool_request,
      tool_result: terminal.tool_result,
      policy_receipt_sha256: decision.policy.receipt_sha256,
      outcome: terminal.outcome,
      dispatch_occurred: terminal.dispatch_occurred,
      state_root_after: terminal.state_root_after,
      dispatch_started_at: terminal.dispatch_started_at,
      terminal_observed_at: terminal.terminal_observed_at,
      latency_ms: terminal.latency_ms,
      failure_code: terminal.failure_code,
    }) as SdkToolActionFrame;
  }

  private append(input: object): SdkEvidenceFrame {
    const body = {
      schema_version: SDK_FRAME_SCHEMA_VERSION,
      session_id: this.sessionId,
      sequence: this.sequence,
      observed_at: this.now(),
      coverage: this.coverage,
      ...input,
      previous_frame_sha256: this.head,
    };
    assertEvidenceSafe(body);
    const frame = { ...body, frame_sha256: digestCanonical(body) } as SdkEvidenceFrame;
    const blockers = sdkFrameBlockers(frame);
    if (blockers.length) throw new Error(blockers.join(","));
    this.sequence += 1;
    this.head = frame.frame_sha256;
    return frame;
  }
}

export function sdkContentReference(content: Uint8Array, mediaType: string): ContentReference {
  if (!(content instanceof Uint8Array) || content.byteLength === 0) {
    throw new Error("sdk_content_bytes_missing");
  }
  if (!/^[\x20-\x7e]{1,200}$/.test(mediaType)) throw new Error("sdk_content_media_type_invalid");
  return {
    schema_version: "gradia.guard.content-ref.v1",
    media_type: mediaType,
    byte_length: content.byteLength,
    plaintext_sha256: sha256(content),
    storage: "digest-only",
    ciphertext_ref: null,
    ciphertext_sha256: null,
    key_id: null,
  };
}

export function sdkOccurrenceSha256(frame: SdkEvidenceFrame): string {
  const identity = operationIdentity(frame);
  const input = operationInput(frame);
  return digestCanonical({
    schema_version: "gradia.guard.sdk-occurrence.v1",
    operation_kind: frame.operation_kind,
    actor_id: frame.actor_id,
    principal_id: frame.principal_id,
    authority_scope_ids: frame.authority_scope_ids,
    logical_operation_id: frame.logical_operation_id,
    attempt_number: frame.attempt_number,
    retry_of_occurrence_sha256: frame.retry_of_occurrence_sha256,
    parent_occurrence_sha256: frame.parent_occurrence_sha256,
    state_root_before: frame.state_root_before,
    identity,
    input_sha256: input.plaintext_sha256,
  });
}

export function recomputeSdkFrameDigest(frame: SdkEvidenceFrame): string {
  const { frame_sha256: _digest, ...body } = frame;
  return digestCanonical(body);
}

export function sdkFrameBlockers(frame: SdkEvidenceFrame): string[] {
  const blockers: string[] = [];
  const common = [
    "actor_id",
    "attempt_number",
    "authority_scope_ids",
    "coverage",
    "frame_kind",
    "frame_sha256",
    "logical_operation_id",
    "observed_at",
    "occurrence_sha256",
    "operation_kind",
    "parent_occurrence_sha256",
    "previous_frame_sha256",
    "principal_id",
    "retry_of_occurrence_sha256",
    "schema_version",
    "sequence",
    "session_id",
    "state_root_before",
  ];
  let specific: readonly string[];
  if (frame.frame_kind === "decision" && frame.operation_kind === "application_decision") {
    specific = ["decision_identity", "decision_input", "policy"];
  } else if (frame.frame_kind === "decision" && frame.operation_kind === "registered_tool_call") {
    specific = ["policy", "tool_identity", "tool_request"];
  } else if (frame.frame_kind === "action" && frame.operation_kind === "application_decision") {
    specific = [
      "decision_identity",
      "decision_input",
      "decision_output",
      "dispatch_occurred",
      "dispatch_started_at",
      "failure_code",
      "latency_ms",
      "outcome",
      "policy_receipt_sha256",
      "resolved_decision_identity",
      "state_root_after",
      "terminal_observed_at",
    ];
  } else if (frame.frame_kind === "action" && frame.operation_kind === "registered_tool_call") {
    specific = [
      "dispatch_occurred",
      "dispatch_started_at",
      "failure_code",
      "latency_ms",
      "outcome",
      "policy_receipt_sha256",
      "resolved_tool_identity",
      "state_root_after",
      "terminal_observed_at",
      "tool_identity",
      "tool_request",
      "tool_result",
    ];
  } else {
    return ["sdk_frame_discriminator_invalid"];
  }
  blockers.push(...exactKeyBlockers(frame, [...common, ...specific], "sdk_frame"));
  if (frame.schema_version !== SDK_FRAME_SCHEMA_VERSION) blockers.push("sdk_frame_schema_invalid");
  try {
    assertStableId(frame.session_id, "session_id");
    assertStableId(frame.actor_id, "actor_id");
    assertStableId(frame.principal_id, "principal_id");
    assertSortedStableIds(frame.authority_scope_ids, "authority_scope_ids");
    assertStableId(frame.logical_operation_id, "logical_operation_id");
  } catch (error) {
    blockers.push(error instanceof Error ? error.message : "sdk_frame_identity_invalid");
  }
  if (!Number.isSafeInteger(frame.sequence) || frame.sequence < 0) blockers.push("sdk_frame_sequence_invalid");
  if (!validTimestamp(frame.observed_at)) blockers.push("sdk_frame_timestamp_invalid");
  blockers.push(...coverageBlockers(frame.coverage));
  if (frame.coverage.tier !== "sdk") blockers.push("sdk_frame_coverage_tier_invalid");
  if (!Number.isSafeInteger(frame.attempt_number) || frame.attempt_number < 1) {
    blockers.push("sdk_frame_attempt_number_invalid");
  }
  if (frame.attempt_number === 1 && frame.retry_of_occurrence_sha256 !== null) {
    blockers.push("sdk_frame_first_attempt_has_retry_parent");
  }
  if (frame.attempt_number > 1 && !isSha256(frame.retry_of_occurrence_sha256)) {
    blockers.push("sdk_frame_retry_parent_missing");
  }
  if (frame.parent_occurrence_sha256 !== null && !isSha256(frame.parent_occurrence_sha256)) {
    blockers.push("sdk_frame_parent_occurrence_invalid");
  }
  if (!isSha256(frame.occurrence_sha256)) blockers.push("sdk_frame_occurrence_digest_invalid");
  if (!isSha256(frame.previous_frame_sha256)) blockers.push("sdk_frame_previous_digest_invalid");
  if (!isSha256(frame.frame_sha256)) blockers.push("sdk_frame_digest_invalid");
  validateStateRootWithBlockers(frame.state_root_before, blockers, "sdk_state_root_before");
  try {
    validateOperationIdentity(operationIdentity(frame));
  } catch (error) {
    blockers.push(error instanceof Error ? error.message : "sdk_operation_identity_invalid");
  }
  const input = operationInput(frame);
  blockers.push(...contentReferenceBlockers(input).map((item) => `sdk_input:${item}`));
  if (input.storage !== "digest-only") blockers.push("sdk_raw_input_retention_refused");
  if (frame.occurrence_sha256 !== sdkOccurrenceSha256(frame)) {
    blockers.push("sdk_frame_occurrence_digest_mismatch");
  }
  if (frame.frame_sha256 !== recomputeSdkFrameDigest(frame)) blockers.push("sdk_frame_digest_mismatch");
  if (frame.frame_kind === "decision") blockers.push(...sdkPolicyBlockers(frame.policy, frame));
  else blockers.push(...sdkActionBlockers(frame));
  try {
    assertEvidenceSafe(frame);
  } catch (error) {
    blockers.push(error instanceof Error ? error.message : "sdk_frame_evidence_unsafe");
  }
  return blockers;
}

function sdkPolicyBlockers(policy: SdkPolicyReceipt, frame: SdkDecisionFrame): string[] {
  const blockers = exactKeyBlockers(
    policy,
    [
      "actor_id",
      "authority_scope_ids",
      "censor_kind",
      "decision",
      "evaluated_at",
      "occurrence_sha256",
      "operation_kind",
      "policy_sha256",
      "principal_id",
      "reason_codes",
      "receipt_sha256",
      "schema_version",
    ],
    "sdk_policy",
  );
  if (policy.schema_version !== "gradia.guard.sdk-policy-receipt.v1") {
    blockers.push("sdk_policy_schema_invalid");
  }
  if (
    policy.operation_kind !== frame.operation_kind ||
    policy.occurrence_sha256 !== frame.occurrence_sha256 ||
    policy.actor_id !== frame.actor_id ||
    policy.principal_id !== frame.principal_id ||
    canonicalJson(policy.authority_scope_ids) !== canonicalJson(frame.authority_scope_ids)
  ) {
    blockers.push("sdk_policy_frame_binding_mismatch");
  }
  if (!isSha256(policy.policy_sha256)) blockers.push("sdk_policy_digest_invalid");
  if (!validTimestamp(policy.evaluated_at) || policy.evaluated_at > frame.observed_at) {
    blockers.push("sdk_policy_timing_invalid");
  }
  try {
    assertSortedStableIds(policy.authority_scope_ids, "authority_scope_ids");
    assertSortedStableIds(policy.reason_codes, "sdk_policy_reason_codes");
    validatePolicyDecision({
      decision: policy.decision,
      censorKind: policy.censor_kind,
      reasonCodes: policy.reason_codes,
      policySha256: policy.policy_sha256,
    });
  } catch (error) {
    blockers.push(error instanceof Error ? error.message : "sdk_policy_shape_invalid");
  }
  const { receipt_sha256: _receipt, ...body } = policy;
  if (policy.receipt_sha256 !== digestCanonical(body)) blockers.push("sdk_policy_receipt_digest_mismatch");
  return blockers;
}

function sdkActionBlockers(frame: SdkActionFrame): string[] {
  const blockers: string[] = [];
  if (!isSha256(frame.policy_receipt_sha256)) blockers.push("sdk_action_policy_receipt_invalid");
  if (!validOutcome(frame.outcome)) blockers.push("sdk_action_outcome_invalid");
  validateStateRootWithBlockers(frame.state_root_after, blockers, "sdk_state_root_after");
  const output = operationOutput(frame);
  if (output !== null) {
    blockers.push(...contentReferenceBlockers(output).map((item) => `sdk_output:${item}`));
    if (output.storage !== "digest-only") blockers.push("sdk_raw_output_retention_refused");
  }
  if (frame.failure_code !== null) {
    try {
      assertStableId(frame.failure_code, "failure_code");
    } catch {
      blockers.push("sdk_failure_code_invalid");
    }
  }
  const censored = ["policy_censored", "budget_censored", "authority_censored"].includes(frame.outcome);
  if (censored) {
    if (
      frame.dispatch_occurred ||
      resolvedIdentity(frame) !== null ||
      output !== null ||
      frame.dispatch_started_at !== null ||
      frame.terminal_observed_at !== null ||
      frame.latency_ms !== null ||
      frame.failure_code === null ||
      canonicalJson(frame.state_root_after) !== canonicalJson(frame.state_root_before)
    ) {
      blockers.push("sdk_censor_shape_invalid");
    }
  } else {
    if (
      !frame.dispatch_occurred ||
      !frame.dispatch_started_at ||
      !frame.terminal_observed_at ||
      frame.latency_ms === null ||
      !Number.isSafeInteger(frame.latency_ms) ||
      frame.latency_ms < 0
    ) {
      blockers.push("sdk_dispatch_timing_missing");
    }
    if (
      frame.dispatch_started_at &&
      frame.terminal_observed_at &&
      (!validTimestamp(frame.dispatch_started_at) ||
        !validTimestamp(frame.terminal_observed_at) ||
        frame.dispatch_started_at > frame.terminal_observed_at ||
        frame.terminal_observed_at > frame.observed_at)
    ) {
      blockers.push("sdk_dispatch_timing_invalid");
    }
  }
  const resolved = resolvedIdentity(frame);
  if (resolved !== null) {
    try {
      validateOperationIdentity(resolved);
    } catch (error) {
      blockers.push(error instanceof Error ? error.message : "sdk_resolved_identity_invalid");
    }
  }
  const identityMatch = resolved !== null && canonicalJson(resolved) === canonicalJson(operationIdentity(frame));
  if (frame.outcome === "success") {
    if (!identityMatch || output === null || frame.failure_code !== null) blockers.push("sdk_success_shape_invalid");
  } else if (frame.outcome === "identity_mismatch") {
    if (resolved === null || identityMatch || !frame.failure_code?.startsWith("resolved_")) {
      blockers.push("sdk_identity_mismatch_shape_invalid");
    }
  } else if (frame.outcome === "decision_failure") {
    if (frame.operation_kind !== "application_decision" || frame.failure_code === null || (resolved !== null && !identityMatch)) {
      blockers.push("sdk_decision_failure_shape_invalid");
    }
  } else if (frame.outcome === "tool_failure") {
    if (frame.operation_kind !== "registered_tool_call" || frame.failure_code === null || (resolved !== null && !identityMatch)) {
      blockers.push("sdk_tool_failure_shape_invalid");
    }
  } else if (frame.outcome === "protocol_failure") {
    if (frame.failure_code === null || (resolved !== null && !identityMatch)) {
      blockers.push("sdk_protocol_failure_shape_invalid");
    }
  }
  return blockers;
}

function validatePolicyDecision(input: SdkPolicyDecisionInput): void {
  if (input.decision === "allowed" && input.censorKind !== null) {
    throw new Error("sdk_allowed_policy_has_censor");
  }
  if (input.decision === "blocked" && !["policy", "budget", "authority"].includes(input.censorKind ?? "")) {
    throw new Error("sdk_blocked_policy_censor_missing");
  }
  if (!["allowed", "blocked"].includes(input.decision)) throw new Error("sdk_policy_decision_invalid");
}

function censorOutcome(policy: SdkPolicyReceipt): SdkOutcome {
  if (policy.censor_kind === "budget") return "budget_censored";
  if (policy.censor_kind === "authority") return "authority_censored";
  return "policy_censored";
}

function optionalContentReference(
  body: Uint8Array | null,
  mediaType: string | null,
  label: string,
): ContentReference | null {
  if ((body === null) !== (mediaType === null)) throw new Error(`${label}_partial`);
  return body === null || mediaType === null ? null : sdkContentReference(body, mediaType);
}

function operationIdentity(frame: SdkEvidenceFrame): SdkDecisionIdentity | SdkToolIdentity {
  return frame.operation_kind === "application_decision" ? frame.decision_identity : frame.tool_identity;
}

function resolvedIdentity(frame: SdkActionFrame): SdkDecisionIdentity | SdkToolIdentity | null {
  return frame.operation_kind === "application_decision"
    ? frame.resolved_decision_identity
    : frame.resolved_tool_identity;
}

function operationInput(frame: SdkEvidenceFrame): ContentReference {
  return frame.operation_kind === "application_decision" ? frame.decision_input : frame.tool_request;
}

function operationOutput(frame: SdkActionFrame): ContentReference | null {
  return frame.operation_kind === "application_decision" ? frame.decision_output : frame.tool_result;
}

function validateOperationIdentity(value: SdkDecisionIdentity | SdkToolIdentity): void {
  if (value.schema_version === "gradia.guard.sdk-decision-identity.v1") validateDecisionIdentity(value);
  else if (value.schema_version === "gradia.guard.sdk-tool-identity.v1") validateToolIdentity(value);
  else throw new Error("sdk_operation_identity_schema_invalid");
}

function validateDecisionIdentity(value: SdkDecisionIdentity): void {
  assertExactKeys(
    value,
    ["contract_sha256", "decision_type", "executor_id", "executor_kind", "executor_version", "schema_version"],
    "sdk_decision_identity",
  );
  if (value.schema_version !== "gradia.guard.sdk-decision-identity.v1") {
    throw new Error("sdk_decision_identity_schema_invalid");
  }
  assertStableId(value.decision_type, "decision_type");
  if (!["model", "component", "human"].includes(value.executor_kind)) {
    throw new Error("sdk_decision_executor_kind_invalid");
  }
  assertPortableIdentity(value.executor_id, "decision_executor_id");
  assertExactVersion(value.executor_version, "decision_executor_version");
  if (!isSha256(value.contract_sha256)) throw new Error("sdk_decision_contract_digest_invalid");
}

function validateToolIdentity(value: SdkToolIdentity): void {
  assertExactKeys(
    value,
    ["interface_sha256", "registry_id", "schema_version", "tool_id", "tool_version"],
    "sdk_tool_identity",
  );
  if (value.schema_version !== "gradia.guard.sdk-tool-identity.v1") {
    throw new Error("sdk_tool_identity_schema_invalid");
  }
  assertStableId(value.registry_id, "tool_registry_id");
  assertPortableIdentity(value.tool_id, "tool_id");
  assertExactVersion(value.tool_version, "tool_version");
  if (!isSha256(value.interface_sha256)) throw new Error("sdk_tool_interface_digest_invalid");
}

function validateStateRoot(value: SdkStateRootIdentity | null): void {
  if (value === null) return;
  assertExactKeys(value, ["namespace_id", "root_sha256", "schema_version", "source"], "sdk_state_root");
  if (value.schema_version !== "gradia.guard.sdk-state-root.v1") throw new Error("sdk_state_root_schema_invalid");
  if (value.source !== "application_declared") throw new Error("sdk_state_root_source_invalid");
  assertStableId(value.namespace_id, "state_root_namespace_id");
  if (!isSha256(value.root_sha256)) throw new Error("sdk_state_root_digest_invalid");
}

function validateStateRootWithBlockers(
  value: SdkStateRootIdentity | null,
  blockers: string[],
  label: string,
): void {
  try {
    validateStateRoot(value);
  } catch (error) {
    blockers.push(error instanceof Error ? `${label}:${error.message}` : `${label}:invalid`);
  }
}

function cloneDecisionIdentity(value: SdkDecisionIdentity): SdkDecisionIdentity {
  return { ...value };
}

function cloneToolIdentity(value: SdkToolIdentity): SdkToolIdentity {
  return { ...value };
}

function cloneStateRoot(value: SdkStateRootIdentity | null): SdkStateRootIdentity | null {
  return value === null ? null : { ...value };
}

function assertPortableIdentity(value: string, field: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/.test(value)) throw new Error(`sdk_${field}_invalid`);
}

function assertExactVersion(value: string, field: string): void {
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/.test(value) ||
    !/[0-9]/.test(value) ||
    /(?:^|[._:/-])(?:latest|current|default|auto)(?:$|[._:/-])/i.test(value)
  ) {
    throw new Error(`sdk_${field}_not_exact_pin`);
  }
}

function assertSortedStableIds(values: readonly string[], field: string): void {
  if (!Array.isArray(values) || values.length === 0) throw new Error(`${field}_missing`);
  if (!isStrictCanonicalStringOrder(values)) {
    throw new Error(`${field}_not_canonical`);
  }
  values.forEach((value) => assertStableId(value, field));
}

function validOutcome(value: SdkOutcome): boolean {
  return [
    "success",
    "decision_failure",
    "tool_failure",
    "protocol_failure",
    "identity_mismatch",
    "policy_censored",
    "budget_censored",
    "authority_censored",
  ].includes(value);
}

function validTimestamp(value: string): boolean {
  return Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}

function exactKeyBlockers(value: object, expected: readonly string[], label: string): string[] {
  try {
    assertExactKeys(value, expected, label);
    return [];
  } catch {
    return [`${label}_fields_invalid`];
  }
}

function assertExactKeys(
  value: object,
  expected: readonly string[],
  label: string,
  allowMissingUndefined = false,
): void {
  const actual = Object.keys(value).sort();
  const wanted = allowMissingUndefined
    ? expected.filter((key) => Object.hasOwn(value, key)).sort()
    : [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label}_fields_invalid`);
  }
}
