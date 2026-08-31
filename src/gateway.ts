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
import { coverageBlockers, gatewayCoverage } from "./coverage.js";
import { contentReferenceBlockers } from "./frames.js";
import { assertEvidenceSafe, assertStableId } from "./security.js";
import {
  GATEWAY_BUNDLE_SCHEMA_VERSION,
  GATEWAY_FRAME_SCHEMA_VERSION,
  GENESIS_SHA256,
  type ContentReference,
  type GatewayActionFrame,
  type GatewayDecisionFrame,
  type GatewayEvidenceBundleManifest,
  type GatewayEvidenceFrame,
  type GatewayOutcome,
  type GatewayPolicyReceipt,
  type GatewayProvider,
  type GatewayUsage,
} from "./types.js";

const GUARD_VERSION = "0.1.0";

export interface GatewayPolicyDecisionInput {
  decision: "allowed" | "blocked";
  censorKind: "policy" | "budget" | null;
  reasonCodes: readonly string[];
  policySha256: string;
}

export interface PrepareGatewayAttemptInput {
  provider: GatewayProvider;
  requestedModel: string;
  logicalRequestId: string;
  attemptNumber: number;
  retryOfOccurrenceSha256: string | null;
  requestBody: Uint8Array;
  requestMediaType: string;
  policy: GatewayPolicyDecisionInput;
}

export interface GatewaySuccessInput {
  responseBody: Uint8Array;
  responseMediaType: string;
  resolvedModel: string;
  usage: GatewayUsage;
  httpStatus: number;
}

export interface GatewayFailureInput {
  outcome: "provider_failure" | "transport_failure" | "protocol_failure";
  responseBody: Uint8Array | null;
  responseMediaType: string | null;
  resolvedModel: string | null;
  usage: GatewayUsage | null;
  httpStatus: number | null;
  failureCode: string;
}

export interface GatewayRecorderOptions {
  directory: string;
  sessionId?: string;
  now?: () => Date;
  monotonicMs?: () => number;
}

export class GatewayIdentityMismatchError extends Error {
  readonly frame: GatewayActionFrame;

  constructor(frame: GatewayActionFrame) {
    super("gateway_resolved_model_identity_mismatch");
    this.name = "GatewayIdentityMismatchError";
    this.frame = frame;
  }
}

export class GatewayAttempt {
  readonly occurrenceSha256: string;
  readonly censored: boolean;
  private readonly recorder: GatewayRecorder;
  private readonly decisionFrame: GatewayDecisionFrame;
  private dispatchStartedAt: string | null = null;
  private dispatchMonotonicMs: number | null = null;
  private closed: boolean;

  constructor(
    recorder: GatewayRecorder,
    decisionFrame: GatewayDecisionFrame,
    censored: boolean,
  ) {
    this.recorder = recorder;
    this.decisionFrame = decisionFrame;
    this.occurrenceSha256 = decisionFrame.occurrence_sha256;
    this.censored = censored;
    this.closed = censored;
  }

  markDispatched(): void {
    if (this.censored) throw new Error("gateway_censored_attempt_cannot_dispatch");
    if (this.closed) throw new Error("gateway_attempt_already_closed");
    if (this.dispatchStartedAt !== null) throw new Error("gateway_attempt_already_dispatched");
    this.dispatchStartedAt = this.recorder.wallTime();
    this.dispatchMonotonicMs = this.recorder.monotonicTime();
  }

  succeed(input: GatewaySuccessInput): GatewayActionFrame {
    assertExactKeys(
      input,
      ["httpStatus", "resolvedModel", "responseBody", "responseMediaType", "usage"],
      "gateway_success_input",
    );
    this.assertDispatchedAndOpen();
    assertModelPin(input.resolvedModel, "resolved_model");
    validateUsage(input.usage);
    assertHttpStatus(input.httpStatus);
    if (input.httpStatus < 200 || input.httpStatus > 299) {
      throw new Error("gateway_success_http_status_invalid");
    }
    const response = gatewayContentReference(input.responseBody, input.responseMediaType);
    const identityMatch = input.resolvedModel === this.decisionFrame.requested_model;
    const frame = this.finish({
      outcome: identityMatch ? "success" : "identity_mismatch",
      dispatchOccurred: true,
      resolvedModel: input.resolvedModel,
      response,
      usage: { ...input.usage },
      httpStatus: input.httpStatus,
      failureCode: identityMatch ? null : "resolved_model_identity_mismatch",
    });
    if (!identityMatch) throw new GatewayIdentityMismatchError(frame);
    return frame;
  }

  fail(input: GatewayFailureInput): GatewayActionFrame {
    assertExactKeys(
      input,
      [
        "failureCode",
        "httpStatus",
        "outcome",
        "resolvedModel",
        "responseBody",
        "responseMediaType",
        "usage",
      ],
      "gateway_failure_input",
    );
    this.assertDispatchedAndOpen();
    assertStableId(input.failureCode, "failure_code");
    if (!["provider_failure", "transport_failure", "protocol_failure"].includes(input.outcome)) {
      throw new Error("gateway_failure_outcome_invalid");
    }
    if (input.resolvedModel !== null) {
      assertModelPin(input.resolvedModel, "resolved_model");
      if (input.resolvedModel !== this.decisionFrame.requested_model) {
        throw new Error("gateway_failure_identity_mismatch_requires_identity_outcome");
      }
    }
    if (input.usage !== null) validateUsage(input.usage);
    if (input.httpStatus !== null) assertHttpStatus(input.httpStatus);
    if (input.outcome === "transport_failure") {
      if (
        input.responseBody !== null ||
        input.responseMediaType !== null ||
        input.resolvedModel !== null ||
        input.usage !== null ||
        input.httpStatus !== null
      ) {
        throw new Error("gateway_transport_failure_has_provider_response");
      }
    } else {
      if (input.responseBody === null || input.responseMediaType === null || input.httpStatus === null) {
        throw new Error("gateway_response_failure_missing_response_evidence");
      }
      if (input.outcome === "provider_failure" && input.httpStatus < 400) {
        throw new Error("gateway_provider_failure_http_status_invalid");
      }
    }
    const response =
      input.responseBody === null || input.responseMediaType === null
        ? null
        : gatewayContentReference(input.responseBody, input.responseMediaType);
    return this.finish({
      outcome: input.outcome,
      dispatchOccurred: true,
      resolvedModel: input.resolvedModel,
      response,
      usage: input.usage,
      httpStatus: input.httpStatus,
      failureCode: input.failureCode,
    });
  }

  private assertDispatchedAndOpen(): void {
    if (this.closed) throw new Error("gateway_attempt_already_closed");
    if (this.dispatchStartedAt === null || this.dispatchMonotonicMs === null) {
      throw new Error("gateway_attempt_not_marked_dispatched");
    }
  }

  private finish(input: {
    outcome: GatewayOutcome;
    dispatchOccurred: boolean;
    resolvedModel: string | null;
    response: ContentReference | null;
    usage: GatewayUsage | null;
    httpStatus: number | null;
    failureCode: string | null;
  }): GatewayActionFrame {
    if (this.dispatchStartedAt === null || this.dispatchMonotonicMs === null) {
      throw new Error("gateway_attempt_not_marked_dispatched");
    }
    const terminalObservedAt = this.recorder.wallTime();
    const latencyMs = Math.max(0, Math.round(this.recorder.monotonicTime() - this.dispatchMonotonicMs));
    this.closed = true;
    return this.recorder.closeAttempt(this.decisionFrame, {
      outcome: input.outcome,
      dispatch_occurred: input.dispatchOccurred,
      resolved_model: input.resolvedModel,
      response: input.response,
      usage: input.usage,
      http_status: input.httpStatus,
      failure_code: input.failureCode,
      dispatch_started_at: this.dispatchStartedAt,
      terminal_observed_at: terminalObservedAt,
      response_received_at: input.response === null ? null : terminalObservedAt,
      latency_ms: latencyMs,
    });
  }
}

export class GatewayRecorder {
  readonly directory: string;
  readonly sessionId: string;
  private readonly now: () => Date;
  private readonly monotonicMs: () => number;
  private readonly frameChain: GatewayFrameChain;
  private readonly framesPath: string;
  private readonly manifestPath: string;
  private manifest: GatewayEvidenceBundleManifest;
  private openAttempts = 0;
  private readonly logicalOccurrences = new Map<string, Map<number, string>>();

  constructor(options: GatewayRecorderOptions) {
    assertExactKeys(options, ["directory", "monotonicMs", "now", "sessionId"], "gateway_recorder_options", true);
    this.now = options.now ?? (() => new Date());
    this.monotonicMs = options.monotonicMs ?? (() => Number(process.hrtime.bigint() / 1_000_000n));
    this.sessionId = options.sessionId ?? randomUUID();
    assertStableId(this.sessionId, "session_id");
    this.directory = resolve(options.directory);
    if (existsSync(this.directory)) throw new Error("gateway_bundle_directory_exists");
    mkdirSync(this.directory, { recursive: true, mode: 0o700 });
    this.framesPath = join(this.directory, "frames.ndjson");
    this.manifestPath = join(this.directory, "bundle.json");
    writeFileSync(this.framesPath, "", { mode: 0o600, flag: "wx" });
    const coverage = gatewayCoverage();
    this.frameChain = new GatewayFrameChain(this.sessionId, coverage, () => this.wallTime());
    this.manifest = {
      schema_version: GATEWAY_BUNDLE_SCHEMA_VERSION,
      guard_version: GUARD_VERSION,
      session_id: this.sessionId,
      created_at: this.wallTime(),
      finalized_at: null,
      status: "recording",
      capture_mode: "digest-only",
      coverage,
      capture_boundary: "explicit_recorder",
      bypass_possible: true,
      bypass_declaration: "calls_outside_this_recorder_are_not_observed",
      frame_count: 0,
      attempt_count: 0,
      chain_head_sha256: GENESIS_SHA256,
    };
    this.writeManifest();
  }

  prepare(input: PrepareGatewayAttemptInput): GatewayAttempt {
    if (this.manifest.status !== "recording") throw new Error("gateway_recorder_finalized");
    assertExactKeys(
      input,
      [
        "attemptNumber",
        "logicalRequestId",
        "policy",
        "provider",
        "requestBody",
        "requestMediaType",
        "requestedModel",
        "retryOfOccurrenceSha256",
      ],
      "gateway_prepare_input",
    );
    assertExactKeys(
      input.policy,
      ["censorKind", "decision", "policySha256", "reasonCodes"],
      "gateway_policy_input",
    );
    assertProvider(input.provider);
    assertModelPin(input.requestedModel, "requested_model");
    assertStableId(input.logicalRequestId, "logical_request_id");
    if (!Number.isSafeInteger(input.attemptNumber) || input.attemptNumber < 1) {
      throw new Error("gateway_attempt_number_invalid");
    }
    if (input.attemptNumber === 1 && input.retryOfOccurrenceSha256 !== null) {
      throw new Error("gateway_first_attempt_has_retry_parent");
    }
    if (input.attemptNumber > 1 && !isSha256(input.retryOfOccurrenceSha256)) {
      throw new Error("gateway_retry_parent_missing");
    }
    if (!isSha256(input.policy.policySha256)) throw new Error("gateway_policy_digest_invalid");
    assertSortedStableIds(input.policy.reasonCodes, "gateway_policy_reason_codes");
    if (input.policy.decision === "allowed" && input.policy.censorKind !== null) {
      throw new Error("gateway_allowed_policy_has_censor");
    }
    if (input.policy.decision === "blocked" && !["policy", "budget"].includes(input.policy.censorKind ?? "")) {
      throw new Error("gateway_blocked_policy_censor_missing");
    }
    const request = gatewayContentReference(input.requestBody, input.requestMediaType);
    const occurrenceBody = {
      schema_version: "gradia.guard.gateway-occurrence.v1",
      provider: input.provider,
      requested_model: input.requestedModel,
      logical_request_id: input.logicalRequestId,
      attempt_number: input.attemptNumber,
      retry_of_occurrence_sha256: input.retryOfOccurrenceSha256,
      request_sha256: request.plaintext_sha256,
    };
    const occurrenceSha256 = digestCanonical(occurrenceBody);
    const priorAttempts = this.logicalOccurrences.get(input.logicalRequestId) ?? new Map<number, string>();
    if (priorAttempts.has(input.attemptNumber)) throw new Error("gateway_logical_attempt_duplicate");
    if (
      input.attemptNumber > 1 &&
      priorAttempts.get(input.attemptNumber - 1) !== input.retryOfOccurrenceSha256
    ) {
      throw new Error("gateway_retry_parent_not_recorded");
    }
    const evaluatedAt = this.wallTime();
    const policyBody = {
      schema_version: "gradia.guard.gateway-policy-receipt.v1",
      provider: input.provider,
      requested_model: input.requestedModel,
      logical_request_id: input.logicalRequestId,
      attempt_number: input.attemptNumber,
      request_sha256: request.plaintext_sha256,
      decision: input.policy.decision,
      censor_kind: input.policy.censorKind,
      reason_codes: [...input.policy.reasonCodes],
      policy_sha256: input.policy.policySha256,
      evaluated_at: evaluatedAt,
    } as const;
    const policy: GatewayPolicyReceipt = {
      ...policyBody,
      receipt_sha256: digestCanonical(policyBody),
    };
    const decision = this.frameChain.decision({
      provider: input.provider,
      requested_model: input.requestedModel,
      logical_request_id: input.logicalRequestId,
      attempt_number: input.attemptNumber,
      retry_of_occurrence_sha256: input.retryOfOccurrenceSha256,
      occurrence_sha256: occurrenceSha256,
      request,
      policy,
    });
    this.append(decision);
    priorAttempts.set(input.attemptNumber, occurrenceSha256);
    this.logicalOccurrences.set(input.logicalRequestId, priorAttempts);
    if (policy.decision === "blocked") {
      const action = this.frameChain.action({
        decision,
        outcome: policy.censor_kind === "budget" ? "budget_censored" : "policy_censored",
        dispatch_occurred: false,
        resolved_model: null,
        response: null,
        usage: null,
        http_status: null,
        dispatch_started_at: null,
        terminal_observed_at: null,
        response_received_at: null,
        latency_ms: null,
        failure_code: policy.reason_codes[0] ?? "pre_dispatch_censored",
      });
      this.append(action);
      this.manifest.attempt_count += 1;
      this.writeManifest();
      return new GatewayAttempt(this, decision, true);
    }
    this.openAttempts += 1;
    return new GatewayAttempt(this, decision, false);
  }

  finalize(): void {
    if (this.manifest.status !== "recording") return;
    if (this.openAttempts !== 0) throw new Error("gateway_open_attempts_prevent_finalization");
    if (this.manifest.attempt_count === 0) throw new Error("gateway_empty_bundle_cannot_finalize");
    this.manifest.status = "finalized";
    this.manifest.finalized_at = this.wallTime();
    this.writeManifest();
  }

  wallTime(): string {
    return this.now().toISOString();
  }

  monotonicTime(): number {
    const value = this.monotonicMs();
    if (!Number.isFinite(value) || value < 0) throw new Error("gateway_monotonic_clock_invalid");
    return value;
  }

  closeAttempt(
    decision: GatewayDecisionFrame,
    terminal: Omit<
      GatewayActionFrame,
      | "schema_version"
      | "session_id"
      | "sequence"
      | "frame_kind"
      | "observed_at"
      | "coverage"
      | "provider"
      | "requested_model"
      | "logical_request_id"
      | "attempt_number"
      | "retry_of_occurrence_sha256"
      | "occurrence_sha256"
      | "request"
      | "policy_receipt_sha256"
      | "previous_frame_sha256"
      | "frame_sha256"
    >,
  ): GatewayActionFrame {
    if (this.openAttempts < 1) throw new Error("gateway_open_attempt_accounting_invalid");
    const action = this.frameChain.action({ decision, ...terminal });
    this.append(action);
    this.openAttempts -= 1;
    this.manifest.attempt_count += 1;
    this.writeManifest();
    return action;
  }

  private append(frame: GatewayEvidenceFrame): void {
    const blockers = gatewayFrameBlockers(frame);
    if (blockers.length) throw new Error(blockers.join(","));
    if (frame.session_id !== this.manifest.session_id) throw new Error("gateway_spool_session_mismatch");
    if (frame.sequence !== this.manifest.frame_count) throw new Error("gateway_spool_sequence_mismatch");
    if (frame.previous_frame_sha256 !== this.manifest.chain_head_sha256) {
      throw new Error("gateway_spool_previous_hash_mismatch");
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

class GatewayFrameChain {
  private sequence = 0;
  private head: string = GENESIS_SHA256;

  constructor(
    private readonly sessionId: string,
    private readonly coverage: ReturnType<typeof gatewayCoverage>,
    private readonly now: () => string,
  ) {}

  decision(
    input: Omit<
      GatewayDecisionFrame,
      | "schema_version"
      | "session_id"
      | "sequence"
      | "frame_kind"
      | "observed_at"
      | "coverage"
      | "previous_frame_sha256"
      | "frame_sha256"
    >,
  ): GatewayDecisionFrame {
    return this.append({ ...input, frame_kind: "decision" }) as GatewayDecisionFrame;
  }

  action(
    input: {
      decision: GatewayDecisionFrame;
      outcome: GatewayOutcome;
      dispatch_occurred: boolean;
      resolved_model: string | null;
      response: ContentReference | null;
      usage: GatewayUsage | null;
      http_status: number | null;
      dispatch_started_at: string | null;
      terminal_observed_at: string | null;
      response_received_at: string | null;
      latency_ms: number | null;
      failure_code: string | null;
    },
  ): GatewayActionFrame {
    const { decision, ...terminal } = input;
    return this.append({
      frame_kind: "action",
      provider: decision.provider,
      requested_model: decision.requested_model,
      logical_request_id: decision.logical_request_id,
      attempt_number: decision.attempt_number,
      retry_of_occurrence_sha256: decision.retry_of_occurrence_sha256,
      occurrence_sha256: decision.occurrence_sha256,
      request: decision.request,
      policy_receipt_sha256: decision.policy.receipt_sha256,
      ...terminal,
    }) as GatewayActionFrame;
  }

  private append(input: object): GatewayEvidenceFrame {
    const body = {
      schema_version: GATEWAY_FRAME_SCHEMA_VERSION,
      session_id: this.sessionId,
      sequence: this.sequence,
      observed_at: this.now(),
      coverage: this.coverage,
      ...input,
      previous_frame_sha256: this.head,
    };
    assertEvidenceSafe(body);
    const frame = { ...body, frame_sha256: digestCanonical(body) } as GatewayEvidenceFrame;
    const blockers = gatewayFrameBlockers(frame);
    if (blockers.length) throw new Error(blockers.join(","));
    this.sequence += 1;
    this.head = frame.frame_sha256;
    return frame;
  }
}

export function gatewayContentReference(content: Uint8Array, mediaType: string): ContentReference {
  if (!(content instanceof Uint8Array) || content.byteLength === 0) {
    throw new Error("gateway_content_bytes_missing");
  }
  if (!/^[\x20-\x7e]{1,200}$/.test(mediaType)) throw new Error("gateway_content_media_type_invalid");
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

export function gatewayFrameBlockers(frame: GatewayEvidenceFrame): string[] {
  const blockers: string[] = [];
  const common = [
    "attempt_number",
    "coverage",
    "frame_kind",
    "frame_sha256",
    "logical_request_id",
    "observed_at",
    "occurrence_sha256",
    "previous_frame_sha256",
    "provider",
    "request",
    "requested_model",
    "retry_of_occurrence_sha256",
    "schema_version",
    "sequence",
    "session_id",
  ];
  blockers.push(
    ...exactKeyBlockers(
      frame,
      frame.frame_kind === "decision"
        ? [...common, "policy"]
        : [
            ...common,
            "dispatch_occurred",
            "dispatch_started_at",
            "failure_code",
            "http_status",
            "latency_ms",
            "outcome",
            "policy_receipt_sha256",
            "resolved_model",
            "response",
            "response_received_at",
            "terminal_observed_at",
            "usage",
          ],
      "gateway_frame",
    ),
  );
  if (frame.schema_version !== GATEWAY_FRAME_SCHEMA_VERSION) blockers.push("gateway_frame_schema_invalid");
  try {
    assertStableId(frame.session_id, "session_id");
    assertProvider(frame.provider);
    assertModelPin(frame.requested_model, "requested_model");
    assertStableId(frame.logical_request_id, "logical_request_id");
  } catch (error) {
    blockers.push(error instanceof Error ? error.message : "gateway_frame_identity_invalid");
  }
  if (!Number.isSafeInteger(frame.sequence) || frame.sequence < 0) blockers.push("gateway_frame_sequence_invalid");
  if (!validTimestamp(frame.observed_at)) blockers.push("gateway_frame_timestamp_invalid");
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
      "gateway_coverage",
    ),
  );
  blockers.push(...coverageBlockers(frame.coverage));
  if (frame.coverage.tier !== "gateway") blockers.push("gateway_frame_coverage_tier_invalid");
  if (!Number.isSafeInteger(frame.attempt_number) || frame.attempt_number < 1) {
    blockers.push("gateway_frame_attempt_number_invalid");
  }
  if (frame.attempt_number === 1 && frame.retry_of_occurrence_sha256 !== null) {
    blockers.push("gateway_frame_first_attempt_has_retry_parent");
  }
  if (frame.attempt_number > 1 && !isSha256(frame.retry_of_occurrence_sha256)) {
    blockers.push("gateway_frame_retry_parent_missing");
  }
  if (!isSha256(frame.occurrence_sha256)) blockers.push("gateway_frame_occurrence_digest_invalid");
  if (!isSha256(frame.previous_frame_sha256)) blockers.push("gateway_frame_previous_digest_invalid");
  if (!isSha256(frame.frame_sha256)) blockers.push("gateway_frame_digest_invalid");
  blockers.push(...contentReferenceBlockers(frame.request).map((item) => `gateway_request:${item}`));
  if (frame.request.storage !== "digest-only") blockers.push("gateway_raw_request_retention_refused");
  if (frame.occurrence_sha256 !== gatewayOccurrenceSha256(frame)) {
    blockers.push("gateway_frame_occurrence_digest_mismatch");
  }
  if (frame.frame_sha256 !== recomputeGatewayFrameDigest(frame)) blockers.push("gateway_frame_digest_mismatch");
  if (frame.frame_kind === "decision") blockers.push(...gatewayPolicyBlockers(frame.policy, frame));
  else blockers.push(...gatewayActionBlockers(frame));
  try {
    assertEvidenceSafe(frame);
  } catch (error) {
    blockers.push(error instanceof Error ? error.message : "gateway_frame_evidence_unsafe");
  }
  return blockers;
}

function gatewayPolicyBlockers(
  policy: GatewayPolicyReceipt,
  frame: GatewayDecisionFrame,
): string[] {
  const blockers = exactKeyBlockers(
    policy,
    [
      "attempt_number",
      "censor_kind",
      "decision",
      "evaluated_at",
      "logical_request_id",
      "policy_sha256",
      "provider",
      "reason_codes",
      "receipt_sha256",
      "request_sha256",
      "requested_model",
      "schema_version",
    ],
    "gateway_policy",
  );
  if (policy.schema_version !== "gradia.guard.gateway-policy-receipt.v1") {
    blockers.push("gateway_policy_schema_invalid");
  }
  if (
    policy.provider !== frame.provider ||
    policy.requested_model !== frame.requested_model ||
    policy.logical_request_id !== frame.logical_request_id ||
    policy.attempt_number !== frame.attempt_number ||
    policy.request_sha256 !== frame.request.plaintext_sha256
  ) {
    blockers.push("gateway_policy_frame_binding_mismatch");
  }
  if (!isSha256(policy.policy_sha256)) blockers.push("gateway_policy_digest_invalid");
  if (!validTimestamp(policy.evaluated_at) || policy.evaluated_at > frame.observed_at) {
    blockers.push("gateway_policy_timing_invalid");
  }
  try {
    assertSortedStableIds(policy.reason_codes, "gateway_policy_reason_codes");
  } catch {
    blockers.push("gateway_policy_reason_codes_invalid");
  }
  if (policy.decision === "allowed" && policy.censor_kind !== null) {
    blockers.push("gateway_allowed_policy_has_censor");
  } else if (policy.decision === "blocked" && !["policy", "budget"].includes(policy.censor_kind ?? "")) {
    blockers.push("gateway_blocked_policy_censor_missing");
  } else if (!["allowed", "blocked"].includes(policy.decision)) {
    blockers.push("gateway_policy_decision_invalid");
  }
  const { receipt_sha256: _receipt, ...body } = policy;
  if (policy.receipt_sha256 !== digestCanonical(body)) blockers.push("gateway_policy_receipt_digest_mismatch");
  return blockers;
}

function gatewayActionBlockers(frame: GatewayActionFrame): string[] {
  const blockers: string[] = [];
  if (!isSha256(frame.policy_receipt_sha256)) blockers.push("gateway_action_policy_receipt_invalid");
  if (
    ![
      "success",
      "provider_failure",
      "transport_failure",
      "protocol_failure",
      "identity_mismatch",
      "policy_censored",
      "budget_censored",
    ].includes(frame.outcome)
  ) {
    blockers.push("gateway_action_outcome_invalid");
  }
  if (frame.resolved_model !== null) {
    try {
      assertModelPin(frame.resolved_model, "resolved_model");
    } catch {
      blockers.push("gateway_resolved_model_invalid");
    }
  }
  if (frame.response !== null) {
    blockers.push(...contentReferenceBlockers(frame.response).map((item) => `gateway_response:${item}`));
    if (frame.response.storage !== "digest-only") blockers.push("gateway_raw_response_retention_refused");
  }
  if (frame.usage !== null) {
    try {
      validateUsage(frame.usage);
    } catch (error) {
      blockers.push(error instanceof Error ? error.message : "gateway_usage_invalid");
    }
  }
  if (frame.http_status !== null) {
    try {
      assertHttpStatus(frame.http_status);
    } catch {
      blockers.push("gateway_http_status_invalid");
    }
  }
  if (frame.failure_code !== null) {
    try {
      assertStableId(frame.failure_code, "failure_code");
    } catch {
      blockers.push("gateway_failure_code_invalid");
    }
  }
  const censored = frame.outcome === "policy_censored" || frame.outcome === "budget_censored";
  if (censored) {
    if (
      frame.dispatch_occurred ||
      frame.resolved_model !== null ||
      frame.response !== null ||
      frame.usage !== null ||
      frame.http_status !== null ||
      frame.dispatch_started_at !== null ||
      frame.terminal_observed_at !== null ||
      frame.response_received_at !== null ||
      frame.latency_ms !== null ||
      frame.failure_code === null
    ) {
      blockers.push("gateway_censor_shape_invalid");
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
      blockers.push("gateway_dispatch_timing_missing");
    }
    if (
      frame.dispatch_started_at &&
      frame.terminal_observed_at &&
      (!validTimestamp(frame.dispatch_started_at) ||
        !validTimestamp(frame.terminal_observed_at) ||
        frame.dispatch_started_at > frame.terminal_observed_at ||
        frame.terminal_observed_at > frame.observed_at)
    ) {
      blockers.push("gateway_dispatch_timing_invalid");
    }
    if (
      (frame.response === null && frame.response_received_at !== null) ||
      (frame.response !== null && frame.response_received_at !== frame.terminal_observed_at)
    ) {
      blockers.push("gateway_response_timing_invalid");
    }
  }
  if (frame.outcome === "success") {
    if (
      frame.resolved_model !== frame.requested_model ||
      frame.response === null ||
      frame.usage === null ||
      frame.http_status === null ||
      frame.http_status < 200 ||
      frame.http_status > 299 ||
      frame.failure_code !== null
    ) {
      blockers.push("gateway_success_shape_invalid");
    }
  } else if (frame.outcome === "identity_mismatch") {
    if (
      frame.resolved_model === null ||
      frame.resolved_model === frame.requested_model ||
      frame.response === null ||
      frame.usage === null ||
      frame.http_status === null ||
      frame.http_status < 200 ||
      frame.http_status > 299 ||
      frame.failure_code !== "resolved_model_identity_mismatch"
    ) {
      blockers.push("gateway_identity_mismatch_shape_invalid");
    }
  } else if (frame.outcome === "transport_failure") {
    if (
      frame.resolved_model !== null ||
      frame.response !== null ||
      frame.usage !== null ||
      frame.http_status !== null ||
      frame.failure_code === null
    ) {
      blockers.push("gateway_transport_failure_shape_invalid");
    }
  } else if (frame.outcome === "provider_failure") {
    if (frame.response === null || frame.http_status === null || frame.http_status < 400 || frame.failure_code === null) {
      blockers.push("gateway_provider_failure_shape_invalid");
    }
  } else if (frame.outcome === "protocol_failure") {
    if (frame.response === null || frame.http_status === null || frame.failure_code === null) {
      blockers.push("gateway_protocol_failure_shape_invalid");
    }
  }
  if (
    frame.resolved_model !== null &&
    frame.outcome !== "identity_mismatch" &&
    frame.resolved_model !== frame.requested_model
  ) {
    blockers.push("gateway_resolved_model_identity_mismatch");
  }
  if (
    censored &&
    frame.failure_code !== null &&
    frame.frame_kind === "action"
  ) {
    // The exact policy receipt is checked against the paired decision offline.
    // This local check keeps the field a non-secret stable code.
    try {
      assertStableId(frame.failure_code, "failure_code");
    } catch {
      blockers.push("gateway_censor_reason_invalid");
    }
  }
  return blockers;
}

export function gatewayOccurrenceSha256(frame: GatewayEvidenceFrame): string {
  return digestCanonical({
    schema_version: "gradia.guard.gateway-occurrence.v1",
    provider: frame.provider,
    requested_model: frame.requested_model,
    logical_request_id: frame.logical_request_id,
    attempt_number: frame.attempt_number,
    retry_of_occurrence_sha256: frame.retry_of_occurrence_sha256,
    request_sha256: frame.request.plaintext_sha256,
  });
}

export function recomputeGatewayFrameDigest(frame: GatewayEvidenceFrame): string {
  const { frame_sha256: _digest, ...body } = frame;
  return digestCanonical(body);
}

export function assertModelPin(value: string, field: string): void {
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/.test(value) ||
    !/[0-9]/.test(value) ||
    /(?:^|[._:/-])(?:latest|current|default|auto)(?:$|[._:/-])/i.test(value)
  ) {
    throw new Error(`gateway_${field}_not_exact_pin`);
  }
}

function assertProvider(value: GatewayProvider): void {
  if (!["anthropic", "openai", "xai", "gemini"].includes(value) && !/^custom:[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$/.test(value)) {
    throw new Error("gateway_provider_invalid");
  }
}

function validateUsage(value: GatewayUsage): void {
  assertExactKeys(
    value,
    [
      "cache_read_input_tokens",
      "cache_write_input_tokens",
      "input_tokens",
      "output_tokens",
      "provider_total_tokens",
    ],
    "gateway_usage",
  );
  for (const [key, item] of Object.entries(value)) {
    if (item !== null && (!Number.isSafeInteger(item) || item < 0)) {
      throw new Error(`gateway_usage_invalid:${key}`);
    }
  }
  if (
    value.provider_total_tokens !== null &&
    value.provider_total_tokens < value.input_tokens + value.output_tokens
  ) {
    throw new Error("gateway_usage_total_inconsistent");
  }
}

function assertHttpStatus(value: number): void {
  if (!Number.isSafeInteger(value) || value < 100 || value > 599) {
    throw new Error("gateway_http_status_invalid");
  }
}

function assertSortedStableIds(values: readonly string[], field: string): void {
  if (!Array.isArray(values) || values.length === 0) throw new Error(`${field}_missing`);
  if (!isStrictCanonicalStringOrder(values)) {
    throw new Error(`${field}_not_canonical`);
  }
  values.forEach((value) => assertStableId(value, field));
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
