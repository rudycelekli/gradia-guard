export const FRAME_SCHEMA_VERSION = "gradia.guard.frame.v1" as const;
export const BUNDLE_SCHEMA_VERSION = "gradia.guard.bundle.v1" as const;
export const GATEWAY_FRAME_SCHEMA_VERSION = "gradia.guard.gateway-frame.v1" as const;
export const GATEWAY_BUNDLE_SCHEMA_VERSION = "gradia.guard.gateway-bundle.v1" as const;
export const SDK_FRAME_SCHEMA_VERSION = "gradia.guard.sdk-frame.v1" as const;
export const SDK_BUNDLE_SCHEMA_VERSION = "gradia.guard.sdk-bundle.v1" as const;
export const GENESIS_SHA256 =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" as const;

export type CaptureTier = "process" | "gateway" | "sdk" | "runtime" | "universe";
export type CaptureMode = "digest-only" | "encrypted";
export type FrameKind = "decision" | "action";

export interface ContentReference {
  schema_version: "gradia.guard.content-ref.v1";
  media_type: string;
  byte_length: number;
  plaintext_sha256: string;
  storage: "digest-only" | "aes-256-gcm";
  ciphertext_ref: string | null;
  ciphertext_sha256: string | null;
  key_id: string | null;
}

export interface CoverageAttestation {
  schema_version: "gradia.guard.coverage.v1";
  tier: CaptureTier;
  observed_surfaces: readonly string[];
  unobserved_surfaces: readonly string[];
  isolation_enforced: boolean;
  visibility_boundary_enforced: boolean;
  full_world_capture: boolean;
}

export interface FrameSubject {
  kind: "process" | "model_call" | "tool_call" | "decision" | "world_transition";
  identity_sha256: string;
}

interface FrameBase {
  schema_version: typeof FRAME_SCHEMA_VERSION;
  session_id: string;
  sequence: number;
  frame_kind: FrameKind;
  observed_at: string;
  subject: FrameSubject;
  coverage: CoverageAttestation;
  inputs: readonly ContentReference[];
  outputs: readonly ContentReference[];
  authority_scope_ids: readonly string[];
  policy_sha256: string | null;
  previous_frame_sha256: string;
  frame_sha256: string;
}

export interface DecisionFrame extends FrameBase {
  frame_kind: "decision";
  decision: {
    kind: "process_dispatch" | "model_dispatch" | "tool_dispatch" | "policy_evaluation";
    verdict: "allowed" | "blocked" | "observed_violation";
    reason_codes: readonly string[];
  };
}

export interface ActionFrame extends FrameBase {
  frame_kind: "action";
  action: {
    kind:
      | "process_started"
      | "stdout_chunk"
      | "stderr_chunk"
      | "process_terminal"
      | "wrapper_failure"
      | "model_response"
      | "tool_result"
      | "world_transition";
    disposition: "running" | "completed" | "failed" | "signaled" | "blocked";
    exit_code: number | null;
    signal: string | null;
    reason_codes: readonly string[];
  };
}

export type EvidenceFrame = DecisionFrame | ActionFrame;

export interface EvidenceBundleManifest {
  schema_version: typeof BUNDLE_SCHEMA_VERSION;
  guard_version: string;
  session_id: string;
  created_at: string;
  finalized_at: string | null;
  status: "recording" | "finalized" | "aborted";
  capture_mode: CaptureMode;
  coverage: CoverageAttestation;
  command_identity_sha256: string;
  frame_count: number;
  chain_head_sha256: string;
  terminal_disposition: "completed" | "failed" | "signaled" | "wrapper_failure" | null;
}

export interface VerificationResult {
  ok: boolean;
  blockers: readonly string[];
  session_id: string | null;
  frame_count: number;
  chain_head_sha256: string | null;
  payloads_checked: number;
  payloads_unavailable: number;
}

export type GatewayProvider =
  | "anthropic"
  | "openai"
  | "xai"
  | "gemini"
  | `custom:${string}`;

export interface GatewayUsage {
  input_tokens: number;
  output_tokens: number;
  cache_read_input_tokens: number | null;
  cache_write_input_tokens: number | null;
  provider_total_tokens: number | null;
}

export interface GatewayPolicyReceipt {
  schema_version: "gradia.guard.gateway-policy-receipt.v1";
  provider: GatewayProvider;
  requested_model: string;
  logical_request_id: string;
  attempt_number: number;
  request_sha256: string;
  decision: "allowed" | "blocked";
  censor_kind: "policy" | "budget" | null;
  reason_codes: readonly string[];
  policy_sha256: string;
  evaluated_at: string;
  receipt_sha256: string;
}

export interface GatewayOccurrenceIdentity {
  schema_version: "gradia.guard.gateway-occurrence.v1";
  provider: GatewayProvider;
  requested_model: string;
  logical_request_id: string;
  attempt_number: number;
  retry_of_occurrence_sha256: string | null;
  request_sha256: string;
  occurrence_sha256: string;
}

interface GatewayFrameBase {
  schema_version: typeof GATEWAY_FRAME_SCHEMA_VERSION;
  session_id: string;
  sequence: number;
  frame_kind: FrameKind;
  observed_at: string;
  coverage: CoverageAttestation;
  provider: GatewayProvider;
  requested_model: string;
  logical_request_id: string;
  attempt_number: number;
  retry_of_occurrence_sha256: string | null;
  occurrence_sha256: string;
  request: ContentReference;
  previous_frame_sha256: string;
  frame_sha256: string;
}

export interface GatewayDecisionFrame extends GatewayFrameBase {
  frame_kind: "decision";
  policy: GatewayPolicyReceipt;
}

export type GatewayOutcome =
  | "success"
  | "provider_failure"
  | "transport_failure"
  | "protocol_failure"
  | "identity_mismatch"
  | "policy_censored"
  | "budget_censored";

export interface GatewayActionFrame extends GatewayFrameBase {
  frame_kind: "action";
  policy_receipt_sha256: string;
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
}

export type GatewayEvidenceFrame = GatewayDecisionFrame | GatewayActionFrame;

export interface GatewayEvidenceBundleManifest {
  schema_version: typeof GATEWAY_BUNDLE_SCHEMA_VERSION;
  guard_version: string;
  session_id: string;
  created_at: string;
  finalized_at: string | null;
  status: "recording" | "finalized";
  capture_mode: "digest-only";
  coverage: CoverageAttestation;
  capture_boundary: "explicit_recorder";
  bypass_possible: true;
  bypass_declaration: "calls_outside_this_recorder_are_not_observed";
  frame_count: number;
  attempt_count: number;
  chain_head_sha256: string;
}

export type SdkOperationKind = "application_decision" | "registered_tool_call";

export interface SdkDecisionIdentity {
  schema_version: "gradia.guard.sdk-decision-identity.v1";
  decision_type: string;
  executor_kind: "model" | "component" | "human";
  executor_id: string;
  executor_version: string;
  contract_sha256: string;
}

export interface SdkToolIdentity {
  schema_version: "gradia.guard.sdk-tool-identity.v1";
  registry_id: string;
  tool_id: string;
  tool_version: string;
  interface_sha256: string;
}

export interface SdkStateRootIdentity {
  schema_version: "gradia.guard.sdk-state-root.v1";
  source: "application_declared";
  namespace_id: string;
  root_sha256: string;
}

export interface SdkPolicyReceipt {
  schema_version: "gradia.guard.sdk-policy-receipt.v1";
  operation_kind: SdkOperationKind;
  occurrence_sha256: string;
  actor_id: string;
  principal_id: string;
  authority_scope_ids: readonly string[];
  decision: "allowed" | "blocked";
  censor_kind: "policy" | "budget" | "authority" | null;
  reason_codes: readonly string[];
  policy_sha256: string;
  evaluated_at: string;
  receipt_sha256: string;
}

interface SdkFrameBase {
  schema_version: typeof SDK_FRAME_SCHEMA_VERSION;
  session_id: string;
  sequence: number;
  frame_kind: FrameKind;
  operation_kind: SdkOperationKind;
  observed_at: string;
  coverage: CoverageAttestation;
  actor_id: string;
  principal_id: string;
  authority_scope_ids: readonly string[];
  logical_operation_id: string;
  attempt_number: number;
  retry_of_occurrence_sha256: string | null;
  parent_occurrence_sha256: string | null;
  occurrence_sha256: string;
  state_root_before: SdkStateRootIdentity | null;
  previous_frame_sha256: string;
  frame_sha256: string;
}

interface SdkDecisionFrameBase extends SdkFrameBase {
  frame_kind: "decision";
  policy: SdkPolicyReceipt;
}

interface SdkActionFrameBase extends SdkFrameBase {
  frame_kind: "action";
  policy_receipt_sha256: string;
  outcome: SdkOutcome;
  dispatch_occurred: boolean;
  state_root_after: SdkStateRootIdentity | null;
  dispatch_started_at: string | null;
  terminal_observed_at: string | null;
  latency_ms: number | null;
  failure_code: string | null;
}

export interface SdkApplicationDecisionFrame extends SdkDecisionFrameBase {
  operation_kind: "application_decision";
  decision_identity: SdkDecisionIdentity;
  decision_input: ContentReference;
}

export interface SdkApplicationActionFrame extends SdkActionFrameBase {
  operation_kind: "application_decision";
  decision_identity: SdkDecisionIdentity;
  resolved_decision_identity: SdkDecisionIdentity | null;
  decision_input: ContentReference;
  decision_output: ContentReference | null;
}

export interface SdkToolDecisionFrame extends SdkDecisionFrameBase {
  operation_kind: "registered_tool_call";
  tool_identity: SdkToolIdentity;
  tool_request: ContentReference;
}

export interface SdkToolActionFrame extends SdkActionFrameBase {
  operation_kind: "registered_tool_call";
  tool_identity: SdkToolIdentity;
  resolved_tool_identity: SdkToolIdentity | null;
  tool_request: ContentReference;
  tool_result: ContentReference | null;
}

export type SdkDecisionFrame = SdkApplicationDecisionFrame | SdkToolDecisionFrame;
export type SdkActionFrame = SdkApplicationActionFrame | SdkToolActionFrame;
export type SdkEvidenceFrame = SdkDecisionFrame | SdkActionFrame;

export type SdkOutcome =
  | "success"
  | "decision_failure"
  | "tool_failure"
  | "protocol_failure"
  | "identity_mismatch"
  | "policy_censored"
  | "budget_censored"
  | "authority_censored";

export interface SdkEvidenceBundleManifest {
  schema_version: typeof SDK_BUNDLE_SCHEMA_VERSION;
  guard_version: string;
  session_id: string;
  created_at: string;
  finalized_at: string | null;
  status: "recording" | "finalized";
  capture_mode: "digest-only";
  coverage: CoverageAttestation;
  capture_boundary: "explicit_sdk";
  bypass_possible: true;
  bypass_declaration: "uninstrumented_or_direct_io_is_not_observed";
  frame_count: number;
  operation_count: number;
  chain_head_sha256: string;
}
