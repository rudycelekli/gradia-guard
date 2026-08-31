import { digestCanonical, isSha256 } from "./canonical.js";
import { assertStableId } from "./security.js";

export const GOVERNANCE_ROUTING_POLICY_SCHEMA_VERSION =
  "gradia.guard.governance-routing-policy.v1" as const;
export const GOVERNANCE_ROUTING_REQUEST_SCHEMA_VERSION =
  "gradia.guard.governance-routing-request.v1" as const;
export const GOVERNANCE_ROUTING_DECISION_SCHEMA_VERSION =
  "gradia.guard.governance-routing-decision.v1" as const;
export const GOVERNANCE_ROUTING_CLAIM_BOUNDARY =
  "This decision applies one approved cost and evidence policy to one frozen request. Eligibility is not dispatch, model quality, evaluator truth, control effectiveness, certification, or release authorization." as const;

export type GovernanceRoutingStage = "diagnostic" | "panel";
export type GovernanceRoutingDisposition =
  | "refused"
  | "human_review_required"
  | "diagnostic_eligible"
  | "panel_eligible";

export interface GovernanceRoutingPolicyBody {
  schema_version: typeof GOVERNANCE_ROUTING_POLICY_SCHEMA_VERSION;
  policy_id: string;
  policy_version: string;
  min_task_value_bps: number;
  min_evaluator_reliability_bps: number;
  max_diagnostic_budget_microusd: number;
  max_panel_budget_microusd: number;
  max_cost_per_accepted_result_microusd: number;
  min_diagnostic_attempts_for_panel: number;
  min_accepted_results_for_panel: number;
  require_independent_human_panel_approval: true;
  claim_boundary: typeof GOVERNANCE_ROUTING_CLAIM_BOUNDARY;
}

export interface GovernanceRoutingPolicy extends GovernanceRoutingPolicyBody {
  policy_sha256: string;
}

export interface GovernanceRoutingRequestBody {
  schema_version: typeof GOVERNANCE_ROUTING_REQUEST_SCHEMA_VERSION;
  request_id: string;
  study_key: string;
  requested_stage: GovernanceRoutingStage;
  task_value_bps: number;
  evaluator_reliability_bps: number;
  cumulative_spend_microusd: number;
  requested_incremental_budget_microusd: number;
  attempted_results: number;
  accepted_results: number;
  result_set_sha256: string | null;
  panel_definition_sha256: string;
  independent_human_approval_sha256: string | null;
}

export interface GovernanceRoutingRequest extends GovernanceRoutingRequestBody {
  request_sha256: string;
}

export interface GovernanceRoutingDecisionBody {
  schema_version: typeof GOVERNANCE_ROUTING_DECISION_SCHEMA_VERSION;
  policy_sha256: string;
  request_sha256: string;
  requested_stage: GovernanceRoutingStage;
  disposition: GovernanceRoutingDisposition;
  dispatch_eligible: boolean;
  human_review_required: boolean;
  cost_per_accepted_result_microusd: number | null;
  remaining_stage_budget_microusd: number;
  blockers: readonly string[];
  claim_boundary: typeof GOVERNANCE_ROUTING_CLAIM_BOUNDARY;
}

export interface GovernanceRoutingDecision extends GovernanceRoutingDecisionBody {
  decision_sha256: string;
}

export function sealGovernanceRoutingPolicy(
  body: GovernanceRoutingPolicyBody,
): GovernanceRoutingPolicy {
  validatePolicyBody(body);
  return { ...body, policy_sha256: digestCanonical(body) };
}

export function verifyGovernanceRoutingPolicy(policy: GovernanceRoutingPolicy): void {
  const { policy_sha256, ...body } = policy;
  validatePolicyBody(body);
  if (!isSha256(policy_sha256) || policy_sha256 !== digestCanonical(body)) {
    throw new Error("governance_routing_policy_digest_mismatch");
  }
}

export function sealGovernanceRoutingRequest(
  body: GovernanceRoutingRequestBody,
): GovernanceRoutingRequest {
  validateRequestBody(body);
  return { ...body, request_sha256: digestCanonical(body) };
}

export function verifyGovernanceRoutingRequest(request: GovernanceRoutingRequest): void {
  const { request_sha256, ...body } = request;
  validateRequestBody(body);
  if (!isSha256(request_sha256) || request_sha256 !== digestCanonical(body)) {
    throw new Error("governance_routing_request_digest_mismatch");
  }
}

export function evaluateGovernanceRoute(
  policy: GovernanceRoutingPolicy,
  request: GovernanceRoutingRequest,
): GovernanceRoutingDecision {
  verifyGovernanceRoutingPolicy(policy);
  verifyGovernanceRoutingRequest(request);
  const hardBlockers = new Set<string>();
  const reviewBlockers = new Set<string>();
  const stageCap =
    request.requested_stage === "diagnostic"
      ? policy.max_diagnostic_budget_microusd
      : policy.max_panel_budget_microusd;
  const remainingBudget = Math.max(stageCap - request.cumulative_spend_microusd, 0);
  const projectedSpend =
    request.cumulative_spend_microusd + request.requested_incremental_budget_microusd;

  if (request.task_value_bps < policy.min_task_value_bps) {
    hardBlockers.add("task_value_below_policy_minimum");
  }
  if (request.requested_incremental_budget_microusd > remainingBudget) {
    hardBlockers.add("requested_budget_exceeds_stage_cap");
  }
  if (request.evaluator_reliability_bps < policy.min_evaluator_reliability_bps) {
    reviewBlockers.add("evaluator_reliability_below_policy_minimum");
  }

  let costPerAccepted: number | null = null;
  if (request.requested_stage === "panel") {
    if (request.attempted_results < policy.min_diagnostic_attempts_for_panel) {
      reviewBlockers.add("diagnostic_attempt_floor_not_met");
    }
    if (request.accepted_results < policy.min_accepted_results_for_panel) {
      reviewBlockers.add("accepted_result_floor_not_met");
    }
    if (request.accepted_results === 0) {
      reviewBlockers.add("cost_per_accepted_result_unavailable");
    } else {
      costPerAccepted = ceilDivide(
        request.cumulative_spend_microusd,
        request.accepted_results,
      );
      if (costPerAccepted > policy.max_cost_per_accepted_result_microusd) {
        reviewBlockers.add("cost_per_accepted_result_above_policy_maximum");
      }
    }
    if (
      policy.require_independent_human_panel_approval &&
      request.independent_human_approval_sha256 === null
    ) {
      reviewBlockers.add("independent_human_approval_required");
    }
  }

  let disposition: GovernanceRoutingDisposition;
  let blockers: string[];
  if (hardBlockers.size > 0) {
    disposition = "refused";
    blockers = [...hardBlockers, ...reviewBlockers].sort();
  } else if (reviewBlockers.size > 0) {
    disposition = "human_review_required";
    blockers = [...reviewBlockers].sort();
  } else {
    disposition = request.requested_stage === "diagnostic" ? "diagnostic_eligible" : "panel_eligible";
    blockers = [];
  }

  const body: GovernanceRoutingDecisionBody = {
    schema_version: GOVERNANCE_ROUTING_DECISION_SCHEMA_VERSION,
    policy_sha256: policy.policy_sha256,
    request_sha256: request.request_sha256,
    requested_stage: request.requested_stage,
    disposition,
    dispatch_eligible: disposition === "diagnostic_eligible" || disposition === "panel_eligible",
    human_review_required: disposition === "human_review_required",
    cost_per_accepted_result_microusd: costPerAccepted,
    remaining_stage_budget_microusd: Math.max(stageCap - projectedSpend, 0),
    blockers,
    claim_boundary: GOVERNANCE_ROUTING_CLAIM_BOUNDARY,
  };
  return { ...body, decision_sha256: digestCanonical(body) };
}

function validatePolicyBody(body: GovernanceRoutingPolicyBody): void {
  if (body.schema_version !== GOVERNANCE_ROUTING_POLICY_SCHEMA_VERSION) {
    throw new Error("governance_routing_policy_schema_invalid");
  }
  assertStableId(body.policy_id, "policy_id");
  assertStableId(body.policy_version, "policy_version");
  boundedInteger(body.min_task_value_bps, 0, 10_000, "min_task_value_bps");
  boundedInteger(
    body.min_evaluator_reliability_bps,
    0,
    10_000,
    "min_evaluator_reliability_bps",
  );
  positiveInteger(body.max_diagnostic_budget_microusd, "max_diagnostic_budget_microusd");
  positiveInteger(body.max_panel_budget_microusd, "max_panel_budget_microusd");
  positiveInteger(
    body.max_cost_per_accepted_result_microusd,
    "max_cost_per_accepted_result_microusd",
  );
  boundedInteger(
    body.min_diagnostic_attempts_for_panel,
    1,
    1_000_000,
    "min_diagnostic_attempts_for_panel",
  );
  boundedInteger(
    body.min_accepted_results_for_panel,
    1,
    1_000_000,
    "min_accepted_results_for_panel",
  );
  if (body.max_panel_budget_microusd < body.max_diagnostic_budget_microusd) {
    throw new Error("governance_routing_panel_budget_below_diagnostic");
  }
  if (body.require_independent_human_panel_approval !== true) {
    throw new Error("governance_routing_human_approval_must_be_required");
  }
  if (body.claim_boundary !== GOVERNANCE_ROUTING_CLAIM_BOUNDARY) {
    throw new Error("governance_routing_claim_boundary_invalid");
  }
}

function validateRequestBody(body: GovernanceRoutingRequestBody): void {
  if (body.schema_version !== GOVERNANCE_ROUTING_REQUEST_SCHEMA_VERSION) {
    throw new Error("governance_routing_request_schema_invalid");
  }
  assertStableId(body.request_id, "request_id");
  assertStableId(body.study_key, "study_key");
  if (body.requested_stage !== "diagnostic" && body.requested_stage !== "panel") {
    throw new Error("governance_routing_stage_invalid");
  }
  boundedInteger(body.task_value_bps, 0, 10_000, "task_value_bps");
  boundedInteger(body.evaluator_reliability_bps, 0, 10_000, "evaluator_reliability_bps");
  boundedInteger(body.cumulative_spend_microusd, 0, Number.MAX_SAFE_INTEGER, "cumulative_spend_microusd");
  positiveInteger(body.requested_incremental_budget_microusd, "requested_incremental_budget_microusd");
  boundedInteger(body.attempted_results, 0, 1_000_000, "attempted_results");
  boundedInteger(body.accepted_results, 0, 1_000_000, "accepted_results");
  if (
    !Number.isSafeInteger(
      body.cumulative_spend_microusd + body.requested_incremental_budget_microusd,
    )
  ) {
    throw new Error("governance_routing_projected_spend_not_safe_integer");
  }
  if (!isSha256(body.panel_definition_sha256)) {
    throw new Error("governance_routing_panel_definition_digest_invalid");
  }
  if (body.result_set_sha256 !== null && !isSha256(body.result_set_sha256)) {
    throw new Error("governance_routing_result_set_digest_invalid");
  }
  if (
    body.independent_human_approval_sha256 !== null &&
    !isSha256(body.independent_human_approval_sha256)
  ) {
    throw new Error("governance_routing_approval_digest_invalid");
  }
  if (body.accepted_results > body.attempted_results) {
    throw new Error("governance_routing_accepted_exceeds_attempted");
  }
  if (body.requested_stage === "diagnostic") {
    if (
      body.attempted_results !== 0 ||
      body.accepted_results !== 0 ||
      body.result_set_sha256 !== null ||
      body.independent_human_approval_sha256 !== null
    ) {
      throw new Error("governance_routing_diagnostic_must_be_prospective");
    }
  } else if (body.attempted_results === 0 || body.result_set_sha256 === null) {
    throw new Error("governance_routing_panel_requires_frozen_results");
  }
}

function positiveInteger(value: number, field: string): void {
  boundedInteger(value, 1, Number.MAX_SAFE_INTEGER, field);
}

function ceilDivide(dividend: number, divisor: number): number {
  return Number((BigInt(dividend) + BigInt(divisor) - 1n) / BigInt(divisor));
}

function boundedInteger(value: number, minimum: number, maximum: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`governance_routing_${field}_invalid`);
  }
}
