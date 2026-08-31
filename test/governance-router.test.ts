import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateGovernanceRoute,
  GOVERNANCE_ROUTING_CLAIM_BOUNDARY,
  GOVERNANCE_ROUTING_POLICY_SCHEMA_VERSION,
  GOVERNANCE_ROUTING_REQUEST_SCHEMA_VERSION,
  sealGovernanceRoutingPolicy,
  sealGovernanceRoutingRequest,
  verifyGovernanceRoutingRequest,
  type GovernanceRoutingPolicyBody,
  type GovernanceRoutingRequestBody,
} from "../src/governance-router.js";

function policy() {
  return sealGovernanceRoutingPolicy({
    schema_version: GOVERNANCE_ROUTING_POLICY_SCHEMA_VERSION,
    policy_id: "guard.default-routing",
    policy_version: "v1",
    min_task_value_bps: 4_000,
    min_evaluator_reliability_bps: 7_500,
    max_diagnostic_budget_microusd: 20_000_000,
    max_panel_budget_microusd: 500_000_000,
    max_cost_per_accepted_result_microusd: 30_000_000,
    min_diagnostic_attempts_for_panel: 2,
    min_accepted_results_for_panel: 1,
    require_independent_human_panel_approval: true,
    claim_boundary: GOVERNANCE_ROUTING_CLAIM_BOUNDARY,
  } satisfies GovernanceRoutingPolicyBody);
}

function request(
  changes: Partial<GovernanceRoutingRequestBody> = {},
) {
  return sealGovernanceRoutingRequest({
    schema_version: GOVERNANCE_ROUTING_REQUEST_SCHEMA_VERSION,
    request_id: "route.study-a.diagnostic.v1",
    study_key: "study-a",
    requested_stage: "diagnostic",
    task_value_bps: 8_500,
    evaluator_reliability_bps: 9_000,
    cumulative_spend_microusd: 0,
    requested_incremental_budget_microusd: 10_000_000,
    attempted_results: 0,
    accepted_results: 0,
    result_set_sha256: null,
    panel_definition_sha256: "a".repeat(64),
    independent_human_approval_sha256: null,
    ...changes,
  });
}

test("prospective diagnostic is eligible but never described as dispatch", () => {
  const decision = evaluateGovernanceRoute(policy(), request());
  assert.equal(decision.disposition, "diagnostic_eligible");
  assert.equal(decision.dispatch_eligible, true);
  assert.deepEqual(decision.blockers, []);
  assert.match(decision.claim_boundary, /Eligibility is not dispatch/);
});

test("panel eligibility requires a frozen denominator and independent approval", () => {
  const base: Partial<GovernanceRoutingRequestBody> = {
    request_id: "route.study-a.panel.v1",
    requested_stage: "panel",
    cumulative_spend_microusd: 40_000_000,
    requested_incremental_budget_microusd: 100_000_000,
    attempted_results: 2,
    accepted_results: 2,
    result_set_sha256: "b".repeat(64),
  };
  const waiting = evaluateGovernanceRoute(policy(), request(base));
  assert.equal(waiting.disposition, "human_review_required");
  assert.deepEqual(waiting.blockers, ["independent_human_approval_required"]);
  assert.equal(waiting.cost_per_accepted_result_microusd, 20_000_000);

  const eligible = evaluateGovernanceRoute(
    policy(),
    request({ ...base, independent_human_approval_sha256: "c".repeat(64) }),
  );
  assert.equal(eligible.disposition, "panel_eligible");
  assert.equal(eligible.dispatch_eligible, true);
  assert.equal(
    policy().policy_sha256,
    "ec97c2e49708ec9addaccee800aa79a9e6dae98a63cae0b3ae955b6b3ee92edb",
  );
  assert.equal(
    request({ ...base, independent_human_approval_sha256: "c".repeat(64) }).request_sha256,
    "cb1325f47d65be84226a49915670ae236f2e9351516b40f698c47cc4f6b2fbf1",
  );
  assert.equal(
    eligible.decision_sha256,
    "53b1f0ab323151fd1fe66f04662916cdea986bfed65aa34e5309406ba2c88365",
  );
});

test("value, reliability, budget, and zero acceptance remain distinct", () => {
  const refused = evaluateGovernanceRoute(
    policy(),
    request({
      task_value_bps: 1_000,
      evaluator_reliability_bps: 1_000,
      requested_incremental_budget_microusd: 20_000_001,
    }),
  );
  assert.equal(refused.disposition, "refused");
  assert.deepEqual(refused.blockers, [
    "evaluator_reliability_below_policy_minimum",
    "requested_budget_exceeds_stage_cap",
    "task_value_below_policy_minimum",
  ]);

  const zero = evaluateGovernanceRoute(
    policy(),
    request({
      request_id: "route.study-a.panel.v1",
      requested_stage: "panel",
      attempted_results: 3,
      accepted_results: 0,
      cumulative_spend_microusd: 25_000_000,
      requested_incremental_budget_microusd: 25_000_000,
      result_set_sha256: "d".repeat(64),
      independent_human_approval_sha256: "e".repeat(64),
    }),
  );
  assert.equal(zero.cost_per_accepted_result_microusd, null);
  assert.deepEqual(zero.blockers, [
    "accepted_result_floor_not_met",
    "cost_per_accepted_result_unavailable",
  ]);
});

test("mutated requests and non-prospective diagnostics fail closed", () => {
  assert.throws(
    () => request({ attempted_results: 1, result_set_sha256: "f".repeat(64) }),
    /diagnostic_must_be_prospective/,
  );
  const valid = request();
  assert.throws(
    () => verifyGovernanceRoutingRequest({ ...valid, task_value_bps: 0 }),
    /request_digest_mismatch/,
  );
});

test("cross-language money remains within exact integer semantics", () => {
  assert.throws(
    () =>
      request({
        cumulative_spend_microusd: Number.MAX_SAFE_INTEGER - 1,
        requested_incremental_budget_microusd: 2,
      }),
    /projected_spend_not_safe_integer/,
  );
});
