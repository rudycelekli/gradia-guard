import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { digestCanonical } from "../src/canonical.js";
import {
  evaluateModelPolicy,
  evaluateToolPolicy,
  loadPolicy,
  sealPolicy,
  starterPolicyBody,
  verifyPolicy,
  type GuardPolicyBody,
} from "../src/policy.js";

const interfaceSha256 = digestCanonical({ tool: "case.read", version: "2026-08-24" });

function policyBody(): GuardPolicyBody {
  return {
    schema_version: "gradia.guard.policy.v1",
    policy_id: "fixture-policy",
    policy_version: "v1",
    default_decision: "blocked",
    model_routes: [
      {
        provider: "openai",
        requested_model: "gpt-5.6-2026-08-01",
        authority_scope_ids: ["case.read", "decision.write"],
        max_request_bytes: 1000,
        max_attempt_number: 2,
      },
    ],
    tool_routes: [
      {
        registry_id: "case-tools",
        tool_id: "case.read",
        tool_version: "v1",
        interface_sha256: interfaceSha256,
        authority_scope_ids: ["case.read"],
        max_request_bytes: 500,
        max_attempt_number: 1,
      },
    ],
  };
}

test("starter policy is deny-by-default, canonical, and self-digested", () => {
  const policy = sealPolicy(starterPolicyBody());
  assert.equal(policy.default_decision, "blocked");
  assert.deepEqual(policy.model_routes, []);
  assert.deepEqual(policy.tool_routes, []);
  assert.doesNotThrow(() => verifyPolicy(policy));
});

test("model policy permits only exact route, scope, bytes, and attempt", () => {
  const policy = sealPolicy(policyBody());
  const allowed = evaluateModelPolicy(policy, {
    provider: "openai",
    requestedModel: "gpt-5.6-2026-08-01",
    requestByteLength: 999,
    attemptNumber: 2,
    authorityScopeIds: ["case.read"],
  });
  assert.equal(allowed.decision, "allowed");
  assert.equal(allowed.policySha256, policy.policy_sha256);

  const blocked = evaluateModelPolicy(policy, {
    provider: "openai",
    requestedModel: "gpt-5.6-2026-08-01",
    requestByteLength: 1001,
    attemptNumber: 3,
    authorityScopeIds: ["admin.write"],
  });
  assert.deepEqual(blocked, {
    decision: "blocked",
    censorKind: "policy",
    reasonCodes: [
      "attempt_limit_exceeded",
      "authority_scope_not_allowed",
      "request_bytes_exceeded",
    ],
    policySha256: policy.policy_sha256,
  });
});

test("tool policy preserves authority censorship separately", () => {
  const policy = sealPolicy(policyBody());
  const toolIdentity = {
    schema_version: "gradia.guard.sdk-tool-identity.v1" as const,
    registry_id: "case-tools",
    tool_id: "case.read",
    tool_version: "v1",
    interface_sha256: interfaceSha256,
  };
  assert.equal(
    evaluateToolPolicy(policy, {
      toolIdentity,
      requestByteLength: 100,
      attemptNumber: 1,
      authorityScopeIds: ["case.read"],
    }).decision,
    "allowed",
  );
  const blocked = evaluateToolPolicy(policy, {
    toolIdentity,
    requestByteLength: 100,
    attemptNumber: 1,
    authorityScopeIds: ["case.write"],
  });
  assert.equal(blocked.decision, "blocked");
  assert.equal(blocked.censorKind, "authority");
  assert.deepEqual(blocked.reasonCodes, ["authority_scope_not_allowed"]);
});

test("policy loading refuses edits, unknown fields, and noncanonical scopes", () => {
  const directory = mkdtempSync(join(tmpdir(), "gradia-policy-"));
  const path = join(directory, "policy.json");
  const policy = sealPolicy(policyBody());
  writeFileSync(path, JSON.stringify(policy));
  assert.deepEqual(loadPolicy(path), policy);

  writeFileSync(path, JSON.stringify({ ...policy, policy_id: "rewritten" }));
  assert.throws(() => loadPolicy(path), /guard_policy_digest_mismatch/);

  writeFileSync(path, JSON.stringify({ ...policy, unexpected: true }));
  assert.throws(() => loadPolicy(path), /guard_policy_keys_invalid/);

  const badScopes = policyBody();
  badScopes.model_routes[0]!.authority_scope_ids = ["decision.write", "case.read"];
  assert.throws(() => sealPolicy(badScopes), /guard_policy_scopes_not_canonical/);
});

test("policy routes refuse duplicates and wildcard-shaped ambiguity", () => {
  const duplicate = policyBody();
  duplicate.model_routes = [...duplicate.model_routes, duplicate.model_routes[0]!];
  assert.throws(() => sealPolicy(duplicate), /guard_policy_model_route_duplicate/);

  const wildcard = policyBody();
  wildcard.model_routes[0]!.requested_model = "*";
  assert.throws(() => sealPolicy(wildcard), /guard_policy_requested_model_invalid/);
});
