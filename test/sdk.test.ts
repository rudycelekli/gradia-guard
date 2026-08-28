import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  SdkIdentityMismatchError,
  SdkRecorder,
  canonicalJson,
  digestCanonical,
  sha256,
  verifyBundle,
  type SdkActionFrame,
  type SdkApplicationActionFrame,
  type SdkDecisionFrame,
  type SdkDecisionIdentity,
  type SdkEvidenceBundleManifest,
  type SdkEvidenceFrame,
  type SdkStateRootIdentity,
  type SdkToolActionFrame,
  type SdkToolIdentity,
} from "../src/index.js";

const POLICY_SHA = "a".repeat(64);
const DECISION_IDENTITY: SdkDecisionIdentity = {
  schema_version: "gradia.guard.sdk-decision-identity.v1",
  decision_type: "underwriting.disposition",
  executor_kind: "model",
  executor_id: "custom:underwriting-agent",
  executor_version: "2026.08.24",
  contract_sha256: "b".repeat(64),
};
const TOOL_IDENTITY: SdkToolIdentity = {
  schema_version: "gradia.guard.sdk-tool-identity.v1",
  registry_id: "mortgage-tools-v1",
  tool_id: "document.read",
  tool_version: "3.1.0",
  interface_sha256: "c".repeat(64),
};
const ROOT_BEFORE: SdkStateRootIdentity = {
  schema_version: "gradia.guard.sdk-state-root.v1",
  source: "application_declared",
  namespace_id: "loan-case",
  root_sha256: "d".repeat(64),
};
const ROOT_AFTER: SdkStateRootIdentity = {
  schema_version: "gradia.guard.sdk-state-root.v1",
  source: "application_declared",
  namespace_id: "loan-case",
  root_sha256: "e".repeat(64),
};

function directory(): string {
  return join(mkdtempSync(join(tmpdir(), "gradia-sdk-test-")), "bundle");
}

function recorder(): SdkRecorder {
  return new SdkRecorder({ directory: directory() });
}

function beginDecision(instance: SdkRecorder, overrides: Record<string, unknown> = {}) {
  return instance.beginApplicationDecision({
    actorId: "agent-underwriter-01",
    principalId: "tenant-premier-demo",
    authorityScopeIds: ["loan.read", "recommendation.write"],
    logicalOperationId: "decision-1",
    attemptNumber: 1,
    retryOfOccurrenceSha256: null,
    parentOccurrenceSha256: null,
    stateRootBefore: ROOT_BEFORE,
    decisionIdentity: DECISION_IDENTITY,
    decisionInputBody: Buffer.from(
      '{"application":"private-input","api_key":"fake-never-persist"}',
    ),
    decisionInputMediaType: "application/json",
    policy: {
      decision: "allowed",
      censorKind: null,
      reasonCodes: ["authority_confirmed", "policy_allowed"],
      policySha256: POLICY_SHA,
    },
    ...overrides,
  } as Parameters<SdkRecorder["beginApplicationDecision"]>[0]);
}

function completeDecision(operation: ReturnType<typeof beginDecision>) {
  operation.markDispatched();
  return operation.succeed({
    resolvedDecisionIdentity: DECISION_IDENTITY,
    decisionOutputBody: Buffer.from(
      '{"decision":"refer","chain_of_thought":"fake-never-persist"}',
    ),
    decisionOutputMediaType: "application/json",
    stateRootAfter: ROOT_AFTER,
  });
}

function beginTool(instance: SdkRecorder, overrides: Record<string, unknown> = {}) {
  return instance.beginRegisteredToolCall({
    actorId: "agent-underwriter-01",
    principalId: "tenant-premier-demo",
    authorityScopeIds: ["document.read"],
    logicalOperationId: "tool-call-1",
    attemptNumber: 1,
    retryOfOccurrenceSha256: null,
    parentOccurrenceSha256: null,
    stateRootBefore: ROOT_BEFORE,
    toolIdentity: TOOL_IDENTITY,
    toolRequestBody: Buffer.from('{"document_id":"private-document"}'),
    toolRequestMediaType: "application/json",
    policy: {
      decision: "allowed",
      censorKind: null,
      reasonCodes: ["authority_confirmed", "policy_allowed"],
      policySha256: POLICY_SHA,
    },
    ...overrides,
  } as Parameters<SdkRecorder["beginRegisteredToolCall"]>[0]);
}

function completeTool(operation: ReturnType<typeof beginTool>) {
  operation.markDispatched();
  return operation.succeed({
    resolvedToolIdentity: TOOL_IDENTITY,
    toolResultBody: Buffer.from('{"status":"read","private":"fake-never-persist"}'),
    toolResultMediaType: "application/json",
    stateRootAfter: ROOT_AFTER,
  });
}

function frames(bundle: string): SdkEvidenceFrame[] {
  const raw = readFileSync(join(bundle, "frames.ndjson"), "utf8").trim();
  return raw ? raw.split("\n").map((line) => JSON.parse(line) as SdkEvidenceFrame) : [];
}

test("explicit SDK records decision and parented tool evidence without raw payloads", () => {
  const instance = recorder();
  const decision = beginDecision(instance);
  const decisionAction = completeDecision(decision);
  const tool = beginTool(instance, {
    parentOccurrenceSha256: decision.occurrenceSha256,
    stateRootBefore: decisionAction.state_root_after,
  });
  completeTool(tool);
  instance.finalize();

  const verification = verifyBundle(instance.directory);
  assert.equal(verification.ok, true, verification.blockers.join(","));
  assert.equal(verification.frame_count, 4);
  const stored = readFileSync(join(instance.directory, "frames.ndjson"), "utf8");
  assert.equal(stored.includes("private-input"), false);
  assert.equal(stored.includes("fake-never-persist"), false);
  assert.equal(stored.includes("chain_of_thought"), false);
  const rows = frames(instance.directory);
  assert.equal(
    (rows[0] as SdkDecisionFrame).operation_kind === "application_decision"
      ? (rows[0] as Extract<SdkDecisionFrame, { operation_kind: "application_decision" }>).decision_input
          .plaintext_sha256
      : null,
    sha256(Buffer.from('{"application":"private-input","api_key":"fake-never-persist"}')),
  );
  assert.equal(rows[2]?.parent_occurrence_sha256, decision.occurrenceSha256);
});

test("SDK refuses unpinned identities, noncanonical authority, and header-shaped API extensions", () => {
  const first = recorder();
  assert.throws(
    () =>
      beginDecision(first, {
        decisionIdentity: { ...DECISION_IDENTITY, executor_version: "latest" },
      }),
    /not_exact_pin/,
  );
  assert.equal(frames(first.directory).length, 0);

  const second = recorder();
  assert.throws(
    () => beginTool(second, { authorityScopeIds: ["z.scope", "a.scope"] }),
    /not_canonical/,
  );
  assert.equal(frames(second.directory).length, 0);

  const third = recorder();
  assert.throws(
    () => beginTool(third, { headers: { authorization: "Bearer fake-never-persist" } }),
    /sdk_begin_tool_input_fields_invalid/,
  );
  assert.equal(frames(third.directory).length, 0);

  const fourth = recorder();
  assert.throws(
    () =>
      beginDecision(fourth, {
        decisionIdentity: {
          ...DECISION_IDENTITY,
          chain_of_thought: "fake-never-persist",
        },
      }),
    /sdk_decision_identity_fields_invalid/,
  );
  assert.equal(frames(fourth.directory).length, 0);
});

test("requested and resolved model identity mismatch is recorded and fails verification", () => {
  const instance = recorder();
  const operation = beginDecision(instance);
  operation.markDispatched();
  assert.throws(
    () =>
      operation.succeed({
        resolvedDecisionIdentity: { ...DECISION_IDENTITY, executor_version: "2026.09.01" },
        decisionOutputBody: Buffer.from('{"decision":"approve"}'),
        decisionOutputMediaType: "application/json",
        stateRootAfter: ROOT_AFTER,
      }),
    (error: unknown) => error instanceof SdkIdentityMismatchError,
  );
  instance.finalize();
  const result = verifyBundle(instance.directory);
  assert.equal(result.ok, false);
  assert.ok(result.blockers.some((item) => item.startsWith("sdk_identity_mismatch_recorded")));
});

test("registered tool identity mismatch is recorded and fails verification", () => {
  const instance = recorder();
  const operation = beginTool(instance);
  operation.markDispatched();
  assert.throws(
    () =>
      operation.succeed({
        resolvedToolIdentity: { ...TOOL_IDENTITY, tool_version: "3.2.0" },
        toolResultBody: Buffer.from('{"status":"read"}'),
        toolResultMediaType: "application/json",
        stateRootAfter: ROOT_AFTER,
      }),
    (error: unknown) => error instanceof SdkIdentityMismatchError,
  );
  instance.finalize();
  const result = verifyBundle(instance.directory);
  assert.equal(result.ok, false);
  assert.ok(result.blockers.some((item) => item.startsWith("sdk_identity_mismatch_recorded")));
});

test("policy, budget, and authority censors remain distinct pre-dispatch outcomes", () => {
  const cases = [
    ["policy", "policy_censored", "policy_denied"],
    ["budget", "budget_censored", "budget_refused"],
    ["authority", "authority_censored", "authority_denied"],
  ] as const;
  for (const [censorKind, expectedOutcome, reason] of cases) {
    const instance = recorder();
    const operation = beginTool(instance, {
      policy: {
        decision: "blocked",
        censorKind,
        reasonCodes: [reason],
        policySha256: POLICY_SHA,
      },
    });
    assert.equal(operation.censored, true);
    assert.throws(() => operation.markDispatched(), /cannot_dispatch/);
    instance.finalize();
    const action = frames(instance.directory).at(-1) as SdkToolActionFrame;
    assert.equal(action.outcome, expectedOutcome);
    assert.equal(action.dispatch_occurred, false);
    assert.equal(verifyBundle(instance.directory).ok, true);
  }
});

test("decision and tool failures preserve typed failure distinctions", () => {
  const instance = recorder();
  const decision = beginDecision(instance);
  decision.markDispatched();
  const decisionFrame = decision.fail({
    outcome: "decision_failure",
    resolvedDecisionIdentity: DECISION_IDENTITY,
    decisionOutputBody: null,
    decisionOutputMediaType: null,
    stateRootAfter: ROOT_BEFORE,
    failureCode: "insufficient_evidence",
  });
  const tool = beginTool(instance);
  tool.markDispatched();
  const toolFrame = tool.fail({
    outcome: "tool_failure",
    resolvedToolIdentity: TOOL_IDENTITY,
    toolResultBody: Buffer.from('{"error":"not_found"}'),
    toolResultMediaType: "application/json",
    stateRootAfter: ROOT_BEFORE,
    failureCode: "record_not_found",
  });
  instance.finalize();
  assert.equal(decisionFrame.outcome, "decision_failure");
  assert.equal(toolFrame.outcome, "tool_failure");
  assert.equal(verifyBundle(instance.directory).ok, true);
});

test("retry and parent lineage require previously recorded exact identities", () => {
  const instance = recorder();
  const parent = beginDecision(instance);
  completeDecision(parent);
  const first = beginTool(instance, { parentOccurrenceSha256: parent.occurrenceSha256 });
  first.markDispatched();
  first.fail({
    outcome: "tool_failure",
    resolvedToolIdentity: TOOL_IDENTITY,
    toolResultBody: null,
    toolResultMediaType: null,
    stateRootAfter: ROOT_BEFORE,
    failureCode: "temporary_unavailable",
  });
  assert.throws(
    () =>
      beginTool(instance, {
        logicalOperationId: "unrelated-child",
        parentOccurrenceSha256: "f".repeat(64),
      }),
    /parent_occurrence_not_recorded/,
  );
  assert.throws(
    () =>
      beginTool(instance, {
        attemptNumber: 2,
        retryOfOccurrenceSha256: first.occurrenceSha256,
        parentOccurrenceSha256: parent.occurrenceSha256,
        toolIdentity: { ...TOOL_IDENTITY, tool_version: "4.0.0" },
      }),
    /retry_identity_context_mismatch/,
  );
  const retry = beginTool(instance, {
    attemptNumber: 2,
    retryOfOccurrenceSha256: first.occurrenceSha256,
    parentOccurrenceSha256: parent.occurrenceSha256,
  });
  completeTool(retry);
  instance.finalize();
  assert.equal(verifyBundle(instance.directory).ok, true);
});

test("open operations cannot finalize and remain explicitly unverifiable after an app crash", () => {
  const instance = recorder();
  const operation = beginDecision(instance);
  operation.markDispatched();
  assert.throws(() => instance.finalize(), /open_operations/);
  const result = verifyBundle(instance.directory);
  assert.equal(result.ok, false);
  assert.ok(result.blockers.includes("sdk_bundle_not_finalized"));
  assert.ok(result.blockers.some((item) => item.startsWith("sdk_action_missing")));
});

test("rehashed authority, pair, and policy timing mutations fail closed", () => {
  const instance = recorder();
  completeDecision(beginDecision(instance));
  instance.finalize();
  const rows = frames(instance.directory);
  const decision = rows[0] as Extract<SdkDecisionFrame, { operation_kind: "application_decision" }>;
  const action = rows[1] as SdkApplicationActionFrame;
  action.authority_scope_ids = ["loan.read", "recommendation.admin"];
  decision.policy.evaluated_at = "2099-01-01T00:00:00.000Z";
  const { receipt_sha256: _receipt, ...policyBody } = decision.policy;
  decision.policy.receipt_sha256 = digestCanonical(policyBody);
  action.policy_receipt_sha256 = decision.policy.receipt_sha256;
  rewriteChain(instance.directory, rows);
  const result = verifyBundle(instance.directory);
  assert.equal(result.ok, false);
  assert.ok(result.blockers.some((item) => item.startsWith("sdk_operation_pair_binding_mismatch")));
  assert.ok(
    result.blockers.some(
      (item) => item.startsWith("sdk_policy_timing_invalid") || item.startsWith("sdk_policy_not_pre_dispatch"),
    ),
  );
});

test("coverage and bypass declarations cannot be edited into completeness claims", () => {
  const instance = recorder();
  completeDecision(beginDecision(instance));
  instance.finalize();
  const manifestPath = join(instance.directory, "bundle.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as SdkEvidenceBundleManifest;
  (manifest as unknown as { bypass_possible: boolean }).bypass_possible = false;
  manifest.coverage.full_world_capture = true;
  writeFileSync(manifestPath, `${canonicalJson(manifest)}\n`);
  const result = verifyBundle(instance.directory);
  assert.equal(result.ok, false);
  assert.ok(result.blockers.includes("sdk_bundle_bypass_declaration_invalid"));
  assert.ok(result.blockers.includes("coverage_full_world_overclaim"));
});

test("missing pair member and reordered frames fail even after chain rebuilding", () => {
  const first = recorder();
  completeDecision(beginDecision(first));
  first.finalize();
  const missing = frames(first.directory);
  missing.splice(0, 1);
  rewriteChain(first.directory, missing);
  const missingResult = verifyBundle(first.directory);
  assert.equal(missingResult.ok, false);
  assert.ok(missingResult.blockers.some((item) => item.startsWith("sdk_decision_missing")));

  const second = recorder();
  completeDecision(beginDecision(second));
  second.finalize();
  const reordered = frames(second.directory).reverse();
  rewriteChain(second.directory, reordered);
  const reorderedResult = verifyBundle(second.directory);
  assert.equal(reorderedResult.ok, false);
  assert.ok(reorderedResult.blockers.some((item) => item.startsWith("sdk_action_precedes_decision")));
});

function rewriteChain(bundle: string, rows: SdkEvidenceFrame[]): void {
  let head = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  rows.forEach((row, index) => {
    row.sequence = index;
    row.previous_frame_sha256 = head;
    const { frame_sha256: _old, ...body } = row;
    row.frame_sha256 = digestCanonical(body);
    head = row.frame_sha256;
  });
  writeFileSync(join(bundle, "frames.ndjson"), `${rows.map((row) => canonicalJson(row)).join("\n")}\n`);
  const manifestPath = join(bundle, "bundle.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as SdkEvidenceBundleManifest;
  manifest.chain_head_sha256 = head;
  manifest.frame_count = rows.length;
  writeFileSync(manifestPath, `${canonicalJson(manifest)}\n`);
}
