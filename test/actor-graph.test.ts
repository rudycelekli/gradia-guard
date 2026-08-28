import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  SdkRecorder,
  analyzeSdkActorGraph,
  canonicalJson,
  canonicalSdkActorGraph,
  digestCanonical,
  formatSdkActorGraph,
  type SdkDecisionIdentity,
  type SdkEvidenceBundleManifest,
  type SdkEvidenceFrame,
  type SdkStateRootIdentity,
  verifySdkBundle,
} from "../src/index.js";

const POLICY_SHA = "a".repeat(64);
const IDENTITY: SdkDecisionIdentity = {
  schema_version: "gradia.guard.sdk-decision-identity.v1",
  decision_type: "research.subproblem",
  executor_kind: "model",
  executor_id: "custom:research-agent",
  executor_version: "2026.08.26",
  contract_sha256: "b".repeat(64),
};
const ROOT: SdkStateRootIdentity = {
  schema_version: "gradia.guard.sdk-state-root.v1",
  source: "application_declared",
  namespace_id: "research-world",
  root_sha256: "c".repeat(64),
};

function begin(
  instance: SdkRecorder,
  actorId: string,
  logicalId: string,
  parent: string | null,
  policyDecision: "allowed" | "blocked" = "allowed",
) {
  return instance.beginApplicationDecision({
    actorId,
    principalId: `principal-${actorId}`,
    authorityScopeIds: ["research.read", "research.write"],
    logicalOperationId: logicalId,
    attemptNumber: 1,
    retryOfOccurrenceSha256: null,
    parentOccurrenceSha256: parent,
    stateRootBefore: ROOT,
    decisionIdentity: IDENTITY,
    decisionInputBody: Buffer.from(
      `{"task":"${logicalId}","private_payload":"fixture-private-input-do-not-project"}`,
    ),
    decisionInputMediaType: "application/json",
    policy:
      policyDecision === "allowed"
        ? {
            decision: "allowed",
            censorKind: null,
            reasonCodes: ["policy_allowed"],
            policySha256: POLICY_SHA,
          }
        : {
            decision: "blocked",
            censorKind: "authority",
            reasonCodes: ["authority_denied"],
            policySha256: POLICY_SHA,
          },
  });
}

function complete(operation: ReturnType<typeof begin>) {
  operation.markDispatched();
  operation.succeed({
    resolvedDecisionIdentity: IDENTITY,
    decisionOutputBody: Buffer.from(
      '{"status":"complete","private_output":"fixture-private-output-do-not-project"}',
    ),
    decisionOutputMediaType: "application/json",
    stateRootAfter: ROOT,
  });
}

test("free actor graph exposes cross-actor parentage without inventing contribution", () => {
  const directory = join(mkdtempSync(join(tmpdir(), "gradia-actor-graph-")), "bundle");
  const recorder = new SdkRecorder({ directory });
  const orchestrator = begin(recorder, "actor-orchestrator", "plan", null);
  complete(orchestrator);
  const worker = begin(recorder, "actor-worker-01", "solve-subproblem", orchestrator.occurrenceSha256);
  complete(worker);
  const synthesis = begin(recorder, "actor-orchestrator", "synthesize", worker.occurrenceSha256);
  complete(synthesis);
  recorder.finalize();

  const report = analyzeSdkActorGraph(directory);
  assert.equal(report.actor_count, 2);
  assert.equal(report.operation_count, 3);
  assert.equal(report.parent_edge_count, 2);
  assert.equal(report.cross_actor_edge_count, 2);
  assert.equal(report.maximum_declared_parent_depth, 2);
  assert.equal(
    report.claim_boundary,
    "application_declared_parentage_only_no_delegation_causal_contribution_or_quality_claim",
  );
  assert.equal(
    report.identity_boundary,
    "actor_and_principal_ids_are_application_declared_not_authenticated",
  );
  assert.equal(
    report.metadata_boundary,
    "payload_bytes_absent_actor_and_principal_ids_emitted_as_plaintext_metadata",
  );
  assert.equal(report.actors[0]?.dispatched_operation_count, 2);
  assert.equal(report.edges.every((edge) => edge.parent_dispatch_occurred), true);
  assert.equal(report.edges.every((edge) => edge.parent_outcome === "success"), true);
  assert.doesNotMatch(canonicalSdkActorGraph(report), /fixture-private-input-do-not-project/);
  assert.doesNotMatch(canonicalSdkActorGraph(report), /fixture-private-output-do-not-project/);
  assert.match(report.report_sha256, /^[0-9a-f]{64}$/);
  assert.equal(canonicalSdkActorGraph(report), canonicalSdkActorGraph(analyzeSdkActorGraph(directory)));

  const cliText = execFileSync(
    process.execPath,
    ["dist/src/cli.js", "actors", directory],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.match(cliText, /Gradia Guard SDK declared-actor graph: SOURCE BUNDLE VERIFIED/);
  assert.match(cliText, /Cross-actor declared parent links: 2/);
  assert.match(cliText, /not authenticated by this graph/);
  assert.match(cliText, /no delegation, causal contribution, competence, or quality claim/);

  const cliJson = JSON.parse(
    execFileSync(process.execPath, ["dist/src/cli.js", "actors", "--json", directory], {
      cwd: process.cwd(),
      encoding: "utf8",
    }),
  ) as {
    actor_count: number;
    cross_actor_edge_count: number;
    claim_boundary: string;
    identity_boundary: string;
  };
  assert.equal(cliJson.actor_count, 2);
  assert.equal(cliJson.cross_actor_edge_count, 2);
  assert.equal(
    cliJson.claim_boundary,
    "application_declared_parentage_only_no_delegation_causal_contribution_or_quality_claim",
  );
  assert.equal(
    cliJson.identity_boundary,
    "actor_and_principal_ids_are_application_declared_not_authenticated",
  );
});

test("actor graph distinguishes a declared parent link from a completed handoff", () => {
  const directory = join(mkdtempSync(join(tmpdir(), "gradia-actor-graph-concurrent-")), "bundle");
  const recorder = new SdkRecorder({ directory });
  const parent = begin(recorder, "actor-orchestrator", "plan", null);
  parent.markDispatched();
  const child = begin(recorder, "actor-worker-01", "solve", parent.occurrenceSha256);
  complete(child);
  parent.succeed({
    resolvedDecisionIdentity: IDENTITY,
    decisionOutputBody: Buffer.from('{"status":"complete"}'),
    decisionOutputMediaType: "application/json",
    stateRootAfter: ROOT,
  });
  recorder.finalize();

  const report = analyzeSdkActorGraph(directory);
  assert.equal(report.edges.length, 1);
  assert.equal(report.edges[0]?.parent_dispatch_occurred, true);
  assert.equal(report.edges[0]?.parent_outcome, "success");
  assert.equal(report.edges[0]?.parent_terminal_preceded_child_decision, false);
});

test("actor graph exposes a censored parent instead of presenting it as executed work", () => {
  const directory = join(mkdtempSync(join(tmpdir(), "gradia-actor-graph-censored-")), "bundle");
  const recorder = new SdkRecorder({ directory });
  const parent = begin(recorder, "actor-orchestrator", "blocked-plan", null, "blocked");
  assert.equal(parent.censored, true);
  const child = begin(recorder, "actor-worker-01", "independent-child", parent.occurrenceSha256);
  complete(child);
  recorder.finalize();

  const report = analyzeSdkActorGraph(directory);
  assert.equal(report.edges.length, 1);
  assert.equal(report.edges[0]?.parent_dispatch_occurred, false);
  assert.equal(report.edges[0]?.parent_outcome, "authority_censored");
  assert.equal(report.edges[0]?.parent_terminal_preceded_child_decision, true);
  assert.equal(
    report.actors.find((row) => row.actor_id === "actor-orchestrator")?.dispatched_operation_count,
    0,
  );
});

test("actor graph refuses before analysis when the SDK bundle is not finalized", () => {
  const directory = join(mkdtempSync(join(tmpdir(), "gradia-actor-graph-open-")), "bundle");
  const recorder = new SdkRecorder({ directory });
  complete(begin(recorder, "actor-orchestrator", "plan", null));

  assert.throws(() => analyzeSdkActorGraph(directory), /sdk_actor_graph_bundle_unverified/);
});

test("actor graph refuses a rehashed forward-parent mutation instead of inventing a depth", () => {
  const directory = join(mkdtempSync(join(tmpdir(), "gradia-actor-graph-forward-")), "bundle");
  const recorder = new SdkRecorder({ directory });
  const parent = begin(recorder, "actor-orchestrator", "plan", null);
  complete(parent);
  const child = begin(recorder, "actor-worker-01", "solve", parent.occurrenceSha256);
  complete(child);
  recorder.finalize();

  const rows = readFrames(directory);
  rewriteChain(directory, [rows[2]!, rows[3]!, rows[0]!, rows[1]!]);
  assert.throws(
    () => analyzeSdkActorGraph(directory),
    /sdk_actor_graph_bundle_unverified:.*sdk_parent_not_prior/,
  );
});

test("actor graph refuses a cycle-shaped parent mutation before graph derivation", () => {
  const directory = join(mkdtempSync(join(tmpdir(), "gradia-actor-graph-cycle-")), "bundle");
  const recorder = new SdkRecorder({ directory });
  const parent = begin(recorder, "actor-orchestrator", "plan", null);
  complete(parent);
  const child = begin(recorder, "actor-worker-01", "solve", parent.occurrenceSha256);
  complete(child);
  recorder.finalize();

  const rows = readFrames(directory);
  rows[0]!.parent_occurrence_sha256 = child.occurrenceSha256;
  rows[1]!.parent_occurrence_sha256 = child.occurrenceSha256;
  rewriteChain(directory, rows);

  assert.throws(
    () => analyzeSdkActorGraph(directory),
    /sdk_actor_graph_bundle_unverified:.*sdk_parent_not_prior/,
  );
});

test("application-declared actor labels cannot become authenticated identity claims", () => {
  const directory = join(mkdtempSync(join(tmpdir(), "gradia-actor-graph-spoof-")), "bundle");
  const recorder = new SdkRecorder({ directory });
  complete(begin(recorder, "claimed-security-officer", "approve", null));
  recorder.finalize();

  const report = analyzeSdkActorGraph(directory);
  assert.equal(report.actors[0]?.actor_id, "claimed-security-officer");
  assert.deepEqual(report.actors[0]?.declared_principal_ids, [
    "principal-claimed-security-officer",
  ]);
  assert.equal(
    report.identity_boundary,
    "actor_and_principal_ids_are_application_declared_not_authenticated",
  );
  assert.equal(Object.hasOwn(report, "authenticated_actor_ids"), false);
  assert.match(formatSdkActorGraph(report), /application-declared, not authenticated/);
});

test("actor graph does not reuse stale verification or surface a forged snapshot label", () => {
  const directory = join(mkdtempSync(join(tmpdir(), "gradia-actor-graph-snapshot-")), "bundle");
  const recorder = new SdkRecorder({ directory });
  complete(begin(recorder, "actor-orchestrator", "plan", null));
  recorder.finalize();
  assert.equal(verifySdkBundle(directory).ok, true);

  const rows = readFrames(directory);
  rows[0]!.actor_id = "forged-actor-after-verification";
  rows[1]!.actor_id = "forged-actor-after-verification";
  writeFileSync(
    join(directory, "frames.ndjson"),
    `${rows.map((row) => canonicalJson(row)).join("\n")}\n`,
  );

  let failure: unknown;
  try {
    analyzeSdkActorGraph(directory);
  } catch (error) {
    failure = error;
  }
  assert.ok(failure instanceof Error);
  assert.match(failure.message, /sdk_actor_graph_bundle_unverified/);
  assert.doesNotMatch(failure.message, /forged-actor-after-verification/);
});

function readFrames(directory: string): SdkEvidenceFrame[] {
  return readFileSync(join(directory, "frames.ndjson"), "utf8")
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line) as SdkEvidenceFrame);
}

function rewriteChain(directory: string, rows: SdkEvidenceFrame[]): void {
  let head = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  rows.forEach((row, index) => {
    row.sequence = index;
    row.previous_frame_sha256 = head;
    const { frame_sha256: _old, ...body } = row;
    row.frame_sha256 = digestCanonical(body);
    head = row.frame_sha256;
  });
  writeFileSync(
    join(directory, "frames.ndjson"),
    `${rows.map((row) => canonicalJson(row)).join("\n")}\n`,
  );
  const manifestPath = join(directory, "bundle.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as SdkEvidenceBundleManifest;
  manifest.chain_head_sha256 = head;
  writeFileSync(manifestPath, `${canonicalJson(manifest)}\n`);
}
