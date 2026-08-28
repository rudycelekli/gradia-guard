import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  canonicalJson,
  createLogicalActionIdentity,
  digestCanonical,
  RUNTIME_ANCHOR_RECEIPT_SCHEMA_VERSION,
  RUNTIME_ANCHOR_STATEMENT_SCHEMA_VERSION,
  RUNTIME_FINALIZATION_SCHEMA_VERSION,
  RUNTIME_GENESIS_SHA256,
  RUNTIME_HEADER_SCHEMA_VERSION,
  RUNTIME_RECEIPT_SCHEMA_VERSION,
  runtimeAnchorReceiptSha256,
  runtimeAnchorStatementSha256,
  runtimeFinalizationSha256,
  runtimeHeaderSha256,
  runtimeReceiptSha256,
  uploadRuntimeEvidenceBundle,
  verifiedRuntimeReceiptForLogicalAction,
  verifyRuntimeEvidenceBundle,
  type GuardRights,
  type RuntimeAnchorReceipt,
  type RuntimeAnchorStatement,
  type RuntimeEvidenceBody,
  type RuntimeEvidenceBundle,
  type RuntimeEvidenceHeader,
  type RuntimeEvidenceReceipt,
  type RuntimeFinalization,
} from "../src/index.js";

const createdAt = "2026-08-27T12:00:00.000Z";
const finalizedAt = "2026-08-27T12:00:00.300Z";

function sha(label: string): string {
  return createHash("sha256").update(label).digest("hex");
}

function buildBundle(options: {
  sessionId?: string;
  processOccurrenceId?: string;
} = {}): RuntimeEvidenceBundle {
  const headerBody = {
    schema_version: RUNTIME_HEADER_SCHEMA_VERSION,
    runtime_version: "0.1.0",
    session_id: options.sessionId ?? "gradia-guard-runtime-cross-language-fixture-v1",
    created_at: createdAt,
    capture_boundary: "declared_runtime_recorder" as const,
    bypass_possible: true as const,
    bypass_declaration:
      "operations_outside_this_recorder_are_not_observed_or_enforced" as const,
    isolation_attestation: "not_attested" as const,
    runtime_identity_sha256: sha("runtime"),
    policy_sha256: sha("policy"),
    credential_policy_sha256: sha("credential-policy"),
    declared_credential_scope_ids: ["model.invoke"],
  };
  const header: RuntimeEvidenceHeader = {
    ...headerBody,
    header_sha256: digestCanonical(headerBody),
  };
  assert.equal(runtimeHeaderSha256(header), header.header_sha256);
  const receipts: RuntimeEvidenceReceipt[] = [];
  appendReceipt(receipts, header, {
    kind: "process",
    operation: "spawn",
    process_identity_sha256: sha("process"),
    parent_process_identity_sha256: sha("parent"),
    command_identity_sha256: sha("command-without-argv"),
    outcome: "running",
    exit_code: null,
    signal: null,
    reason_codes: ["runtime_dispatch_observed"],
  }, "2026-08-27T12:00:00.100Z", options.processOccurrenceId ?? "process-spawn-1");
  appendReceipt(receipts, header, {
    kind: "terminal",
    terminal_status: "completed",
    reason_codes: ["runtime_capture_completed"],
    preterminal_receipt_count: 1,
    preterminal_chain_head_sha256: receipts[0]?.receipt_sha256 ?? RUNTIME_GENESIS_SHA256,
    crash_recovery: false,
  }, "2026-08-27T12:00:00.200Z", "runtime-terminal-1");
  const terminal = receipts[1] as RuntimeEvidenceReceipt;
  const finalizationBody = {
    schema_version: RUNTIME_FINALIZATION_SCHEMA_VERSION,
    session_id: header.session_id,
    header_sha256: header.header_sha256,
    finalized_at: finalizedAt,
    receipt_count: receipts.length,
    chain_head_sha256: terminal.receipt_sha256,
    terminal_receipt_sha256: terminal.receipt_sha256,
    terminal_status: "completed" as const,
  };
  const finalization: RuntimeFinalization = {
    ...finalizationBody,
    finalization_sha256: digestCanonical(finalizationBody),
  };
  assert.equal(runtimeFinalizationSha256(finalization), finalization.finalization_sha256);
  const statementBody = {
    schema_version: RUNTIME_ANCHOR_STATEMENT_SCHEMA_VERSION,
    session_id: header.session_id,
    header_sha256: header.header_sha256,
    finalization_sha256: finalization.finalization_sha256,
    receipt_count: receipts.length,
    chain_head_sha256: terminal.receipt_sha256,
  };
  const statement: RuntimeAnchorStatement = {
    ...statementBody,
    statement_sha256: digestCanonical(statementBody),
  };
  assert.equal(runtimeAnchorStatementSha256(statement), statement.statement_sha256);
  const anchorBody = {
    schema_version: RUNTIME_ANCHOR_RECEIPT_SCHEMA_VERSION,
    store_id: "local-portable-anchor.v1",
    anchor_sequence: 0,
    anchored_at: finalizedAt,
    previous_anchor_sha256: RUNTIME_GENESIS_SHA256,
    statement,
  };
  const anchor: RuntimeAnchorReceipt = {
    ...anchorBody,
    anchor_sha256: digestCanonical(anchorBody),
  };
  assert.equal(runtimeAnchorReceiptSha256(anchor), anchor.anchor_sha256);
  return { header, receipts, finalization, anchor_receipt: anchor };
}

test("logical action binding verifies the complete runtime bundle before returning its receipt", () => {
  const identity = createLogicalActionIdentity({
    schema_version: "gradia.logical-action-coordinates.v1",
    action_namespace_id: "run-conditional-underwriting-001",
    actor_id: "underwriter-agent-01",
    logical_operation_id: "loan-case-042.condition-review",
    attempt_number: 2,
  });
  const bundle = buildBundle({
    sessionId: identity.coordinates.action_namespace_id,
    processOccurrenceId: identity.occurrence_id,
  });
  const receipt = verifiedRuntimeReceiptForLogicalAction(bundle, identity);
  assert.equal(receipt.occurrence_id, identity.occurrence_id);

  const absent = createLogicalActionIdentity({
    ...identity.coordinates,
    attempt_number: 3,
  });
  assert.throws(
    () => verifiedRuntimeReceiptForLogicalAction(bundle, absent),
    /logical_action_runtime_occurrence_missing/,
  );
  const otherNamespace = createLogicalActionIdentity({
    ...identity.coordinates,
    action_namespace_id: "run-conditional-underwriting-002",
  });
  assert.throws(
    () => verifiedRuntimeReceiptForLogicalAction(bundle, otherNamespace),
    /logical_action_runtime_namespace_mismatch/,
  );
  const tampered = structuredClone(bundle);
  tampered.receipts[0]!.receipt_sha256 = "f".repeat(64);
  assert.throws(
    () => verifiedRuntimeReceiptForLogicalAction(tampered, identity),
    /logical_action_runtime_bundle_unverified/,
  );
});

function appendReceipt(
  receipts: RuntimeEvidenceReceipt[],
  header: RuntimeEvidenceHeader,
  body: RuntimeEvidenceBody,
  observedAt: string,
  occurrenceId: string,
): void {
  const receiptBody = {
    schema_version: RUNTIME_RECEIPT_SCHEMA_VERSION,
    session_id: header.session_id,
    header_sha256: header.header_sha256,
    sequence: receipts.length,
    logical_time: receipts.length,
    observed_at: observedAt,
    occurrence_id: occurrenceId,
    previous_receipt_sha256: receipts.at(-1)?.receipt_sha256 ?? RUNTIME_GENESIS_SHA256,
    body,
  };
  const receipt: RuntimeEvidenceReceipt = {
    ...receiptBody,
    receipt_sha256: digestCanonical(receiptBody),
  };
  assert.equal(runtimeReceiptSha256(receipt), receipt.receipt_sha256);
  receipts.push(receipt);
}

function signedRemoteAnchor(input: {
  editionId: string;
  bundleSha256: string;
  editionSha256: string;
  rights: GuardRights;
}): unknown {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ format: "der", type: "spki" });
  const publicRaw = publicDer.subarray(publicDer.length - 32);
  const attestation = {
    schema_version: "gradia.guard.remote-anchor.v1",
    anchor_scope: "admitted_edition_and_retention_declaration",
    guard_evidence_edition_id: input.editionId,
    org_id: "org-01",
    project_id: "project-01",
    session_id: "gradia-guard-runtime-cross-language-fixture-v1",
    bundle_sha256: input.bundleSha256,
    edition_sha256: input.editionSha256,
    verification_sha256: sha("verification"),
    retention_policy_id: "digest-only-v1",
    retention_execution_proved: false,
    deletion_proved: false,
    storage_residency_proved: false,
    created_by: "collector-01",
    created_at: "2026-08-27T12:00:01+00:00",
  } as const;
  return {
    attestation,
    signature_ed25519: sign(null, Buffer.from(canonicalJson(attestation)), privateKey).toString("hex"),
    public_key_ed25519: publicRaw.toString("hex"),
    public_key_id: createHash("sha256").update(publicRaw).digest("hex").slice(0, 16),
  };
}

test("portable runtime verifier reproduces the managed G3 bundle and preserves its ceiling", () => {
  const bundle = buildBundle();
  const fixture = JSON.parse(
    readFileSync(
      fileURLToPath(new URL("../../test/fixtures/runtime-reference-bundle.json", import.meta.url)),
      "utf8",
    ),
  ) as unknown;
  assert.equal(canonicalJson(fixture), canonicalJson(bundle));
  const result = verifyRuntimeEvidenceBundle(bundle);
  assert.equal(result.ok, true, result.blockers.join(","));
  assert.equal(result.receipt_count, 2);
  assert.equal(result.terminal_status, "completed");
  assert.equal(result.bundle_sha256, digestCanonical(bundle));
  assert.equal(
    result.claim_boundary,
    "declared_runtime_observation_not_container_or_kubernetes_enforcement",
  );
});

test("portable runtime verifier refuses mutation, extra fields, and non-genesis anchors", () => {
  const mutation = structuredClone(buildBundle()) as unknown as Record<string, unknown>;
  const receipts = mutation["receipts"] as Record<string, unknown>[];
  (receipts[0]?.["body"] as Record<string, unknown>)["command_identity_sha256"] = sha("forged");
  const changed = verifyRuntimeEvidenceBundle(mutation);
  assert.equal(changed.ok, false);
  assert.ok(changed.blockers.includes("runtime_receipt_digest_mismatch:0"));

  const secret = structuredClone(buildBundle()) as unknown as Record<string, unknown>;
  (secret["header"] as Record<string, unknown>)["credential_value"] = "must-never-enter-schema";
  assert.deepEqual(verifyRuntimeEvidenceBundle(secret).blockers, ["runtime_evidence_bundle_schema_invalid"]);

  const nonportable = structuredClone(buildBundle());
  nonportable.anchor_receipt.anchor_sequence = 1;
  nonportable.anchor_receipt.anchor_sha256 = runtimeAnchorReceiptSha256(nonportable.anchor_receipt);
  const refused = verifyRuntimeEvidenceBundle(nonportable);
  assert.equal(refused.ok, false);
  assert.ok(refused.blockers.includes("runtime_anchor_unverified"));
});

test("managed G3 upload verifies before dispatch and binds exact remote admission", async () => {
  const bundle = buildBundle();
  const rights: GuardRights = {
    evaluation: true,
    redistribution: false,
    derived_publication: false,
    training: false,
    raw_trajectory: false,
  };
  const bundleSha256 = digestCanonical(bundle);
  const editionSha256 = digestCanonical({
    schema_version: "gradia.guard.evidence-edition.v1",
    project_id: "project-01",
    bundle_sha256: bundleSha256,
    rights,
    retention_policy_id: "digest-only-v1",
    created_by: "collector-01",
  });
  const result = await uploadRuntimeEvidenceBundle(bundle, {
    apiBase: "https://ingest.example.test",
    projectId: "project-01",
    token: "service-account-secret",
    retentionPolicyId: "digest-only-v1",
    rights,
    fetchImpl: async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      assert.equal(canonicalJson(body["bundle"]), canonicalJson(bundle));
      assert.equal(String(init?.body).includes("service-account-secret"), false);
      const requestId = new Headers(init?.headers).get("x-request-id") ?? "";
      return new Response(JSON.stringify({
        guard_evidence_edition_id: "guard-runtime-edition-01",
        bundle_sha256: bundleSha256,
        edition_sha256: editionSha256,
        created_by: "collector-01",
        remote_anchor: signedRemoteAnchor({
          editionId: "guard-runtime-edition-01",
          bundleSha256,
          editionSha256,
          rights,
        }),
      }), { status: 201, headers: { "x-request-id": requestId } });
    },
  });
  assert.equal(result.bundleSha256, bundleSha256);
  assert.equal(result.editionSha256, editionSha256);
  assert.equal(result.remoteAnchorVerification.ok, true);

  const corrupt = structuredClone(bundle);
  corrupt.finalization.receipt_count += 1;
  await assert.rejects(
    uploadRuntimeEvidenceBundle(corrupt, {
      apiBase: "https://ingest.example.test",
      projectId: "project-01",
      token: "service-account-secret",
      retentionPolicyId: "digest-only-v1",
      rights,
      fetchImpl: async () => { throw new Error("network_must_not_run"); },
    }),
    /upload_runtime_bundle_unverified/,
  );
});
