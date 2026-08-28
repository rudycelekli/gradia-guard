import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  appendFileSync,
  chmodSync,
  mkdtempSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  DurableRuntimeEvidenceRecorder,
  loadRuntimeEvidenceBundle,
  verifyRuntimeEvidenceBundle,
  type RuntimeProcessEvidenceBody,
} from "../src/index.js";

function sha(label: string): string {
  return createHash("sha256").update(label).digest("hex");
}

function directory(label: string): string {
  return join(mkdtempSync(join(tmpdir(), `gradia-runtime-${label}-`)), "journal");
}

function recorder(path: string): DurableRuntimeEvidenceRecorder {
  return new DurableRuntimeEvidenceRecorder({
    directory: path,
    runtimeVersion: "0.1.0",
    sessionId: "runtime-crash-recovery-1",
    createdAt: "2026-08-27T13:00:00.000Z",
    runtimeIdentitySha256: sha("runtime"),
    policySha256: sha("policy"),
    credentialPolicySha256: sha("credential-policy"),
    declaredCredentialScopeIds: ["model.invoke"],
  });
}

function processSpawn(): RuntimeProcessEvidenceBody {
  return {
    kind: "process",
    operation: "spawn",
    process_identity_sha256: sha("process"),
    parent_process_identity_sha256: sha("parent"),
    command_identity_sha256: sha("command"),
    outcome: "running",
    exit_code: null,
    signal: null,
    reason_codes: ["runtime_dispatch_observed"],
  };
}

test("fsync-backed recorder recovers a verified prefix and emits an honest crash terminal", () => {
  const path = directory("recover");
  const first = recorder(path);
  first.append(processSpawn(), {
    logicalTime: 0,
    observedAt: "2026-08-27T13:00:00.100Z",
    occurrenceId: "process-spawn-1",
  });

  const recovered = DurableRuntimeEvidenceRecorder.recover(path);
  assert.equal(recovered.receipts.length, 1);
  recovered.terminalize({
    terminalStatus: "crashed",
    reasonCodes: ["runtime_parent_detected_crash"],
    crashRecovery: true,
    logicalTime: 1,
    observedAt: "2026-08-27T13:00:00.200Z",
    occurrenceId: "runtime-crash-terminal-1",
  });
  const bundle = recovered.finalize("2026-08-27T13:00:00.300Z");
  const verification = verifyRuntimeEvidenceBundle(bundle);
  assert.equal(verification.ok, true, verification.blockers.join(","));
  assert.equal(verification.terminal_status, "crashed");
  const terminal = bundle.receipts.at(-1);
  assert.equal(terminal?.body.kind, "terminal");
  if (terminal?.body.kind === "terminal") {
    assert.equal(terminal.body.crash_recovery, true);
  }
  assert.deepEqual(loadRuntimeEvidenceBundle(recovered.bundlePath), bundle);
  assert.equal(statSync(path).mode & 0o777, 0o700);
  for (const file of [recovered.headerPath, recovered.receiptsPath, recovered.bundlePath]) {
    assert.equal(statSync(file).mode & 0o777, 0o600);
  }
  assert.throws(() => DurableRuntimeEvidenceRecorder.recover(path), /already_finalized/);
});

test("recovery refuses truncation and rehashed-looking journal corruption", () => {
  const truncatedPath = directory("truncated");
  const truncated = recorder(truncatedPath);
  truncated.append(processSpawn(), {
    logicalTime: 0,
    observedAt: "2026-08-27T13:00:00.100Z",
    occurrenceId: "process-spawn-1",
  });
  appendFileSync(truncated.receiptsPath, "{", "utf8");
  assert.throws(
    () => DurableRuntimeEvidenceRecorder.recover(truncatedPath),
    /runtime_receipt_journal_truncated/,
  );

  const corruptPath = directory("corrupt");
  const corrupt = recorder(corruptPath);
  corrupt.append(processSpawn(), {
    logicalTime: 0,
    observedAt: "2026-08-27T13:00:00.100Z",
    occurrenceId: "process-spawn-1",
  });
  const receipt = JSON.parse(readFileSync(corrupt.receiptsPath, "utf8")) as Record<string, unknown>;
  const body = receipt["body"] as Record<string, unknown>;
  body["command_identity_sha256"] = sha("forged-command");
  writeFileSync(corrupt.receiptsPath, `${JSON.stringify(receipt)}\n`, { mode: 0o600 });
  chmodSync(corrupt.receiptsPath, 0o600);
  assert.throws(
    () => DurableRuntimeEvidenceRecorder.recover(corruptPath),
    /runtime_receipt_digest_mismatch:0/,
  );
});

test("invalid body and post-terminal writes never enter the durable journal", () => {
  const path = directory("state-machine");
  const current = recorder(path);
  const before = readFileSync(current.receiptsPath, "utf8");
  const invalid = processSpawn() as unknown as Record<string, unknown>;
  invalid["outcome"] = "completed";
  assert.throws(
    () => current.append(invalid as unknown as RuntimeProcessEvidenceBody, {
      logicalTime: 0,
      observedAt: "2026-08-27T13:00:00.100Z",
      occurrenceId: "invalid-process-1",
    }),
    /runtime_evidence_prefix_schema_invalid/,
  );
  assert.equal(readFileSync(current.receiptsPath, "utf8"), before);
  current.terminalize({
    terminalStatus: "completed",
    reasonCodes: ["runtime_capture_completed"],
    crashRecovery: false,
    logicalTime: 0,
    observedAt: "2026-08-27T13:00:00.200Z",
    occurrenceId: "runtime-terminal-1",
  });
  const terminalBytes = readFileSync(current.receiptsPath, "utf8");
  assert.throws(
    () => current.append(processSpawn(), {
      logicalTime: 1,
      observedAt: "2026-08-27T13:00:00.300Z",
      occurrenceId: "late-process-1",
    }),
    /runtime_post_terminal_write/,
  );
  assert.equal(readFileSync(current.receiptsPath, "utf8"), terminalBytes);
});
