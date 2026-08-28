import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  FrameChain,
  digestCanonical,
  processCoverage,
  runGuardedProcess,
  verifyBundle,
  type ActionFrame,
  type EvidenceFrame,
} from "../src/index.js";

function temp(): string {
  return mkdtempSync(join(tmpdir(), "gradia-guard-test-"));
}

function lines(directory: string): EvidenceFrame[] {
  return readFileSync(join(directory, "frames.ndjson"), "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as EvidenceFrame);
}

test("digest-only process run produces a finalized, verifiable chain", async () => {
  const result = await runGuardedProcess({
    command: [process.execPath, "test/fixtures/child.mjs", "0"],
    outputRoot: temp(),
    captureMode: "digest-only",
    cwd: process.cwd(),
  });
  assert.equal(result.exitCode, 0);
  const verification = verifyBundle(result.directory);
  assert.equal(verification.ok, true, verification.blockers.join(","));
  assert.ok(verification.payloads_unavailable >= 2);
  assert.equal((lines(result.directory).at(-1) as ActionFrame).action.kind, "process_terminal");
  assert.equal(readFileSync(join(result.directory, "frames.ndjson"), "utf8").includes("visible output"), false);
});

test("encrypted spool decrypts only with the supplied key", async () => {
  const key = Buffer.alloc(32, 7);
  const result = await runGuardedProcess({
    command: [process.execPath, "test/fixtures/child.mjs", "0"],
    outputRoot: temp(),
    captureMode: "encrypted",
    encryptionKey: key,
    keyId: "local-test-key.v1",
    cwd: process.cwd(),
  });
  const withoutKey = verifyBundle(result.directory);
  assert.equal(withoutKey.ok, true);
  assert.ok(withoutKey.payloads_unavailable >= 2);
  const withKey = verifyBundle(result.directory, { encryptionKey: key, expectedKeyId: "local-test-key.v1" });
  assert.equal(withKey.ok, true, withKey.blockers.join(","));
  assert.ok(withKey.payloads_checked >= 2);
  const wrongKey = verifyBundle(result.directory, { encryptionKey: Buffer.alloc(32, 8) });
  assert.equal(wrongKey.ok, false);
  assert.ok(wrongKey.blockers.some((item) => item.startsWith("encrypted_payload_decryption_failed")));
});

test("tampering and frame reordering fail closed", async () => {
  const result = await runGuardedProcess({
    command: [process.execPath, "test/fixtures/child.mjs", "0"],
    outputRoot: temp(),
    captureMode: "digest-only",
    cwd: process.cwd(),
  });
  const original = lines(result.directory);
  const tampered = structuredClone(original);
  (tampered[1] as ActionFrame).action.reason_codes = ["forged"];
  writeFileSync(
    join(result.directory, "frames.ndjson"),
    `${tampered.map((item) => JSON.stringify(item)).join("\n")}\n`,
  );
  assert.ok(verifyBundle(result.directory).blockers.some((item) => item.startsWith("frame_digest_mismatch")));

  const reordered = [original[0], original[2], original[1], ...original.slice(3)];
  writeFileSync(
    join(result.directory, "frames.ndjson"),
    `${reordered.map((item) => JSON.stringify(item)).join("\n")}\n`,
  );
  const blockers = verifyBundle(result.directory).blockers;
  assert.ok(blockers.some((item) => item.startsWith("frame_sequence_gap")));
  assert.ok(blockers.some((item) => item.startsWith("frame_previous_hash_mismatch")));
});

test("missing predecessor and truncation cannot verify", async () => {
  const result = await runGuardedProcess({
    command: [process.execPath, "test/fixtures/child.mjs", "0"],
    outputRoot: temp(),
    captureMode: "digest-only",
    cwd: process.cwd(),
  });
  const original = lines(result.directory);
  writeFileSync(
    join(result.directory, "frames.ndjson"),
    original
      .slice(1)
      .map((item) => JSON.stringify(item))
      .join("\n"),
  );
  const blockers = verifyBundle(result.directory).blockers;
  assert.ok(blockers.includes("frame_log_truncated"));
  assert.ok(blockers.some((item) => item.startsWith("frame_sequence_gap")));
  assert.ok(blockers.some((item) => item.startsWith("frame_previous_hash_mismatch")));
});

test("coverage overclaim is rejected even if attacker recomputes the frame digest", async () => {
  const result = await runGuardedProcess({
    command: [process.execPath, "test/fixtures/child.mjs", "0"],
    outputRoot: temp(),
    captureMode: "digest-only",
    cwd: process.cwd(),
  });
  const frames = lines(result.directory);
  const first = frames[0] as EvidenceFrame;
  first.coverage = { ...first.coverage, full_world_capture: true };
  const { frame_sha256: _old, ...body } = first;
  first.frame_sha256 = digestCanonical(body);
  writeFileSync(
    join(result.directory, "frames.ndjson"),
    `${frames.map((item) => JSON.stringify(item)).join("\n")}\n`,
  );
  const blockers = verifyBundle(result.directory).blockers;
  assert.ok(blockers.some((item) => item.startsWith("coverage_full_world_overclaim")));
});

test("secret and private-reasoning shapes are refused before a frame exists", () => {
  const chain = new FrameChain({ sessionId: "safe-session" });
  assert.throws(
    () =>
      chain.decision({
        subject: { kind: "decision", identity_sha256: "a".repeat(64) },
        coverage: processCoverage(),
        inputs: [],
        outputs: [],
        authority_scope_ids: [],
        policy_sha256: null,
        decision: {
          kind: "policy_evaluation",
          verdict: "allowed",
          reason_codes: ["safe"],
          ...({ api_key: "must-not-land" } as object),
        },
      }),
    /evidence_secret_shape_refused/,
  );
  assert.equal(chain.length, 0);
  assert.throws(
    () =>
      chain.action({
        subject: { kind: "decision", identity_sha256: "a".repeat(64) },
        coverage: processCoverage(),
        inputs: [],
        outputs: [],
        authority_scope_ids: [],
        policy_sha256: null,
        action: {
          kind: "tool_result",
          disposition: "completed",
          exit_code: null,
          signal: null,
          reason_codes: ["safe"],
          ...({ chain_of_thought: "must-not-land" } as object),
        },
      }),
    /evidence_private_reasoning_refused/,
  );
});

test("nonzero child exit is finalized as failed and remains verifiable", async () => {
  const result = await runGuardedProcess({
    command: [process.execPath, "test/fixtures/child.mjs", "7"],
    outputRoot: temp(),
    captureMode: "digest-only",
    cwd: process.cwd(),
  });
  assert.equal(result.exitCode, 7);
  const terminal = lines(result.directory).at(-1) as ActionFrame;
  assert.equal(terminal.action.disposition, "failed");
  assert.equal(terminal.action.exit_code, 7);
  assert.equal(verifyBundle(result.directory).ok, true);
});

test("a signaled child receives an explicit terminal receipt", async () => {
  const result = await runGuardedProcess({
    command: [process.execPath, "test/fixtures/child.mjs", "signal"],
    outputRoot: temp(),
    captureMode: "digest-only",
    cwd: process.cwd(),
  });
  assert.equal(result.signal, "SIGTERM");
  const terminal = lines(result.directory).at(-1) as ActionFrame;
  assert.equal(terminal.action.disposition, "signaled");
  assert.equal(terminal.action.signal, "SIGTERM");
  assert.equal(verifyBundle(result.directory).ok, true);
});

test("spawn failure is finalized and is not misreported as a child failure", async () => {
  const result = await runGuardedProcess({
    command: [join(temp(), "executable-that-does-not-exist")],
    outputRoot: temp(),
    captureMode: "digest-only",
  });
  assert.equal(result.exitCode, 125);
  const terminal = lines(result.directory).at(-1) as ActionFrame;
  assert.equal(terminal.action.kind, "wrapper_failure");
  assert.equal(verifyBundle(result.directory).ok, true);
});
