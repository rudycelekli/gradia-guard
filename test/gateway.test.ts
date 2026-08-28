import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  GatewayIdentityMismatchError,
  GatewayRecorder,
  canonicalJson,
  digestCanonical,
  sha256,
  verifyBundle,
  type GatewayActionFrame,
  type GatewayDecisionFrame,
  type GatewayEvidenceBundleManifest,
  type GatewayEvidenceFrame,
  type GatewayUsage,
} from "../src/index.js";

const USAGE: GatewayUsage = {
  input_tokens: 100,
  output_tokens: 25,
  cache_read_input_tokens: 0,
  cache_write_input_tokens: 0,
  provider_total_tokens: 125,
};
const POLICY_SHA = "a".repeat(64);

function temp(): string {
  return join(mkdtempSync(join(tmpdir(), "gradia-gateway-test-")), "bundle");
}

function recorder(): GatewayRecorder {
  return new GatewayRecorder({ directory: temp() });
}

function prepare(
  instance: GatewayRecorder,
  overrides: Partial<Parameters<GatewayRecorder["prepare"]>[0]> = {},
) {
  return instance.prepare({
    provider: "anthropic",
    requestedModel: "claude-opus-5-20260801",
    logicalRequestId: "request-1",
    attemptNumber: 1,
    retryOfOccurrenceSha256: null,
    requestBody: Buffer.from(
      '{"messages":[{"role":"user","content":"private test prompt"}],"api_key":"fake-never-store"}',
    ),
    requestMediaType: "application/json",
    policy: {
      decision: "allowed",
      censorKind: null,
      reasonCodes: ["budget_reserved", "policy_allowed"],
      policySha256: POLICY_SHA,
    },
    ...overrides,
  });
}

function success(attempt: ReturnType<typeof prepare>, resolvedModel = "claude-opus-5-20260801") {
  attempt.markDispatched();
  return attempt.succeed({
    responseBody: Buffer.from(
      '{"model":"claude-opus-5-20260801","content":"answer","chain_of_thought":"fake-never-store"}',
    ),
    responseMediaType: "application/json",
    resolvedModel,
    usage: USAGE,
    httpStatus: 200,
  });
}

function frames(directory: string): GatewayEvidenceFrame[] {
  return readFileSync(join(directory, "frames.ndjson"), "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as GatewayEvidenceFrame);
}

test("gateway recorder captures a real provider-neutral success without raw bodies", () => {
  const instance = recorder();
  const attempt = prepare(instance);
  const response = success(attempt);
  instance.finalize();

  const verification = verifyBundle(instance.directory);
  assert.equal(verification.ok, true, verification.blockers.join(","));
  assert.equal(response.outcome, "success");
  assert.equal(response.resolved_model, "claude-opus-5-20260801");
  assert.deepEqual(response.usage, USAGE);
  assert.equal(response.dispatch_occurred, true);
  assert.ok((response.latency_ms ?? -1) >= 0);
  const rawFrames = readFileSync(join(instance.directory, "frames.ndjson"), "utf8");
  assert.equal(rawFrames.includes("private test prompt"), false);
  assert.equal(rawFrames.includes("fake-never-store"), false);
  assert.equal(rawFrames.includes("chain_of_thought"), false);
  assert.equal(
    (frames(instance.directory)[0] as GatewayDecisionFrame).request.plaintext_sha256,
    sha256(
      Buffer.from(
        '{"messages":[{"role":"user","content":"private test prompt"}],"api_key":"fake-never-store"}',
      ),
    ),
  );
});

test("latest aliases and malformed unversioned model identities are refused", () => {
  const first = recorder();
  assert.throws(() => prepare(first, { requestedModel: "claude-opus-latest" }), /not_exact_pin/);
  assert.equal(framesOrEmpty(first.directory).length, 0);

  const second = recorder();
  assert.throws(() => prepare(second, { requestedModel: "frontier-model" }), /not_exact_pin/);
  assert.equal(framesOrEmpty(second.directory).length, 0);
});

test("gateway input has no header or credential capture surface", () => {
  const instance = recorder();
  const unsafe = {
    provider: "anthropic",
    requestedModel: "claude-opus-5-20260801",
    logicalRequestId: "request-1",
    attemptNumber: 1,
    retryOfOccurrenceSha256: null,
    requestBody: Buffer.from("{}"),
    requestMediaType: "application/json",
    policy: {
      decision: "allowed",
      censorKind: null,
      reasonCodes: ["policy_allowed"],
      policySha256: POLICY_SHA,
    },
    headers: { authorization: "Bearer fake-never-store" },
  };
  assert.throws(
    () => instance.prepare(unsafe as unknown as Parameters<GatewayRecorder["prepare"]>[0]),
    /gateway_prepare_input_fields_invalid/,
  );
  assert.equal(framesOrEmpty(instance.directory).length, 0);
});

test("resolved-model mismatch is recorded and the success path fails closed", () => {
  const instance = recorder();
  const attempt = prepare(instance);
  assert.throws(
    () => success(attempt, "claude-opus-5-20260901"),
    (error: unknown) => error instanceof GatewayIdentityMismatchError,
  );
  instance.finalize();
  const action = frames(instance.directory).at(-1) as GatewayActionFrame;
  assert.equal(action.outcome, "identity_mismatch");
  const verification = verifyBundle(instance.directory);
  assert.equal(verification.ok, false);
  assert.ok(verification.blockers.some((item) => item.startsWith("gateway_identity_mismatch_recorded")));
});

test("pre-dispatch budget censor is distinct from provider failure", () => {
  const censoredRecorder = recorder();
  const censored = prepare(censoredRecorder, {
    policy: {
      decision: "blocked",
      censorKind: "budget",
      reasonCodes: ["budget_reservation_refused"],
      policySha256: POLICY_SHA,
    },
  });
  assert.equal(censored.censored, true);
  assert.throws(() => censored.markDispatched(), /cannot_dispatch/);
  censoredRecorder.finalize();
  const censorFrame = frames(censoredRecorder.directory).at(-1) as GatewayActionFrame;
  assert.equal(censorFrame.outcome, "budget_censored");
  assert.equal(censorFrame.dispatch_occurred, false);
  assert.equal(verifyBundle(censoredRecorder.directory).ok, true);

  const failedRecorder = recorder();
  const failed = prepare(failedRecorder);
  failed.markDispatched();
  failed.fail({
    outcome: "provider_failure",
    responseBody: Buffer.from('{"error":"rate_limited"}'),
    responseMediaType: "application/json",
    resolvedModel: null,
    usage: null,
    httpStatus: 429,
    failureCode: "provider_rate_limited",
  });
  failedRecorder.finalize();
  const failureFrame = frames(failedRecorder.directory).at(-1) as GatewayActionFrame;
  assert.equal(failureFrame.outcome, "provider_failure");
  assert.equal(failureFrame.dispatch_occurred, true);
  assert.equal(verifyBundle(failedRecorder.directory).ok, true);
});

test("transport failure cannot smuggle a provider response", () => {
  const instance = recorder();
  const attempt = prepare(instance);
  attempt.markDispatched();
  assert.throws(
    () =>
      attempt.fail({
        outcome: "transport_failure",
        responseBody: Buffer.from("body-that-cannot-exist"),
        responseMediaType: "text/plain",
        resolvedModel: null,
        usage: null,
        httpStatus: null,
        failureCode: "connection_reset",
      }),
    /has_provider_response/,
  );
  assert.throws(() => instance.finalize(), /open_attempts/);
});

test("retry occurrence must bind to the immediately prior recorded attempt", () => {
  const instance = recorder();
  const first = prepare(instance);
  success(first);
  assert.throws(
    () =>
      prepare(instance, {
        attemptNumber: 2,
        retryOfOccurrenceSha256: "b".repeat(64),
      }),
    /retry_parent_not_recorded/,
  );
  const retry = prepare(instance, {
    attemptNumber: 2,
    retryOfOccurrenceSha256: first.occurrenceSha256,
  });
  retry.markDispatched();
  retry.fail({
    outcome: "transport_failure",
    responseBody: null,
    responseMediaType: null,
    resolvedModel: null,
    usage: null,
    httpStatus: null,
    failureCode: "connection_reset",
  });
  instance.finalize();
  assert.equal(verifyBundle(instance.directory).ok, true);
});

test("semantic mutation is rejected even after every hash is recomputed", () => {
  const instance = recorder();
  success(prepare(instance));
  instance.finalize();
  const rows = frames(instance.directory);
  const action = rows[1] as GatewayActionFrame;
  delete (action as unknown as { usage?: GatewayUsage }).usage;
  rewriteChain(instance.directory, rows);
  const verification = verifyBundle(instance.directory);
  assert.equal(verification.ok, false);
  assert.ok(
    verification.blockers.some(
      (item) => item.startsWith("gateway_frame_fields_invalid") || item.startsWith("gateway_frame_shape_unreadable"),
    ),
  );
});

test("bypass declaration and coverage cannot be edited into stronger claims", () => {
  const instance = recorder();
  success(prepare(instance));
  instance.finalize();
  const manifestPath = join(instance.directory, "bundle.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as GatewayEvidenceBundleManifest;
  (manifest as unknown as { bypass_possible: boolean }).bypass_possible = false;
  manifest.coverage.full_world_capture = true;
  writeFileSync(manifestPath, `${canonicalJson(manifest)}\n`);
  const verification = verifyBundle(instance.directory);
  assert.equal(verification.ok, false);
  assert.ok(verification.blockers.includes("gateway_bundle_bypass_declaration_invalid"));
  assert.ok(verification.blockers.includes("coverage_full_world_overclaim"));
});

test("rehashed policy and dispatch-timing mutations remain detectable", () => {
  const instance = recorder();
  success(prepare(instance));
  instance.finalize();
  const rows = frames(instance.directory);
  const decision = rows[0] as GatewayDecisionFrame;
  decision.policy.decision = "blocked";
  decision.policy.censor_kind = "budget";
  decision.policy.reason_codes = ["budget_reservation_refused"];
  const { receipt_sha256: _receipt, ...policyBody } = decision.policy;
  decision.policy.receipt_sha256 = digestCanonical(policyBody);
  const action = rows[1] as GatewayActionFrame;
  action.terminal_observed_at = "2026-01-01T00:00:00.000Z";
  action.response_received_at = "2026-01-01T00:00:00.000Z";
  rewriteChain(instance.directory, rows);
  const verification = verifyBundle(instance.directory);
  assert.equal(verification.ok, false);
  assert.ok(
    verification.blockers.some((item) => item.startsWith("gateway_policy_outcome_mismatch")),
  );
  assert.ok(
    verification.blockers.some((item) => item.startsWith("gateway_dispatch_timing_invalid")),
  );
});

function framesOrEmpty(directory: string): GatewayEvidenceFrame[] {
  const raw = readFileSync(join(directory, "frames.ndjson"), "utf8").trim();
  return raw ? raw.split("\n").map((line) => JSON.parse(line) as GatewayEvidenceFrame) : [];
}

function rewriteChain(directory: string, rows: GatewayEvidenceFrame[]): void {
  let head = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  rows.forEach((row, index) => {
    row.sequence = index;
    row.previous_frame_sha256 = head;
    const { frame_sha256: _old, ...body } = row;
    row.frame_sha256 = digestCanonical(body);
    head = row.frame_sha256;
  });
  writeFileSync(join(directory, "frames.ndjson"), `${rows.map((row) => canonicalJson(row)).join("\n")}\n`);
  const manifestPath = join(directory, "bundle.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as GatewayEvidenceBundleManifest;
  manifest.chain_head_sha256 = head;
  manifest.frame_count = rows.length;
  writeFileSync(manifestPath, `${canonicalJson(manifest)}\n`);
}
