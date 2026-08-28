import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  BUNDLE_SCHEMA_VERSION,
  FrameChain,
  GatewayRecorder,
  SdkRecorder,
  canonicalJson,
  digestCanonical,
  processCoverage,
  sha256,
} from "../dist/src/index.js";

const sessionId = "gradia-guard-cross-language-fixture-v1";
const timestamps = [
  "2026-08-23T12:00:01.000Z",
  "2026-08-23T12:00:02.000Z",
  "2026-08-23T12:00:03.000Z",
  "2026-08-23T12:00:04.000Z",
];
let timestampIndex = 0;
const chain = new FrameChain({
  sessionId,
  now: () => new Date(timestamps[timestampIndex++]),
});
const commandIdentity = digestCanonical({ executable: "node", argv: ["agent.js"] });
const subject = { kind: "process", identity_sha256: commandIdentity };
const coverage = processCoverage();
const policySha256 = digestCanonical({
  schema_version: "gradia.guard.reference-fixture-policy.v1",
  purpose: "cross_language_ingestion",
});
const outputBytes = Buffer.from("fixture-output\n");
const outputReference = {
  schema_version: "gradia.guard.content-ref.v1",
  media_type: "application/octet-stream; channel=stdout",
  byte_length: outputBytes.byteLength,
  plaintext_sha256: sha256(outputBytes),
  storage: "digest-only",
  ciphertext_ref: null,
  ciphertext_sha256: null,
  key_id: null,
};
const common = {
  subject,
  coverage,
  inputs: [],
  outputs: [],
  authority_scope_ids: [],
  policy_sha256: policySha256,
};
const frames = [
  chain.decision({
    ...common,
    decision: {
      kind: "process_dispatch",
      verdict: "allowed",
      reason_codes: ["fixture_dispatch_allowed"],
    },
  }),
  chain.action({
    ...common,
    action: {
      kind: "process_started",
      disposition: "running",
      exit_code: null,
      signal: null,
      reason_codes: ["fixture_process_started"],
    },
  }),
  chain.action({
    ...common,
    outputs: [outputReference],
    action: {
      kind: "stdout_chunk",
      disposition: "running",
      exit_code: null,
      signal: null,
      reason_codes: ["fixture_stdout_observed"],
    },
  }),
  chain.action({
    ...common,
    action: {
      kind: "process_terminal",
      disposition: "completed",
      exit_code: 0,
      signal: null,
      reason_codes: ["fixture_process_completed"],
    },
  }),
];
const manifest = {
  schema_version: BUNDLE_SCHEMA_VERSION,
  guard_version: "0.1.0",
  session_id: sessionId,
  created_at: "2026-08-23T12:00:00.000Z",
  finalized_at: "2026-08-23T12:00:05.000Z",
  status: "finalized",
  capture_mode: "digest-only",
  coverage,
  command_identity_sha256: commandIdentity,
  frame_count: frames.length,
  chain_head_sha256: chain.chainHead,
  terminal_disposition: "completed",
};
const expected = {
  bundle: `${canonicalJson(manifest)}\n`,
  frames: `${frames.map((frame) => canonicalJson(frame)).join("\n")}\n`,
};

const gatewayTimes = [
  "2026-08-24T12:00:00.000Z",
  "2026-08-24T12:00:01.000Z",
  "2026-08-24T12:00:02.000Z",
  "2026-08-24T12:00:03.000Z",
  "2026-08-24T12:00:04.000Z",
  "2026-08-24T12:00:05.000Z",
  "2026-08-24T12:00:06.000Z",
];
let gatewayTimeIndex = 0;
const monotonicTimes = [1000, 1042];
let monotonicIndex = 0;
const gatewayRoot = mkdtempSync(join(tmpdir(), "gradia-gateway-fixture-"));
const gatewayDirectory = join(gatewayRoot, "bundle");
const gateway = new GatewayRecorder({
  directory: gatewayDirectory,
  sessionId: "gradia-guard-gateway-cross-language-fixture-v1",
  now: () => new Date(gatewayTimes[gatewayTimeIndex++]),
  monotonicMs: () => monotonicTimes[monotonicIndex++],
});
const gatewayAttempt = gateway.prepare({
  provider: "anthropic",
  requestedModel: "claude-opus-5-20260801",
  logicalRequestId: "gateway-request-1",
  attemptNumber: 1,
  retryOfOccurrenceSha256: null,
  requestBody: Buffer.from('{"messages":[{"role":"user","content":"fixture"}]}'),
  requestMediaType: "application/json",
  policy: {
    decision: "allowed",
    censorKind: null,
    reasonCodes: ["budget_reserved", "policy_allowed"],
    policySha256: "a".repeat(64),
  },
});
gatewayAttempt.markDispatched();
gatewayAttempt.succeed({
  responseBody: Buffer.from('{"content":"fixture answer","model":"claude-opus-5-20260801"}'),
  responseMediaType: "application/json",
  resolvedModel: "claude-opus-5-20260801",
  usage: {
    input_tokens: 12,
    output_tokens: 4,
    cache_read_input_tokens: 0,
    cache_write_input_tokens: 0,
    provider_total_tokens: 16,
  },
  httpStatus: 200,
});
gateway.finalize();
const gatewayExpected = {
  bundle: readFileSync(join(gatewayDirectory, "bundle.json"), "utf8"),
  frames: readFileSync(join(gatewayDirectory, "frames.ndjson"), "utf8"),
};
rmSync(gatewayRoot, { recursive: true, force: true });

const sdkTimes = [
  "2026-08-24T14:00:00.000Z",
  "2026-08-24T14:00:01.000Z",
  "2026-08-24T14:00:02.000Z",
  "2026-08-24T14:00:03.000Z",
  "2026-08-24T14:00:04.000Z",
  "2026-08-24T14:00:05.000Z",
  "2026-08-24T14:00:06.000Z",
  "2026-08-24T14:00:07.000Z",
  "2026-08-24T14:00:08.000Z",
  "2026-08-24T14:00:09.000Z",
  "2026-08-24T14:00:10.000Z",
  "2026-08-24T14:00:11.000Z",
];
let sdkTimeIndex = 0;
const sdkMonotonicTimes = [1000, 1024, 2000, 2035];
let sdkMonotonicIndex = 0;
const sdkRoot = mkdtempSync(join(tmpdir(), "gradia-sdk-fixture-"));
const sdkDirectory = join(sdkRoot, "bundle");
const sdk = new SdkRecorder({
  directory: sdkDirectory,
  sessionId: "gradia-guard-sdk-cross-language-fixture-v1",
  now: () => new Date(sdkTimes[sdkTimeIndex++]),
  monotonicMs: () => sdkMonotonicTimes[sdkMonotonicIndex++],
});
const stateRootBefore = {
  schema_version: "gradia.guard.sdk-state-root.v1",
  source: "application_declared",
  namespace_id: "case-state",
  root_sha256: "d".repeat(64),
};
const stateRootAfterDecision = {
  ...stateRootBefore,
  root_sha256: "e".repeat(64),
};
const stateRootAfterTool = {
  ...stateRootBefore,
  root_sha256: "f".repeat(64),
};
const sdkDecisionIdentity = {
  schema_version: "gradia.guard.sdk-decision-identity.v1",
  decision_type: "reference.disposition",
  executor_kind: "model",
  executor_id: "custom:reference-engine",
  executor_version: "2026.08.24",
  contract_sha256: "b".repeat(64),
};
const sdkDecision = sdk.beginApplicationDecision({
  actorId: "fixture-agent-01",
  principalId: "fixture-tenant-01",
  authorityScopeIds: ["case.read", "decision.write"],
  logicalOperationId: "sdk-decision-1",
  attemptNumber: 1,
  retryOfOccurrenceSha256: null,
  parentOccurrenceSha256: null,
  stateRootBefore,
  decisionIdentity: sdkDecisionIdentity,
  decisionInputBody: Buffer.from('{"case_id":"fixture-case"}'),
  decisionInputMediaType: "application/json",
  policy: {
    decision: "allowed",
    censorKind: null,
    reasonCodes: ["authority_confirmed", "policy_allowed"],
    policySha256: "a".repeat(64),
  },
});
sdkDecision.markDispatched();
sdkDecision.succeed({
  resolvedDecisionIdentity: sdkDecisionIdentity,
  decisionOutputBody: Buffer.from('{"disposition":"refer"}'),
  decisionOutputMediaType: "application/json",
  stateRootAfter: stateRootAfterDecision,
});
const sdkToolIdentity = {
  schema_version: "gradia.guard.sdk-tool-identity.v1",
  registry_id: "fixture-registry-v1",
  tool_id: "case.lookup",
  tool_version: "2.0.0",
  interface_sha256: "c".repeat(64),
};
const sdkTool = sdk.beginRegisteredToolCall({
  actorId: "fixture-agent-01",
  principalId: "fixture-tenant-01",
  authorityScopeIds: ["case.read"],
  logicalOperationId: "sdk-tool-1",
  attemptNumber: 1,
  retryOfOccurrenceSha256: null,
  parentOccurrenceSha256: sdkDecision.occurrenceSha256,
  stateRootBefore: stateRootAfterDecision,
  toolIdentity: sdkToolIdentity,
  toolRequestBody: Buffer.from('{"case_id":"fixture-case"}'),
  toolRequestMediaType: "application/json",
  policy: {
    decision: "allowed",
    censorKind: null,
    reasonCodes: ["authority_confirmed", "policy_allowed"],
    policySha256: "a".repeat(64),
  },
});
sdkTool.markDispatched();
sdkTool.succeed({
  resolvedToolIdentity: sdkToolIdentity,
  toolResultBody: Buffer.from('{"status":"found"}'),
  toolResultMediaType: "application/json",
  stateRootAfter: stateRootAfterTool,
});
sdk.finalize();
const sdkExpected = {
  bundle: readFileSync(join(sdkDirectory, "bundle.json"), "utf8"),
  frames: readFileSync(join(sdkDirectory, "frames.ndjson"), "utf8"),
};
rmSync(sdkRoot, { recursive: true, force: true });

if (process.argv[2] === "--check") {
  const fixture = join("test", "fixtures", "reference-bundle");
  const actualBundle = readFileSync(join(fixture, "bundle.json"), "utf8");
  const actualFrames = readFileSync(join(fixture, "frames.ndjson"), "utf8");
  if (actualBundle !== expected.bundle || actualFrames !== expected.frames) {
    process.stderr.write("reference fixture drifted from the current ABI\n");
    process.exitCode = 1;
  }
  const gatewayFixture = join("test", "fixtures", "gateway-reference-bundle");
  const actualGatewayBundle = readFileSync(join(gatewayFixture, "bundle.json"), "utf8");
  const actualGatewayFrames = readFileSync(join(gatewayFixture, "frames.ndjson"), "utf8");
  if (
    actualGatewayBundle !== gatewayExpected.bundle ||
    actualGatewayFrames !== gatewayExpected.frames
  ) {
    process.stderr.write("gateway reference fixture drifted from the current ABI\n");
    process.exitCode = 1;
  }
  const sdkFixture = join("test", "fixtures", "sdk-reference-bundle");
  const actualSdkBundle = readFileSync(join(sdkFixture, "bundle.json"), "utf8");
  const actualSdkFrames = readFileSync(join(sdkFixture, "frames.ndjson"), "utf8");
  if (actualSdkBundle !== sdkExpected.bundle || actualSdkFrames !== sdkExpected.frames) {
    process.stderr.write("SDK reference fixture drifted from the current ABI\n");
    process.exitCode = 1;
  }
} else {
  process.stdout.write(
    `${JSON.stringify({ process: expected, gateway: gatewayExpected, sdk: sdkExpected })}\n`,
  );
}
