import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { AuthenticatedProviderGateway } from "../src/authenticated-gateway.js";
import { digestCanonical } from "../src/canonical.js";
import { sealPolicy, type GuardPolicyBody } from "../src/policy.js";
import { verifyGatewayBundle } from "../src/gateway-verify.js";
import { issueWorkloadIdentity, type GuardWorkloadIdentityClaims } from "../src/workload-identity.js";

const keys = generateKeyPairSync("ed25519");
const now = 1_787_549_400;
const requestedModel = "gpt-5.6-2026-08-01";

function identityClaims(): GuardWorkloadIdentityClaims {
  return {
    issuer_id: "gradia-managed",
    organization_id: "org-1",
    project_id: "project-1",
    workload_id: "agent-1",
    deployment_id: "deployment-1",
    audience: "guard-egress",
    policy_sha256: digestCanonical(policyBody()),
    image_sha256: digestCanonical({ image: "v1" }),
    configuration_sha256: digestCanonical({ configuration: "v1" }),
    collector_sha256: digestCanonical({ collector: "v1" }),
    authority_scope_ids: ["case.read"],
    issued_at_unix: now,
    not_before_unix: now,
    expires_at_unix: now + 300,
    nonce_sha256: digestCanonical({ nonce: "fixture" }),
  };
}

function policyBody(): GuardPolicyBody {
  return {
    schema_version: "gradia.guard.policy.v1",
    policy_id: "gateway-policy",
    policy_version: "v1",
    default_decision: "blocked",
    model_routes: [
      {
        provider: "openai",
        requested_model: requestedModel,
        authority_scope_ids: ["case.read"],
        max_request_bytes: 10_000,
        max_attempt_number: 1,
      },
    ],
    tool_routes: [],
  };
}

function requestBody(): Uint8Array {
  return Buffer.from(JSON.stringify({ model: requestedModel, input: "hello" }));
}

function responseBody(model = requestedModel): Uint8Array {
  return Buffer.from(
    JSON.stringify({
      id: "response-1",
      model,
      usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 },
      output: [],
    }),
  );
}

function readFrames(directory: string): Array<Record<string, unknown>> {
  return readFileSync(join(directory, "frames.ndjson"), "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

function makeGateway(
  directory: string,
  upstreamDispatch: ConstructorParameters<typeof AuthenticatedProviderGateway>[0]["upstreamDispatch"],
  identity = issueWorkloadIdentity(identityClaims(), "issuer-key-v1", keys.privateKey),
): AuthenticatedProviderGateway {
  const source = identityClaims();
  return new AuthenticatedProviderGateway({
    directory,
    policy: sealPolicy(policyBody()),
    workloadIdentity: identity,
    trustedPublicKeys: { "issuer-key-v1": keys.publicKey },
    workloadExpectation: {
      issuerId: source.issuer_id,
      organizationId: source.organization_id,
      projectId: source.project_id,
      workloadId: source.workload_id,
      deploymentId: source.deployment_id,
      audience: source.audience,
      policySha256: source.policy_sha256,
      imageSha256: source.image_sha256,
      configurationSha256: source.configuration_sha256,
      collectorSha256: source.collector_sha256,
    },
    maxIdentityLifetimeSeconds: 600,
    nowUnix: () => now + 1,
    upstreamDispatch,
  });
}

const request = {
  provider: "openai" as const,
  requestBody: requestBody(),
  requestMediaType: "application/json" as const,
  requestedModelFromRoute: null,
  logicalRequestId: "request-1",
  attemptNumber: 1,
  retryOfOccurrenceSha256: null,
  authorityScopeIds: ["case.read"],
};

test("authenticated gateway verifies identity and policy before dispatch", async () => {
  const directory = join(mkdtempSync(join(tmpdir(), "gradia-auth-gateway-")), "bundle");
  let dispatches = 0;
  const gateway = makeGateway(directory, async (input) => {
    dispatches += 1;
    assert.deepEqual(Object.keys(input).sort(), [
      "provider",
      "requestBody",
      "requestMediaType",
      "requestedModel",
    ]);
    assert.equal(input.requestedModel, requestedModel);
    return { responseBody: responseBody(), responseMediaType: "application/json", httpStatus: 200 };
  });
  const result = await gateway.dispatch(request);
  gateway.finalize();
  assert.equal(dispatches, 1);
  assert.equal(result.disposition, "completed");
  assert.equal(result.action?.outcome, "success");
  assert.ok(result.identitySha256);
  assert.deepEqual(verifyGatewayBundle(directory).blockers, []);
  const decision = readFrames(directory)[0] as { policy: { reason_codes: string[] } };
  assert.ok(decision.policy.reason_codes.includes(`workload_identity_sha256:${result.identitySha256}`));
  assert.doesNotMatch(readFileSync(join(directory, "frames.ndjson"), "utf8"), /hello/);
});

test("invalid workload identity records a refusal and never dispatches", async () => {
  const directory = join(mkdtempSync(join(tmpdir(), "gradia-auth-refuse-")), "bundle");
  let dispatches = 0;
  const identity = issueWorkloadIdentity(identityClaims(), "foreign-key-v1", generateKeyPairSync("ed25519").privateKey);
  const gateway = makeGateway(directory, async () => {
    dispatches += 1;
    throw new Error("must not run");
  }, identity);
  const result = await gateway.dispatch(request);
  gateway.finalize();
  assert.equal(dispatches, 0);
  assert.equal(result.disposition, "blocked");
  assert.equal(result.identitySha256, null);
  assert.deepEqual(verifyGatewayBundle(directory).blockers, []);
  const frames = readFrames(directory);
  assert.equal(frames[1]?.["dispatch_occurred"], false);
  assert.deepEqual((frames[0]?.["policy"] as { reason_codes: string[] }).reason_codes, [
    "workload_identity_refused",
  ]);
});

test("valid identity cannot override a denied model policy", async () => {
  const directory = join(mkdtempSync(join(tmpdir(), "gradia-policy-refuse-")), "bundle");
  let dispatches = 0;
  const gateway = makeGateway(directory, async () => {
    dispatches += 1;
    throw new Error("must not run");
  });
  const result = await gateway.dispatch({
    ...request,
    requestBody: Buffer.from(JSON.stringify({ model: "gpt-5.6-2026-09-01", input: "hello" })),
  });
  gateway.finalize();
  assert.equal(dispatches, 0);
  assert.equal(result.disposition, "blocked");
  assert.ok(result.identitySha256);
  const decision = readFrames(directory)[0] as { policy: { reason_codes: string[] } };
  assert.ok(decision.policy.reason_codes.includes("model_route_not_allowed"));
  assert.ok(decision.policy.reason_codes.some((reason) => reason.startsWith("workload_identity_sha256:")));
});

test("upstream transport failure stays distinct and finalizes evidence", async () => {
  const directory = join(mkdtempSync(join(tmpdir(), "gradia-transport-failure-")), "bundle");
  const gateway = makeGateway(directory, async () => {
    throw new Error("socket detail must not leak");
  });
  const result = await gateway.dispatch(request);
  gateway.finalize();
  assert.equal(result.disposition, "transport_failure");
  assert.equal(result.action?.failure_code, "upstream_transport_failure");
  assert.deepEqual(verifyGatewayBundle(directory).blockers, []);
  assert.doesNotMatch(readFileSync(join(directory, "frames.ndjson"), "utf8"), /socket detail/);
});

test("resolved-model substitution is recorded and withheld from the caller", async () => {
  const directory = join(mkdtempSync(join(tmpdir(), "gradia-identity-mismatch-")), "bundle");
  const gateway = makeGateway(directory, async () => ({
    responseBody: responseBody("gpt-5.6-2026-09-01"),
    responseMediaType: "application/json",
    httpStatus: 200,
  }));
  const result = await gateway.dispatch(request);
  gateway.finalize();
  assert.equal(result.disposition, "identity_mismatch");
  assert.equal(result.response, null);
  assert.equal(result.action?.outcome, "identity_mismatch");
  assert.ok(verifyGatewayBundle(directory).blockers.some((item) => item.includes("identity_mismatch_recorded")));
});
