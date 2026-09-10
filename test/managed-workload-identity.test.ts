import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { AuthenticatedProviderGateway, canonicalJson, digestCanonical, issueWorkloadIdentity,
  ManagedWorkloadIdentityClient, sealPolicy, type GuardWorkloadIdentityClaims } from "../src/index.js";

const keys = generateKeyPairSync("ed25519"), stranger = generateKeyPairSync("ed25519");
const policy = sealPolicy({ schema_version: "gradia.guard.policy.v1", policy_id: "managed-test", policy_version: "1",
  default_decision: "blocked", tool_routes: [], model_routes: [{ provider: "openai", requested_model: "model-1",
    authority_scope_ids: ["model.invoke"], max_attempt_number: 1, max_request_bytes: 1000 }] });
function fixture() {
  let now = 1800000000, exchanges = 0, checks = 0, sources = 0;
  let refusal = false, forgery = false, wrongNonce = false, uncertain = false;
  const claims: GuardWorkloadIdentityClaims = { issuer_id: "gradia-operational-trust", organization_id: "a".repeat(32),
    project_id: "b".repeat(32), workload_id: "worker", deployment_id: "deployment", audience: "guard-gateway",
    policy_sha256: policy.policy_sha256, image_sha256: "2".repeat(64), configuration_sha256: "3".repeat(64),
    collector_sha256: "4".repeat(64), authority_scope_ids: ["model.invoke"], issued_at_unix: now,
    not_before_unix: now, expires_at_unix: now + 300, nonce_sha256: "5".repeat(64) };
  const expectation = { issuerId: claims.issuer_id, organizationId: claims.organization_id, projectId: claims.project_id,
    workloadId: claims.workload_id, deploymentId: claims.deployment_id, audience: claims.audience,
    policySha256: claims.policy_sha256, imageSha256: claims.image_sha256, configurationSha256: claims.configuration_sha256,
    collectorSha256: claims.collector_sha256, requiredAuthorityScopeIds: ["model.invoke"] };
  const requests: Record<string, unknown>[] = [];
  const client = new ManagedWorkloadIdentityClient({ apiBase: "https://guard.example.test", organizationId: claims.organization_id,
    projectId: claims.project_id, grantId: "ci", expectedTrustPolicySha256: "a".repeat(64), requestId: "first",
    expectation, trustedPublicKeys: { issuer: keys.publicKey }, sourceToken: async () => `fresh-source-${++sources}`,
    nowUnix: () => now, fetchImpl: async (url, options) => {
      const body = JSON.parse(String(options?.body)) as Record<string, unknown>; requests.push(body);
      assert.equal(options?.redirect, "error");
      if (String(url).endsWith("exchange")) {
        exchanges++;
        if (uncertain) throw new Error("uncertain transport outcome");
        return Response.json({ issuance_id: String(exchanges).padStart(32, "0"), policy_sha256: "a".repeat(64),
          identity: issueWorkloadIdentity({ ...claims, issued_at_unix: now, not_before_unix: now, expires_at_unix: now + 300,
            nonce_sha256: digestCanonical(exchanges) }, "issuer", keys.privateKey) });
      }
      checks++;
      if (refusal) return new Response("refused", { status: 403 });
      const attestation = { schema_version: "gradia.guard.current-workload-trust.v1", identity_sha256: body["identity_sha256"],
        request_nonce: wrongNonce ? "0".repeat(64) : body["request_nonce"], policy_sha256: "a".repeat(64),
        key_id: "issuer", checked_at_unix: now, expires_at_unix: now + 5,
        claim_boundary: "current_database_trust_check_not_dispatch_or_non_bypassability" };
      return Response.json({ attestation, signature_base64url: sign(null, Buffer.from(canonicalJson(attestation)),
        forgery ? stranger.privateKey : keys.privateKey).toString("base64url") });
    } });
  return { client, claims, expectation, requests, now: () => now, advance: () => { now += 275; },
    state: () => ({ exchanges, checks, sources }), refuse: () => { refusal = true; }, forge: () => { forgery = true; },
    wrongNonce: () => { wrongNonce = true; }, uncertain: () => { uncertain = true; } };
}

test("managed identities single-flight initial exchange, freshly check, and renew exact issuance", async () => {
  const f = fixture();
  const [first, same] = await Promise.all([f.client.identity(), f.client.identity()]);
  assert.deepEqual(first, same); assert.equal(f.state().exchanges, 1);
  await f.client.check(first);
  f.advance(); const renewed = await f.client.identity();
  assert.notEqual(renewed.identity_sha256, first.identity_sha256);
  assert.equal(f.requests.at(-1)?.["renewal_of"], "1".padStart(32, "0"));
  assert.equal(f.requests.at(-1)?.["source_token"], "fresh-source-2");
  await f.client.check(renewed);
  assert.deepEqual(f.state(), { exchanges: 2, checks: 2, sources: 2 });
});

test("managed status refuses substituted key and replayed nonce", async () => {
  for (const change of ["forge", "wrongNonce"] as const) {
    const f = fixture(); const identity = await f.client.identity(); f[change]();
    await assert.rejects(f.client.check(identity), /check_(binding|signature)_invalid/);
  }
});

test("ambiguous federation exchange is terminal and never automatically retries", async () => {
  const f = fixture(); f.uncertain();
  await assert.rejects(f.client.identity(), /no_retry/);
  await assert.rejects(f.client.identity(), /no_retry/);
  assert.equal(f.state().exchanges, 1);
});

test("revoked managed workload records a blocked provider attempt with zero dispatches", async () => {
  const f = fixture(); const identity = await f.client.identity(); f.refuse();
  const root = mkdtempSync(join(tmpdir(), "guard-managed-refusal-")); let dispatches = 0;
  try {
    const gateway = new AuthenticatedProviderGateway({ directory: join(root, "bundle"), policy, workloadIdentity: identity,
      managedIdentity: f.client, trustedPublicKeys: { issuer: keys.publicKey }, workloadExpectation: f.expectation,
      maxIdentityLifetimeSeconds: 300, nowUnix: f.now, upstreamDispatch: async () => { dispatches++; throw new Error("must not dispatch"); } });
    const result = await gateway.dispatch({ provider: "openai", requestBody: Buffer.from('{"model":"model-1","input":"private"}'),
      requestMediaType: "application/json", requestedModelFromRoute: null, logicalRequestId: "refused", attemptNumber: 1,
      retryOfOccurrenceSha256: null, authorityScopeIds: ["model.invoke"] });
    gateway.finalize();
    assert.equal(result.disposition, "blocked"); assert.equal(dispatches, 0); assert.equal(f.state().checks, 1);
  } finally { rmSync(root, { recursive: true }); }
});
