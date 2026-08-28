import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { digestCanonical } from "../src/canonical.js";
import {
  issueWorkloadIdentity,
  verifyWorkloadIdentity,
  type GuardWorkloadIdentity,
  type GuardWorkloadIdentityClaims,
  type VerifyWorkloadIdentityOptions,
} from "../src/workload-identity.js";

const issuerKeys = generateKeyPairSync("ed25519");
const foreignKeys = generateKeyPairSync("ed25519");
const now = 1_787_549_400;

function claims(): GuardWorkloadIdentityClaims {
  return {
    issuer_id: "gradia-managed",
    organization_id: "org-1",
    project_id: "project-1",
    workload_id: "agent-1",
    deployment_id: "deployment-1",
    audience: "guard-egress",
    policy_sha256: digestCanonical({ policy: "v1" }),
    image_sha256: digestCanonical({ image: "v1" }),
    configuration_sha256: digestCanonical({ configuration: "v1" }),
    collector_sha256: digestCanonical({ collector: "v1" }),
    authority_scope_ids: ["case.read", "decision.write"],
    issued_at_unix: now,
    not_before_unix: now,
    expires_at_unix: now + 300,
    nonce_sha256: digestCanonical({ nonce: "fixture-1" }),
  };
}

function options(source = claims()): VerifyWorkloadIdentityOptions {
  return {
    trustedPublicKeys: { "issuer-key-v1": issuerKeys.publicKey },
    expectation: {
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
      requiredAuthorityScopeIds: ["case.read"],
    },
    nowUnix: now + 1,
    maxLifetimeSeconds: 600,
  };
}

function clone(identity: GuardWorkloadIdentity): GuardWorkloadIdentity {
  return JSON.parse(JSON.stringify(identity)) as GuardWorkloadIdentity;
}

test("issuer-signed workload identity binds every deployment control", () => {
  const source = claims();
  const identity = issueWorkloadIdentity(source, "issuer-key-v1", issuerKeys.privateKey);
  const verified = verifyWorkloadIdentity(identity, options(source));
  assert.equal(verified.identitySha256, identity.identity_sha256);
  assert.equal(verified.keyId, "issuer-key-v1");
  assert.deepEqual(verified.claims, source);
});

test("claim or digest tampering fails even when shape remains valid", () => {
  const identity = issueWorkloadIdentity(claims(), "issuer-key-v1", issuerKeys.privateKey);
  const changedClaim = clone(identity);
  changedClaim.claims.workload_id = "agent-2";
  assert.throws(() => verifyWorkloadIdentity(changedClaim, options()), /digest_mismatch/);

  const changedDigest = clone(identity);
  changedDigest.identity_sha256 = digestCanonical({ replacement: true });
  assert.throws(() => verifyWorkloadIdentity(changedDigest, options()), /digest_mismatch/);
});

test("a re-signed foreign identity is still untrusted", () => {
  const identity = issueWorkloadIdentity(claims(), "foreign-key-v1", foreignKeys.privateKey);
  assert.throws(() => verifyWorkloadIdentity(identity, options()), /key_untrusted/);
});

test("expired, premature, and overlong identities fail closed", () => {
  const expired = claims();
  expired.issued_at_unix = now - 600;
  expired.not_before_unix = now - 600;
  expired.expires_at_unix = now;
  assert.throws(
    () => verifyWorkloadIdentity(issueWorkloadIdentity(expired, "issuer-key-v1", issuerKeys.privateKey), {
      ...options(expired),
      nowUnix: now,
    }),
    /expired/,
  );

  const premature = claims();
  premature.not_before_unix = now + 60;
  premature.expires_at_unix = now + 360;
  assert.throws(
    () => verifyWorkloadIdentity(issueWorkloadIdentity(premature, "issuer-key-v1", issuerKeys.privateKey), options(premature)),
    /not_yet_valid/,
  );

  const overlong = claims();
  overlong.expires_at_unix = now + 601;
  assert.throws(
    () => verifyWorkloadIdentity(issueWorkloadIdentity(overlong, "issuer-key-v1", issuerKeys.privateKey), options(overlong)),
    /lifetime_exceeded/,
  );
});

test("audience, policy, image, configuration, collector, and scope are exact", () => {
  const source = claims();
  const identity = issueWorkloadIdentity(source, "issuer-key-v1", issuerKeys.privateKey);
  for (const [field, value, error] of [
    ["audience", "different-audience", /audience_mismatch/],
    ["policySha256", digestCanonical({ policy: "v2" }), /policy_mismatch/],
    ["imageSha256", digestCanonical({ image: "v2" }), /image_mismatch/],
    ["configurationSha256", digestCanonical({ configuration: "v2" }), /configuration_mismatch/],
    ["collectorSha256", digestCanonical({ collector: "v2" }), /collector_mismatch/],
  ] as const) {
    const changed = options(source);
    Object.assign(changed.expectation, { [field]: value });
    assert.throws(() => verifyWorkloadIdentity(identity, changed), error);
  }

  const missingScope = options(source);
  missingScope.expectation.requiredAuthorityScopeIds = ["admin.write"];
  assert.throws(() => verifyWorkloadIdentity(identity, missingScope), /authority_scope_missing/);
});

test("scope ordering, duplicate scope, unknown fields, and invalid signatures refuse", () => {
  const unordered = claims();
  unordered.authority_scope_ids = ["decision.write", "case.read"];
  assert.throws(() => issueWorkloadIdentity(unordered, "issuer-key-v1", issuerKeys.privateKey), /not_canonical/);

  const duplicate = claims();
  duplicate.authority_scope_ids = ["case.read", "case.read"];
  assert.throws(() => issueWorkloadIdentity(duplicate, "issuer-key-v1", issuerKeys.privateKey), /not_canonical/);

  const identity = issueWorkloadIdentity(claims(), "issuer-key-v1", issuerKeys.privateKey);
  const unknown = { ...clone(identity), extra: true } as GuardWorkloadIdentity;
  assert.throws(() => verifyWorkloadIdentity(unknown, options()), /keys_invalid/);

  const signature = clone(identity);
  signature.signature_base64url = "x".repeat(86);
  assert.throws(() => verifyWorkloadIdentity(signature, options()), /digest_mismatch|signature_invalid/);
});

test("non-Ed25519 issuer keys are rejected", () => {
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  assert.throws(
    () => issueWorkloadIdentity(claims(), "issuer-key-v1", rsa.privateKey),
    /private_key_not_ed25519/,
  );
});
