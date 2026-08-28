import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync, type KeyLike } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { digestCanonical } from "../src/canonical.js";
import { verifyKubernetesIdentityExchangeReceipt } from "../src/kubernetes-identity-exchange.js";

const liveRoot = join(process.cwd(), "test/fixtures/kubernetes-identity-exchange/live");
const receiptPath = join(liveRoot, "kubernetes-identity-exchange.json");
const parentPath = join(liveRoot, "kubernetes-enforcement.json");
const gatewayPath = join(liveRoot, "gateway-evidence");
const publicKeyPath = join(liveRoot, "issuer-public-key.pem");
const brokerCaPath = join(liveRoot, "identity-broker-ca.pem");

function receipt(): Record<string, unknown> {
  return JSON.parse(readFileSync(receiptPath, "utf8")) as Record<string, unknown>;
}

function parent(): unknown {
  return JSON.parse(readFileSync(parentPath, "utf8")) as unknown;
}

function options(publicKey: KeyLike = readFileSync(publicKeyPath)) {
  return {
    parentReceipt: parent(),
    gatewayEvidenceDirectory: gatewayPath,
    trustedIssuerPublicKey: publicKey,
    trustedBrokerTlsCa: readFileSync(brokerCaPath),
  };
}

function rehash(value: Record<string, unknown>): void {
  const { receipt_sha256: _old, ...body } = value;
  value["receipt_sha256"] = digestCanonical(body);
}

test("checked-in Kubernetes TokenReview exchange replays under the independent public key", () => {
  const verified = verifyKubernetesIdentityExchangeReceipt(receipt(), options());
  assert.equal(
    verified.receipt_sha256,
    "4d01d6b8e405bfc937b0b51dd918521a47e5b33d0d93f81512a2909d2df3fa5b",
  );
  assert.equal(
    verified.parent_kubernetes_enforcement_receipt_sha256,
    "c2f7ae42d729c636334d49359315e3c425c42632db312a7c58f64af62f6e53de",
  );
  assert.equal(verified.token_review.authenticated, true);
  assert.equal(verified.broker.replay_rejections, 1);
  assert.equal(verified.coverage.cloud_workload_identity_federation_proved, false);
});

test("Kubernetes identity CLI reproduces the exchange and its claim ceiling", () => {
  const output = JSON.parse(execFileSync(process.execPath, [
    "dist/src/cli.js",
    "runtime",
    "verify-kubernetes-identity",
    "--receipt",
    receiptPath,
    "--kubernetes-receipt",
    parentPath,
    "--gateway-evidence",
    gatewayPath,
    "--issuer-public-key",
    publicKeyPath,
    "--broker-ca",
    brokerCaPath,
  ], { cwd: process.cwd(), encoding: "utf8" })) as {
    ok: boolean;
    receipt_sha256: string;
    coverage: Record<string, boolean>;
  };
  assert.equal(output.ok, true);
  assert.equal(
    output.receipt_sha256,
    "4d01d6b8e405bfc937b0b51dd918521a47e5b33d0d93f81512a2909d2df3fa5b",
  );
  assert.equal(output.coverage["managed_gradia_identity_service_proved"], false);
});

test("rehashing cannot turn unauthenticated review or cloud federation into proof", () => {
  const unauthenticated = receipt();
  (unauthenticated["token_review"] as Record<string, unknown>)["authenticated"] = false;
  rehash(unauthenticated);
  assert.throws(
    () => verifyKubernetesIdentityExchangeReceipt(unauthenticated, options()),
    /kubernetes_token_review_observation_invalid/,
  );

  const overclaim = receipt();
  (overclaim["coverage"] as Record<string, unknown>)[
    "cloud_workload_identity_federation_proved"
  ] = true;
  rehash(overclaim);
  assert.throws(
    () => verifyKubernetesIdentityExchangeReceipt(overclaim, options()),
    /kubernetes_identity_exchange_coverage_overclaim/,
  );
});

test("audience, Pod UID, credential ID, and signed nonce remain one binding", () => {
  for (const field of [
    "credential_id_sha256",
    "pod_uid_sha256",
    "user_uid_sha256",
  ]) {
    const changed = receipt();
    (changed["token_review"] as Record<string, unknown>)[field] = "f".repeat(64);
    rehash(changed);
    assert.throws(
      () => verifyKubernetesIdentityExchangeReceipt(changed, options()),
      /kubernetes_identity_exchange_signed_binding_invalid/,
    );
  }

  const audience = receipt();
  (audience["token_review"] as Record<string, unknown>)["returned_audiences"] = [
    "https://kubernetes.default.svc.cluster.local",
  ];
  rehash(audience);
  assert.throws(
    () => verifyKubernetesIdentityExchangeReceipt(audience, options()),
    /kubernetes_token_review_observation_invalid/,
  );

  const collector = receipt();
  ((collector["guard_workload_identity"] as Record<string, unknown>)[
    "claims"
  ] as Record<string, unknown>)["collector_sha256"] = "f".repeat(64);
  rehash(collector);
  assert.throws(
    () => verifyKubernetesIdentityExchangeReceipt(collector, options()),
    /guard_workload_identity_digest_mismatch|signature_invalid|kubernetes_identity_exchange_signed_binding_invalid/,
  );
});

test("a substituted issuer and an expanded TokenReview role are refused", () => {
  const foreign = generateKeyPairSync("ed25519").publicKey;
  assert.throws(
    () => verifyKubernetesIdentityExchangeReceipt(receipt(), options(foreign)),
    /kubernetes_identity_broker_observation_invalid|signature_invalid/,
  );

  assert.throws(
    () => verifyKubernetesIdentityExchangeReceipt(receipt(), {
      ...options(),
      trustedBrokerTlsCa: Buffer.from("not-the-pinned-broker-ca"),
    }),
    /kubernetes_identity_broker_observation_invalid/,
  );

  const role = receipt();
  (role["broker"] as Record<string, unknown>)["cluster_role_rules_sha256"] =
    digestCanonical([{
      apiGroups: ["authentication.k8s.io"],
      resources: ["tokenreviews"],
      verbs: ["create", "get"],
    }]);
  rehash(role);
  assert.throws(
    () => verifyKubernetesIdentityExchangeReceipt(role, options()),
    /kubernetes_identity_broker_observation_invalid/,
  );
});

test("the public replay fixture contains no private key, raw token, or provider credential", () => {
  const paths = [
    receiptPath,
    parentPath,
    publicKeyPath,
    brokerCaPath,
    ...readdirSync(gatewayPath).map((name) => join(gatewayPath, name)),
  ];
  const text = paths.map((path) => readFileSync(path, "utf8")).join("\n");
  for (const forbidden of [
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "fixture-parent-only-provider-value",
    "projected_service_account_token",
    "reviewer.jwt",
    "identity.jwt",
  ]) {
    assert.equal(text.includes(forbidden), false, forbidden);
  }
});
