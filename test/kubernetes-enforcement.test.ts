import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { digestCanonical } from "../src/canonical.js";
import { verifyKubernetesEnforcementReceipt } from "../src/kubernetes-enforcement.js";

const liveRoot = join(process.cwd(), "test/fixtures/kubernetes-enforcement/live");
const receiptPath = join(liveRoot, "kubernetes-enforcement.json");
const gatewayPath = join(liveRoot, "gateway-evidence");

function receipt(): Record<string, unknown> {
  return JSON.parse(readFileSync(receiptPath, "utf8")) as Record<string, unknown>;
}

function rehash(value: Record<string, unknown>): void {
  const { receipt_sha256: _old, ...body } = value;
  value["receipt_sha256"] = digestCanonical(body);
}

test("checked-in live Kubernetes receipt and gateway chain replay independently", () => {
  const verified = verifyKubernetesEnforcementReceipt(receipt(), gatewayPath);
  assert.equal(
    verified.receipt_sha256,
    "bb12a19c7190caba1d187e8d00881eacef4842dddce1488a776db459de387d6a",
  );
  assert.equal(
    verified.gateway_evidence.chain_head_sha256,
    "c95984bce33afae04a0d470579e973ae5113d78b5f54e25c10e20208de4b7d2f",
  );
  assert.equal(verified.restart.replacement_observed, true);
  assert.equal(verified.coverage.live_provider_behavior_proved, false);
  assert.equal(verified.coverage.exhaustive_bypass_resistance_proved, false);
});

test("Kubernetes CLI reproduces the offline verification and claim ceiling", () => {
  const output = JSON.parse(
    execFileSync(
      process.execPath,
      [
        "dist/src/cli.js",
        "runtime",
        "verify-kubernetes",
        "--receipt",
        receiptPath,
        "--gateway-evidence",
        gatewayPath,
      ],
      { cwd: process.cwd(), encoding: "utf8" },
    ),
  ) as {
    ok: boolean;
    receipt_sha256: string;
    coverage: Record<string, boolean>;
  };
  assert.equal(output.ok, true);
  assert.equal(
    output.receipt_sha256,
    "bb12a19c7190caba1d187e8d00881eacef4842dddce1488a776db459de387d6a",
  );
  assert.equal(output.coverage["full_host_enforcement"], false);
});

test("Kubernetes receipt refuses rehashed coverage and admission overclaims", () => {
  const coverage = receipt();
  (coverage["coverage"] as Record<string, unknown>)["live_provider_behavior_proved"] = true;
  rehash(coverage);
  assert.throws(
    () => verifyKubernetesEnforcementReceipt(coverage, gatewayPath),
    /kubernetes_coverage_overclaim/,
  );

  const admission = receipt();
  (admission["admission"] as Record<string, unknown>)[
    "agent_provider_credential_rejected_by_exact_policy"
  ] = false;
  rehash(admission);
  assert.throws(
    () => verifyKubernetesEnforcementReceipt(admission, gatewayPath),
    /kubernetes_admission_observation_invalid/,
  );
});

test("Kubernetes receipt refuses a substituted node image and projected identity", () => {
  const node = receipt();
  (node["cluster"] as Record<string, unknown>)["kind_node_image_sha256"] = "f".repeat(64);
  rehash(node);
  assert.throws(
    () => verifyKubernetesEnforcementReceipt(node, gatewayPath),
    /kubernetes_cluster_observation_invalid/,
  );

  const identity = receipt();
  const projected = identity["projected_identity"] as Record<string, unknown>;
  projected["expires_at_unix"] = (projected["expires_at_unix"] as number) + 1;
  projected["lifetime_seconds"] = 601;
  rehash(identity);
  assert.throws(
    () => verifyKubernetesEnforcementReceipt(identity, gatewayPath),
    /kubernetes_projected_identity_invalid/,
  );
});

test("Kubernetes receipt binds the gateway credential to the selected provider", () => {
  const value = receipt();
  (value["gateway"] as Record<string, unknown>)["provider_credential_names_present"] = [
    "ANTHROPIC_API_KEY",
  ];
  rehash(value);
  assert.throws(
    () => verifyKubernetesEnforcementReceipt(value, gatewayPath),
    /kubernetes_gateway_provider_credential_route_mismatch/,
  );
});
