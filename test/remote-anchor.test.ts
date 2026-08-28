import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { canonicalJson } from "../src/canonical.js";
import { verifyGuardRemoteAnchor } from "../src/remote-anchor.js";

const expectation = {
  guardEvidenceEditionId: "edition-01",
  projectId: "project-01",
  sessionId: "session-01",
  bundleSha256: "a".repeat(64),
  editionSha256: "b".repeat(64),
  retentionPolicyId: "retention-01",
  createdBy: "collector-01",
};

function signedAnchor(): Record<string, unknown> {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ format: "der", type: "spki" });
  const publicRaw = publicDer.subarray(publicDer.length - 32);
  const attestation = {
    schema_version: "gradia.guard.remote-anchor.v1",
    anchor_scope: "admitted_edition_and_retention_declaration",
    guard_evidence_edition_id: expectation.guardEvidenceEditionId,
    org_id: "org-01",
    project_id: expectation.projectId,
    session_id: expectation.sessionId,
    bundle_sha256: expectation.bundleSha256,
    edition_sha256: expectation.editionSha256,
    verification_sha256: "c".repeat(64),
    retention_policy_id: expectation.retentionPolicyId,
    retention_execution_proved: false,
    deletion_proved: false,
    storage_residency_proved: false,
    created_by: expectation.createdBy,
    created_at: "2026-08-26T20:00:00+00:00",
  };
  return {
    attestation,
    signature_ed25519: sign(null, Buffer.from(canonicalJson(attestation)), privateKey).toString(
      "hex",
    ),
    public_key_ed25519: publicRaw.toString("hex"),
    public_key_id: createHash("sha256").update(publicRaw).digest("hex").slice(0, 16),
  };
}

test("remote anchor verifies exact admission bindings with only the public key", () => {
  const anchor = signedAnchor();
  const result = verifyGuardRemoteAnchor(anchor, expectation);
  assert.equal(result.ok, true);
  assert.match(result.anchorSha256, /^[0-9a-f]{64}$/);
});

test("remote anchor refuses signed overclaim, substitution, and key pin mismatch", () => {
  const overclaim = signedAnchor();
  (overclaim["attestation"] as Record<string, unknown>)["retention_execution_proved"] = true;
  assert.throws(
    () => verifyGuardRemoteAnchor(overclaim, expectation),
    /guard_remote_anchor_retention_overclaim/,
  );

  const substituted = signedAnchor();
  (substituted["attestation"] as Record<string, unknown>)["bundle_sha256"] = "d".repeat(64);
  assert.throws(
    () => verifyGuardRemoteAnchor(substituted, expectation),
    /guard_remote_anchor_binding_mismatch:bundle_sha256/,
  );

  assert.throws(
    () => verifyGuardRemoteAnchor(signedAnchor(), { ...expectation, pinnedPublicKeyId: "0".repeat(16) }),
    /guard_remote_anchor_unpinned_key/,
  );

  const trusted = signedAnchor();
  assert.throws(
    () =>
      verifyGuardRemoteAnchor(signedAnchor(), {
        ...expectation,
        pinnedPublicKeyEd25519: trusted["public_key_ed25519"] as string,
      }),
    /guard_remote_anchor_unpinned_public_key/,
  );
});
