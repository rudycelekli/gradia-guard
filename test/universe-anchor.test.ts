import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { canonicalJson } from "../src/canonical.js";
import { verifyUniverseAnchor } from "../src/universe-anchor.js";

const expected = {
  projectId: "project-01",
  runId: "run-01",
  episodeId: "episode-01",
  taskId: "task-01",
  scenarioDigest: "a".repeat(64),
};

function signedAnchor(eventCount = 1, restoreCount = 1): Record<string, unknown> {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ format: "der", type: "spki" });
  const publicRaw = publicDer.subarray(publicDer.length - 32);
  const attestation = {
    schema_version: "gradia.guard.universe-anchor.v1",
    anchor_scope: "verified_durable_observatory_prefix",
    project_id: expected.projectId,
    run_id: expected.runId,
    episode_id: expected.episodeId,
    task_id: expected.taskId,
    scenario_version_id: "scenario-version-01",
    scenario_digest: expected.scenarioDigest,
    run_status: "completed",
    episode_status: "completed",
    completed_at: "2026-08-26T22:00:00+00:00",
    frame_count: 12,
    visible_frame_count: 10,
    event_frame_count: eventCount,
    restore_frame_count: restoreCount,
    root_chain_head_sha256: "b".repeat(64),
    agent_chain_head_sha256: "c".repeat(64),
    terminal_world_root_sha256: "d".repeat(64),
    world_state_root_chain_verified: true,
    agent_projection_chain_verified: true,
    visibility_boundary_verified: true,
    evolution_witness_binding_verified: eventCount > 0,
    snapshot_restore_verified: restoreCount > 0,
    counterfactual_pair_verified: false,
    full_host_enforcement_proved: false,
    raw_payload_included: false,
    retention_execution_proved: false,
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

test("Universe anchor verifies world, projection, witness and restore coverage offline", () => {
  const result = verifyUniverseAnchor(signedAnchor(), expected);
  assert.equal(result.ok, true);
  assert.deepEqual(result.coverage, {
    evolutionWitness: true,
    snapshotRestore: true,
    counterfactualPair: false,
    fullHostEnforcement: false,
  });
});

test("Universe anchor refuses overclaim, count drift, identity substitution and foreign key", () => {
  const overclaim = signedAnchor();
  (overclaim["attestation"] as Record<string, unknown>)["counterfactual_pair_verified"] = true;
  assert.throws(() => verifyUniverseAnchor(overclaim, expected), /universe_anchor_coverage_overclaim/);

  const counts = signedAnchor();
  (counts["attestation"] as Record<string, unknown>)["event_frame_count"] = 13;
  assert.throws(() => verifyUniverseAnchor(counts, expected), /universe_anchor_count_invalid/);

  assert.throws(
    () => verifyUniverseAnchor(signedAnchor(), { ...expected, runId: "run-02" }),
    /universe_anchor_binding_mismatch:run_id/,
  );
  assert.throws(
    () => verifyUniverseAnchor(signedAnchor(), { ...expected, pinnedPublicKeyId: "0".repeat(16) }),
    /universe_anchor_unpinned_key/,
  );

  const trusted = signedAnchor();
  assert.throws(
    () =>
      verifyUniverseAnchor(signedAnchor(), {
        ...expected,
        pinnedPublicKeyEd25519: trusted["public_key_ed25519"] as string,
      }),
    /universe_anchor_unpinned_public_key/,
  );
});
