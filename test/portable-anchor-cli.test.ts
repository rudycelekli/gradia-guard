import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { canonicalJson } from "../src/canonical.js";

const GUARD_EXPECTATION = {
  edition: "edition-01",
  project: "project-01",
  session: "session-01",
  bundleSha256: "a".repeat(64),
  editionSha256: "b".repeat(64),
  retentionPolicy: "retention-01",
  createdBy: "collector-01",
};

const UNIVERSE_EXPECTATION = {
  project: "project-01",
  run: "run-01",
  episode: "episode-01",
  task: "task-01",
  scenarioDigest: "d".repeat(64),
};

test("portable Guard anchor CLI requires a pinned key and exact independent bindings", () => {
  const directory = mkdtempSync(join(tmpdir(), "gradia-anchor-cli-"));
  const trusted = signingMaterial();
  const anchorPath = join(directory, "guard-anchor.json");
  writeFileSync(anchorPath, `${canonicalJson(guardAnchor(trusted))}\n`);

  const output = JSON.parse(
    execFileSync(process.execPath, ["dist/src/cli.js", "anchor", "verify-guard", ...guardArgs(anchorPath, trusted.publicKeyHex)], {
      cwd: process.cwd(),
      encoding: "utf8",
    }),
  ) as {
    ok: boolean;
    public_key_id: string;
    claim_boundary: string;
    trust_boundary: string;
  };
  assert.equal(output.ok, true);
  assert.equal(output.public_key_id, trusted.publicKeyId);
  assert.match(output.trust_boundary, /required_full_ed25519_public_key_pin/);
  assert.match(output.claim_boundary, /no_retention_execution_deletion_or_residency_claim/);

  const withoutPin = guardArgs(anchorPath, trusted.publicKeyHex);
  withoutPin.splice(withoutPin.indexOf("--public-key-ed25519"), 2);
  const refused = spawnSync(
    process.execPath,
    ["dist/src/cli.js", "anchor", "verify-guard", ...withoutPin],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(refused.status, 2);
  assert.match(refused.stderr, /anchor_option_required:--public-key-ed25519/);
  assert.equal(refused.stdout, "");
});

test("portable Guard anchor CLI refuses a substituted signer and signed retention overclaim", () => {
  const directory = mkdtempSync(join(tmpdir(), "gradia-anchor-cli-mutation-"));
  const trusted = signingMaterial();
  const foreign = signingMaterial();
  const foreignPath = join(directory, "foreign.json");
  writeFileSync(foreignPath, `${canonicalJson(guardAnchor(foreign))}\n`);
  const substitution = spawnSync(
    process.execPath,
    ["dist/src/cli.js", "anchor", "verify-guard", ...guardArgs(foreignPath, trusted.publicKeyHex)],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(substitution.status, 2);
  assert.match(substitution.stderr, /guard_remote_anchor_unpinned_public_key/);
  assert.equal(substitution.stdout, "");

  const overclaimPath = join(directory, "overclaim.json");
  writeFileSync(overclaimPath, `${canonicalJson(guardAnchor(trusted, true))}\n`);
  const overclaim = spawnSync(
    process.execPath,
    ["dist/src/cli.js", "anchor", "verify-guard", ...guardArgs(overclaimPath, trusted.publicKeyHex)],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(overclaim.status, 2);
  assert.match(overclaim.stderr, /guard_remote_anchor_retention_overclaim/);
  assert.equal(overclaim.stdout, "");
});

test("portable Universe anchor CLI reports only signed coverage and refuses overclaim", () => {
  const directory = mkdtempSync(join(tmpdir(), "gradia-universe-anchor-cli-"));
  const trusted = signingMaterial();
  const anchorPath = join(directory, "universe-anchor.json");
  writeFileSync(anchorPath, `${canonicalJson(universeAnchor(trusted))}\n`);

  const output = JSON.parse(
    execFileSync(
      process.execPath,
      ["dist/src/cli.js", "anchor", "verify-universe", ...universeArgs(anchorPath, trusted.publicKeyHex)],
      { cwd: process.cwd(), encoding: "utf8" },
    ),
  ) as {
    ok: boolean;
    coverage: Record<string, boolean>;
    claim_boundary: string;
  };
  assert.equal(output.ok, true);
  assert.deepEqual(output.coverage, {
    counterfactual_pair: false,
    evolution_witness: true,
    full_host_enforcement: false,
    snapshot_restore: true,
  });
  assert.match(output.claim_boundary, /no_counterfactual_pair_or_full_host_enforcement_claim/);

  const overclaimPath = join(directory, "universe-overclaim.json");
  writeFileSync(overclaimPath, `${canonicalJson(universeAnchor(trusted, true))}\n`);
  const refused = spawnSync(
    process.execPath,
    [
      "dist/src/cli.js",
      "anchor",
      "verify-universe",
      ...universeArgs(overclaimPath, trusted.publicKeyHex),
    ],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(refused.status, 2);
  assert.match(refused.stderr, /universe_anchor_coverage_overclaim/);
  assert.equal(refused.stdout, "");
});

interface SigningMaterial {
  privateKey: KeyObject;
  publicKeyHex: string;
  publicKeyId: string;
}

function signingMaterial(): SigningMaterial {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ format: "der", type: "spki" });
  const publicRaw = publicDer.subarray(publicDer.length - 32);
  return {
    privateKey,
    publicKeyHex: publicRaw.toString("hex"),
    publicKeyId: createHash("sha256").update(publicRaw).digest("hex").slice(0, 16),
  };
}

function guardAnchor(material: SigningMaterial, retentionOverclaim = false): Record<string, unknown> {
  const attestation = {
    schema_version: "gradia.guard.remote-anchor.v1",
    anchor_scope: "admitted_edition_and_retention_declaration",
    guard_evidence_edition_id: GUARD_EXPECTATION.edition,
    org_id: "org-01",
    project_id: GUARD_EXPECTATION.project,
    session_id: GUARD_EXPECTATION.session,
    bundle_sha256: GUARD_EXPECTATION.bundleSha256,
    edition_sha256: GUARD_EXPECTATION.editionSha256,
    verification_sha256: "c".repeat(64),
    retention_policy_id: GUARD_EXPECTATION.retentionPolicy,
    retention_execution_proved: retentionOverclaim,
    deletion_proved: false,
    storage_residency_proved: false,
    created_by: GUARD_EXPECTATION.createdBy,
    created_at: "2026-08-27T12:00:00+00:00",
  };
  return signed(material, attestation);
}

function universeAnchor(material: SigningMaterial, counterfactualOverclaim = false): Record<string, unknown> {
  const attestation = {
    schema_version: "gradia.guard.universe-anchor.v1",
    anchor_scope: "verified_durable_observatory_prefix",
    project_id: UNIVERSE_EXPECTATION.project,
    run_id: UNIVERSE_EXPECTATION.run,
    episode_id: UNIVERSE_EXPECTATION.episode,
    task_id: UNIVERSE_EXPECTATION.task,
    scenario_version_id: "scenario-version-01",
    scenario_digest: UNIVERSE_EXPECTATION.scenarioDigest,
    run_status: "completed",
    episode_status: "completed",
    completed_at: "2026-08-27T12:00:00+00:00",
    frame_count: 12,
    visible_frame_count: 10,
    event_frame_count: 1,
    restore_frame_count: 1,
    root_chain_head_sha256: "e".repeat(64),
    agent_chain_head_sha256: "f".repeat(64),
    terminal_world_root_sha256: "1".repeat(64),
    world_state_root_chain_verified: true,
    agent_projection_chain_verified: true,
    visibility_boundary_verified: true,
    evolution_witness_binding_verified: true,
    snapshot_restore_verified: true,
    counterfactual_pair_verified: counterfactualOverclaim,
    full_host_enforcement_proved: false,
    raw_payload_included: false,
    retention_execution_proved: false,
  };
  return signed(material, attestation);
}

function signed(material: SigningMaterial, attestation: Record<string, unknown>): Record<string, unknown> {
  return {
    attestation,
    signature_ed25519: sign(
      null,
      Buffer.from(canonicalJson(attestation)),
      material.privateKey,
    ).toString("hex"),
    public_key_ed25519: material.publicKeyHex,
    public_key_id: material.publicKeyId,
  };
}

function guardArgs(path: string, publicKeyEd25519: string): string[] {
  return [
    "--anchor",
    path,
    "--public-key-ed25519",
    publicKeyEd25519,
    "--edition",
    GUARD_EXPECTATION.edition,
    "--project",
    GUARD_EXPECTATION.project,
    "--session",
    GUARD_EXPECTATION.session,
    "--bundle-sha256",
    GUARD_EXPECTATION.bundleSha256,
    "--edition-sha256",
    GUARD_EXPECTATION.editionSha256,
    "--retention-policy",
    GUARD_EXPECTATION.retentionPolicy,
    "--created-by",
    GUARD_EXPECTATION.createdBy,
  ];
}

function universeArgs(path: string, publicKeyEd25519: string): string[] {
  return [
    "--anchor",
    path,
    "--public-key-ed25519",
    publicKeyEd25519,
    "--project",
    UNIVERSE_EXPECTATION.project,
    "--run",
    UNIVERSE_EXPECTATION.run,
    "--episode",
    UNIVERSE_EXPECTATION.episode,
    "--task",
    UNIVERSE_EXPECTATION.task,
    "--scenario-digest",
    UNIVERSE_EXPECTATION.scenarioDigest,
  ];
}
