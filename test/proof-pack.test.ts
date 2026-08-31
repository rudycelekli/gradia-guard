import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { canonicalJson, digestCanonical } from "../src/canonical.js";
import { verifyProofPack, verifyProofPackDirectory } from "../src/proof-pack.js";

const fixture = join("test", "fixtures", "proof-pack-reference");

function loadFixture() {
  return {
    manifest: JSON.parse(readFileSync(join(fixture, "manifest.json"), "utf8")) as Record<string, unknown>,
    frames: readFileSync(join(fixture, "frames.ndjson"), "utf8")
      .trimEnd()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>),
  };
}

test("Proof Pack reference fixture independently reproduces every aggregate", () => {
  const result = verifyProofPackDirectory(fixture);
  assert.equal(result.ok, true, result.blockers.join(","));
  assert.equal(result.frame_count, 2);
  assert.equal(result.profile, "gradia-wind-tunnel-evidence-manifest.v1");
  assert.equal(result.frames_chain_head, "bcdd97369bd111f2d97898c3288c83388188bfa73d621df317306f0fe333530c");
  assert.deepEqual(result.aggregate_checks, {
    totals: true,
    density_by_rung: true,
    density_by_transform: true,
    density_by_benchmark: true,
    exploit_magnitude_hist: true,
  });
  assert.match(result.claim_boundary, /not_authorship_timestamp_rights/);
});

test("Proof Pack verifier refuses a self-consistent re-digested aggregate forgery", () => {
  const input = loadFixture();
  const totals = input.manifest["totals"] as Record<string, unknown>;
  totals["attempts"] = 99;
  input.manifest["manifest_sha256"] = digestCanonical(
    Object.fromEntries(Object.entries(input.manifest).filter(([key]) => key !== "manifest_sha256")),
  );
  const result = verifyProofPack(input);
  assert.equal(result.ok, false);
  assert.ok(result.blockers.includes("proof_pack_aggregate_mismatch:totals"));
  assert.ok(!result.blockers.includes("proof_pack_manifest_digest_mismatch"));
});

test("Proof Pack verifier refuses changed exploit semantics even after rehashing the chain", () => {
  const input = loadFixture();
  input.frames[0]!["is_exploit"] = true;
  let head = digestCanonical({ schema: "gradia-wind-tunnel-frames.v1" });
  for (const frame of input.frames) {
    const episode = Object.fromEntries(Object.entries(frame).filter(([key]) => key !== "frame_sha256"));
    head = digestCanonical({ prev: head, episode });
    frame["frame_sha256"] = head;
  }
  input.manifest["frames_chain_head"] = head;
  input.manifest["manifest_sha256"] = digestCanonical(
    Object.fromEntries(Object.entries(input.manifest).filter(([key]) => key !== "manifest_sha256")),
  );
  const result = verifyProofPack(input);
  assert.equal(result.ok, false);
  assert.ok(result.blockers.includes("proof_pack_exploit_semantics_invalid:0"));
});

test("Proof Pack CLI is account-free, canonical, and fail-closed", () => {
  const stdout = execFileSync(
    process.execPath,
    ["dist/src/cli.js", "proof-pack", "verify", fixture],
    { cwd: process.cwd(), encoding: "utf8", env: {} },
  );
  const verified = JSON.parse(stdout) as { ok: boolean; schema_version: string };
  assert.equal(verified.ok, true);
  assert.equal(verified.schema_version, "gradia.proof-pack.verification.v1");
  assert.equal(stdout, `${canonicalJson(verified)}\n`);

  const root = mkdtempSync(join(tmpdir(), "gradia-proof-pack-tampered-"));
  cpSync(fixture, root, { recursive: true });
  const manifest = JSON.parse(readFileSync(join(root, "manifest.json"), "utf8")) as Record<string, unknown>;
  (manifest["totals"] as Record<string, unknown>)["attempts"] = 99;
  manifest["manifest_sha256"] = digestCanonical(
    Object.fromEntries(Object.entries(manifest).filter(([key]) => key !== "manifest_sha256")),
  );
  writeFileSync(join(root, "manifest.json"), `${canonicalJson(manifest)}\n`);
  const refused = spawnSync(
    process.execPath,
    ["dist/src/cli.js", "proof-pack", "verify", root],
    { cwd: process.cwd(), encoding: "utf8", env: {} },
  );
  assert.equal(refused.status, 1, refused.stderr);
  assert.ok(JSON.parse(refused.stdout).blockers.includes("proof_pack_aggregate_mismatch:totals"));
});

test("reusable action emits bounded outputs and an honest verification summary", () => {
  const root = mkdtempSync(join(tmpdir(), "gradia-proof-pack-action-"));
  const output = join(root, "github-output");
  const summary = join(root, "step-summary");
  const executed = spawnSync(
    process.execPath,
    ["scripts/proof-pack-action.mjs", fixture],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: {
        ...process.env,
        GITHUB_OUTPUT: output,
        GITHUB_STEP_SUMMARY: summary,
      },
    },
  );

  assert.equal(executed.status, 0, executed.stderr);
  assert.match(executed.stdout, /"ok":true/);
  assert.equal(
    readFileSync(output, "utf8"),
    [
      "ok=true",
      "manifest_sha256=d024972479d9b72266ddd0ef7dbae96889a1481109ebfdded9b1b0a55a74114a",
      "frames_chain_head=bcdd97369bd111f2d97898c3288c83388188bfa73d621df317306f0fe333530c",
      "",
    ].join("\n"),
  );
  const markdown = readFileSync(summary, "utf8");
  assert.match(markdown, /\*\*Result:\*\* verified/);
  assert.match(markdown, /not_authorship_timestamp_rights_runtime_enforcement_or_scientific_validity/);
});
