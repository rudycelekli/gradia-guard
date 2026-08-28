import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { compareBundles, formatComparison } from "../src/compare.js";

const FIXTURES = join(process.cwd(), "test", "fixtures");

test("identical verified bundles compare exactly without claiming semantic equivalence", () => {
  const fixture = join(FIXTURES, "reference-bundle");
  const comparison = compareBundles(fixture, fixture);
  assert.equal(comparison.ok, true);
  assert.equal(comparison.exact_bundle_identity, true);
  assert.equal(comparison.same_schema, true);
  assert.equal(comparison.same_tier, true);
  assert.equal(comparison.semantic_equivalence_claimed, false);
  assert.equal(comparison.behavioral_regression_claim_eligible, false);
  assert.deepEqual(comparison.differences, []);
});

test("different verified tiers expose structural and coverage differences", () => {
  const comparison = compareBundles(
    join(FIXTURES, "reference-bundle"),
    join(FIXTURES, "gateway-reference-bundle"),
  );
  assert.equal(comparison.ok, true);
  assert.equal(comparison.exact_bundle_identity, false);
  assert.equal(comparison.same_schema, false);
  assert.equal(comparison.same_tier, false);
  assert.ok(comparison.differences.includes("schema_changed"));
  assert.ok(comparison.differences.includes("assurance_tier_changed"));
  assert.match(formatComparison(comparison), /Behavioral regression claim: not eligible/);
});

test("one tampered side refuses the comparison and contributes no coverage claims", () => {
  const right = mkdtempSync(join(tmpdir(), "gradia-guard-compare-"));
  cpSync(join(FIXTURES, "reference-bundle"), right, { recursive: true });
  const path = join(right, "bundle.json");
  const manifest = JSON.parse(readFileSync(path, "utf8")) as { chain_head_sha256: string };
  manifest.chain_head_sha256 = "f".repeat(64);
  writeFileSync(path, `${JSON.stringify(manifest)}\n`);

  const comparison = compareBundles(join(FIXTURES, "reference-bundle"), right);
  assert.equal(comparison.ok, false);
  assert.ok(comparison.blockers.includes("right:manifest_chain_head_mismatch"));
  assert.equal(comparison.right.tier, null);
  assert.deepEqual(comparison.observed_surfaces_added, []);
});
