import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { formatInspection, inspectBundle } from "../src/inspect.js";

const FIXTURES = join(process.cwd(), "test", "fixtures");

test("inspection makes process evidence useful without strengthening its claim", () => {
  const inspection = inspectBundle(join(FIXTURES, "reference-bundle"));
  assert.equal(inspection.ok, true);
  assert.equal(inspection.assurance.tier, "process");
  assert.equal(inspection.assurance.isolation_enforced, false);
  assert.equal(inspection.assurance.full_world_capture, false);
  assert.ok(inspection.observed_surfaces.includes("process.lifecycle"));
  assert.ok(inspection.unobserved_surfaces.includes("model.request"));
  assert.match(inspection.assurance.claim_ceiling, /no model, tool, file, network, or world-state claim/);
  assert.match(formatInspection(inspection), /Next evidence door:/);
});

test("inspection distinguishes gateway and SDK evidence doors", () => {
  const gateway = inspectBundle(join(FIXTURES, "gateway-reference-bundle"));
  const sdk = inspectBundle(join(FIXTURES, "sdk-reference-bundle"));
  assert.equal(gateway.assurance.tier, "gateway");
  assert.ok(gateway.unobserved_surfaces.includes("calls.outside_recorder"));
  assert.match(gateway.next_steps.join(" "), /deny direct provider egress/);
  assert.equal(sdk.assurance.tier, "sdk");
  assert.ok(sdk.unobserved_surfaces.includes("calls.outside_sdk"));
  assert.match(sdk.next_steps.join(" "), /unregistered tool/);
});

test("inspection refuses to present coverage from a tampered bundle", () => {
  const directory = mkdtempSync(join(tmpdir(), "gradia-guard-inspect-"));
  cpSync(join(FIXTURES, "reference-bundle"), directory, { recursive: true });
  const path = join(directory, "bundle.json");
  const bundle = JSON.parse(readFileSync(path, "utf8")) as { chain_head_sha256: string };
  bundle.chain_head_sha256 = "0".repeat(64);
  writeFileSync(path, `${JSON.stringify(bundle)}\n`);

  const inspection = inspectBundle(directory);
  assert.equal(inspection.ok, false);
  assert.equal(inspection.assurance.tier, null);
  assert.deepEqual(inspection.observed_surfaces, []);
  assert.ok(inspection.blockers.includes("manifest_chain_head_mismatch"));
  assert.equal(inspection.assurance.claim_ceiling, "none: bundle integrity did not verify");
});
