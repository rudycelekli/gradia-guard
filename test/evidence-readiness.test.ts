import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { digestCanonical } from "../src/canonical.js";
import {
  assessEvidenceReadiness,
  loadEvidenceProfile,
  sealEvidenceProfile,
  starterEvidenceProfileBody,
  verifyEvidenceProfile,
  type EvidenceProfileBody,
  type EvidenceReadinessReportBody,
} from "../src/evidence-readiness.js";

const processFixture = join(process.cwd(), "test/fixtures/reference-bundle");
const gatewayFixture = join(process.cwd(), "test/fixtures/gateway-reference-bundle");

test("starter profile is canonical, self-digested, and framework-text neutral", () => {
  const profile = sealEvidenceProfile(starterEvidenceProfileBody());
  verifyEvidenceProfile(profile);
  assert.equal(profile.schema_version, "gradia.guard.evidence-profile.v1");
  assert.equal(profile.source_bytes_sha256, null);
  assert.deepEqual(
    profile.requirements.map((item) => item.requirement_id),
    [...profile.requirements.map((item) => item.requirement_id)].sort(),
  );
  assert.equal(JSON.stringify(profile).includes("ISO/IEC"), false);
  assert.equal(JSON.stringify(profile).includes("NIST"), false);
});

test("process evidence becomes useful without satisfying model or governance gaps", () => {
  const report = assessEvidenceReadiness(processFixture, sealEvidenceProfile(starterEvidenceProfileBody()));
  assert.equal(report.bundle.verified, true);
  assert.equal(report.bundle.assurance_tier, "process");
  assert.equal(requirementStatus(report, "execution.process_lineage"), "evidence_ready");
  assert.equal(requirementStatus(report, "execution.model_lineage"), "missing");
  assert.equal(requirementStatus(report, "oversight.human_disposition"), "missing");
  assert.match(report.claim_boundary, /does not establish control effectiveness/);
  const { report_sha256: supplied, ...body } = report;
  assert.equal(supplied, digestCanonical(body satisfies EvidenceReadinessReportBody));
});

test("gateway evidence satisfies exact model lineage but not runtime isolation", () => {
  const report = assessEvidenceReadiness(gatewayFixture, sealEvidenceProfile(starterEvidenceProfileBody()));
  assert.equal(report.bundle.verified, true);
  assert.equal(report.bundle.assurance_tier, "gateway");
  assert.equal(requirementStatus(report, "execution.model_lineage"), "evidence_ready");
  assert.equal(requirementStatus(report, "execution.runtime_effects"), "missing");
  assert.equal(requirementStatus(report, "execution.world_evolution"), "missing");
});

test("tampered evidence makes every readiness judgment indeterminate", () => {
  const parent = mkdtempSync(join(tmpdir(), "gradia-readiness-tamper-"));
  const bundle = join(parent, "bundle");
  cpSync(gatewayFixture, bundle, { recursive: true });
  writeFileSync(join(bundle, "frames.ndjson"), `${readFileSync(join(bundle, "frames.ndjson"), "utf8")}{}\n`);
  const report = assessEvidenceReadiness(bundle, sealEvidenceProfile(starterEvidenceProfileBody()));
  assert.equal(report.bundle.verified, false);
  assert.equal(report.counts.indeterminate, report.requirements.length);
  assert.equal(report.counts.evidence_ready, 0);
  assert.ok(report.blockers.length > 0);
});

test("licensed control references remain opaque and source-byte bound", () => {
  const body = starterEvidenceProfileBody();
  const custom: EvidenceProfileBody = {
    ...body,
    profile_id: "customer-licensed-crosswalk",
    source_reference: "Customer-controlled licensed crosswalk edition 7",
    source_bytes_sha256: "a".repeat(64),
    requirements: body.requirements.map((item, index) =>
      index === 0 ? { ...item, external_control_refs: ["ISO-IEC-42001:licensed-ref-A"] } : item,
    ),
  };
  const profile = sealEvidenceProfile(custom);
  verifyEvidenceProfile(profile);
  assert.equal(profile.source_bytes_sha256, "a".repeat(64));
  assert.deepEqual(profile.requirements[0]?.external_control_refs, ["ISO-IEC-42001:licensed-ref-A"]);
});

test("profile mutation and unknown fields fail closed", () => {
  const directory = mkdtempSync(join(tmpdir(), "gradia-readiness-profile-"));
  const path = join(directory, "profile.json");
  const profile = sealEvidenceProfile(starterEvidenceProfileBody());
  writeFileSync(path, JSON.stringify({ ...profile, unexpected: true }));
  assert.throws(() => loadEvidenceProfile(path), /evidence_profile_fields_invalid/);
  writeFileSync(path, JSON.stringify({ ...profile, profile_version: "v2" }));
  assert.throws(() => loadEvidenceProfile(path), /evidence_profile_digest_mismatch/);
});

function requirementStatus(
  report: ReturnType<typeof assessEvidenceReadiness>,
  requirementId: string,
): string {
  const item = report.requirements.find((candidate) => candidate.requirement_id === requirementId);
  assert.ok(item, `missing requirement ${requirementId}`);
  return item.status;
}
