import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalJson } from "./canonical.js";
import type { CaptureTier, CoverageAttestation, VerificationResult } from "./types.js";
import { verifyBundle } from "./verify.js";

export const COMPARISON_SCHEMA_VERSION = "gradia.guard.comparison.v1" as const;

interface ComparableManifest {
  schema_version: string;
  frame_count: number;
  chain_head_sha256: string;
  coverage: CoverageAttestation;
}

export interface GuardComparison {
  schema_version: typeof COMPARISON_SCHEMA_VERSION;
  ok: boolean;
  blockers: readonly string[];
  comparison_scope: "bundle_structure_and_digest_identity_only";
  semantic_equivalence_claimed: false;
  behavioral_regression_claim_eligible: false;
  left: {
    schema_version: string | null;
    tier: CaptureTier | null;
    frame_count: number;
    chain_head_sha256: string | null;
  };
  right: {
    schema_version: string | null;
    tier: CaptureTier | null;
    frame_count: number;
    chain_head_sha256: string | null;
  };
  exact_bundle_identity: boolean;
  same_schema: boolean;
  same_tier: boolean;
  observed_surfaces_added: readonly string[];
  observed_surfaces_removed: readonly string[];
  unobserved_surfaces_added: readonly string[];
  unobserved_surfaces_removed: readonly string[];
  differences: readonly string[];
}

export function compareBundles(leftDirectory: string, rightDirectory: string): GuardComparison {
  const leftVerification = verifyBundle(leftDirectory);
  const rightVerification = verifyBundle(rightDirectory);
  const blockers = [
    ...leftVerification.blockers.map((item) => `left:${item}`),
    ...rightVerification.blockers.map((item) => `right:${item}`),
  ].sort();
  if (!leftVerification.ok || !rightVerification.ok) {
    return refusedComparison(leftVerification, rightVerification, blockers);
  }

  let left: ComparableManifest;
  let right: ComparableManifest;
  try {
    left = readManifest(leftDirectory);
    right = readManifest(rightDirectory);
  } catch {
    return refusedComparison(leftVerification, rightVerification, ["comparison_manifest_unreadable"]);
  }

  const exactBundleIdentity =
    left.schema_version === right.schema_version && left.chain_head_sha256 === right.chain_head_sha256;
  const sameSchema = left.schema_version === right.schema_version;
  const sameTier = left.coverage.tier === right.coverage.tier;
  const observedAdded = difference(right.coverage.observed_surfaces, left.coverage.observed_surfaces);
  const observedRemoved = difference(left.coverage.observed_surfaces, right.coverage.observed_surfaces);
  const unobservedAdded = difference(right.coverage.unobserved_surfaces, left.coverage.unobserved_surfaces);
  const unobservedRemoved = difference(left.coverage.unobserved_surfaces, right.coverage.unobserved_surfaces);
  const differences: string[] = [];
  if (!sameSchema) differences.push("schema_changed");
  if (!sameTier) differences.push("assurance_tier_changed");
  if (left.frame_count !== right.frame_count) differences.push("frame_count_changed");
  if (left.chain_head_sha256 !== right.chain_head_sha256) differences.push("chain_head_changed");
  if (observedAdded.length > 0) differences.push("observed_surfaces_added");
  if (observedRemoved.length > 0) differences.push("observed_surfaces_removed");
  if (unobservedAdded.length > 0) differences.push("unobserved_surfaces_added");
  if (unobservedRemoved.length > 0) differences.push("unobserved_surfaces_removed");

  return {
    schema_version: COMPARISON_SCHEMA_VERSION,
    ok: true,
    blockers: [],
    comparison_scope: "bundle_structure_and_digest_identity_only",
    semantic_equivalence_claimed: false,
    behavioral_regression_claim_eligible: false,
    left: summary(left),
    right: summary(right),
    exact_bundle_identity: exactBundleIdentity,
    same_schema: sameSchema,
    same_tier: sameTier,
    observed_surfaces_added: observedAdded,
    observed_surfaces_removed: observedRemoved,
    unobserved_surfaces_added: unobservedAdded,
    unobserved_surfaces_removed: unobservedRemoved,
    differences,
  };
}

function readManifest(directory: string): ComparableManifest {
  return JSON.parse(readFileSync(join(directory, "bundle.json"), "utf8")) as ComparableManifest;
}

function difference(values: readonly string[], baseline: readonly string[]): string[] {
  return values.filter((value) => !baseline.includes(value)).sort();
}

function summary(manifest: ComparableManifest): GuardComparison["left"] {
  return {
    schema_version: manifest.schema_version,
    tier: manifest.coverage.tier,
    frame_count: manifest.frame_count,
    chain_head_sha256: manifest.chain_head_sha256,
  };
}

function refusedComparison(
  left: VerificationResult,
  right: VerificationResult,
  blockers: readonly string[],
): GuardComparison {
  return {
    schema_version: COMPARISON_SCHEMA_VERSION,
    ok: false,
    blockers,
    comparison_scope: "bundle_structure_and_digest_identity_only",
    semantic_equivalence_claimed: false,
    behavioral_regression_claim_eligible: false,
    left: verificationSummary(left),
    right: verificationSummary(right),
    exact_bundle_identity: false,
    same_schema: false,
    same_tier: false,
    observed_surfaces_added: [],
    observed_surfaces_removed: [],
    unobserved_surfaces_added: [],
    unobserved_surfaces_removed: [],
    differences: [],
  };
}

function verificationSummary(value: VerificationResult): GuardComparison["left"] {
  return {
    schema_version: null,
    tier: null,
    frame_count: value.frame_count,
    chain_head_sha256: value.chain_head_sha256,
  };
}

export function canonicalComparison(comparison: GuardComparison): string {
  return `${canonicalJson(comparison)}\n`;
}

export function formatComparison(comparison: GuardComparison): string {
  const lines = [
    `Gradia Guard comparison: ${comparison.ok ? "VERIFIED" : "REFUSED"}`,
    "Scope: bundle structure and digest identity only",
    "Behavioral regression claim: not eligible without an admitted evaluation contract",
  ];
  if (comparison.blockers.length > 0) {
    lines.push("", "Blockers:", ...comparison.blockers.map((item) => `  - ${item}`));
  } else {
    lines.push(
      "",
      `Left:  ${comparison.left.schema_version} · ${comparison.left.tier} · ${comparison.left.frame_count} frames`,
      `Right: ${comparison.right.schema_version} · ${comparison.right.tier} · ${comparison.right.frame_count} frames`,
      `Exact bundle identity: ${comparison.exact_bundle_identity ? "yes" : "no"}`,
      "",
      "Structural differences:",
      ...(comparison.differences.length > 0
        ? comparison.differences.map((item) => `  - ${item}`)
        : ["  + none"]),
    );
  }
  return `${lines.join("\n")}\n`;
}
