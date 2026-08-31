import { readFileSync } from "node:fs";
import {
  canonicalJson,
  digestCanonical,
  isSha256,
  isStrictCanonicalStringOrder,
} from "./canonical.js";
import { inspectBundle, type GuardInspection } from "./inspect.js";
import { assertStableId } from "./security.js";

export const EVIDENCE_PROFILE_SCHEMA_VERSION = "gradia.guard.evidence-profile.v1" as const;
export const EVIDENCE_READINESS_SCHEMA_VERSION = "gradia.guard.evidence-readiness.v1" as const;

export interface EvidenceRequirement {
  requirement_id: string;
  display_name: string;
  external_control_refs: readonly string[];
  required_surfaces: readonly string[];
  require_isolation_enforced: boolean;
  require_visibility_boundary_enforced: boolean;
  require_full_world_capture: boolean;
}

export interface EvidenceProfileBody {
  schema_version: typeof EVIDENCE_PROFILE_SCHEMA_VERSION;
  profile_id: string;
  profile_version: string;
  source_reference: string;
  source_bytes_sha256: string | null;
  requirements: readonly EvidenceRequirement[];
}

export interface EvidenceProfile extends EvidenceProfileBody {
  profile_sha256: string;
}

export type EvidenceReadinessStatus = "evidence_ready" | "partial" | "missing" | "indeterminate";

export interface EvidenceRequirementAssessment {
  requirement_id: string;
  display_name: string;
  external_control_refs: readonly string[];
  status: EvidenceReadinessStatus;
  observed_required_surfaces: readonly string[];
  missing_required_surfaces: readonly string[];
  unmet_boundary_requirements: readonly string[];
}

export interface EvidenceReadinessReportBody {
  schema_version: typeof EVIDENCE_READINESS_SCHEMA_VERSION;
  profile_id: string;
  profile_version: string;
  profile_sha256: string;
  source_reference: string;
  source_bytes_sha256: string | null;
  bundle: {
    verified: boolean;
    session_id: string | null;
    chain_head_sha256: string | null;
    assurance_tier: string | null;
  };
  counts: Record<EvidenceReadinessStatus, number>;
  requirements: readonly EvidenceRequirementAssessment[];
  blockers: readonly string[];
  claim_boundary: string;
}

export interface EvidenceReadinessReport extends EvidenceReadinessReportBody {
  report_sha256: string;
}

const CLAIM_BOUNDARY =
  "This report evaluates whether one verified Guard bundle contains the declared evidence surfaces. It does not establish control effectiveness, legal compliance, certification, or auditor acceptance.";

export function starterEvidenceProfileBody(): EvidenceProfileBody {
  return {
    schema_version: EVIDENCE_PROFILE_SCHEMA_VERSION,
    profile_id: "gradia-ai-governance-core",
    profile_version: "v1",
    source_reference: "Gradia original starter profile; replace or extend with licensed organization control references",
    source_bytes_sha256: null,
    requirements: [
      requirement(
        "assurance.release_regression",
        "Evidence-bound release comparison",
        ["evaluation.admission", "release.comparison"],
      ),
      requirement(
        "execution.decision_tool_authority",
        "Decision, tool, authority and policy lineage",
        ["decision.identity", "policy.receipt", "tool.identity", "tool.request", "tool.result"],
      ),
      requirement(
        "execution.model_lineage",
        "Covered model request, response, identity and usage",
        ["model.identity", "model.request", "model.response", "model.usage"],
      ),
      requirement(
        "execution.process_lineage",
        "Process dispatch, lifecycle and covered output identity",
        ["process.dispatch", "process.lifecycle", "process.stdio"],
      ),
      requirement(
        "execution.runtime_effects",
        "Isolated file, network and credential-scope evidence",
        ["credential.scopes", "filesystem.effects", "network.effects", "process.lifecycle"],
        true,
      ),
      requirement(
        "execution.world_evolution",
        "Controlled world, visibility and snapshot/restore evidence",
        ["agent.projection", "auditor.projection", "evolution.witness", "snapshot.restore", "world.root"],
        true,
        true,
        true,
      ),
      requirement(
        "governance.rights_retention",
        "Rights decision and retention execution evidence",
        ["retention.execution", "rights.decision"],
      ),
      requirement(
        "oversight.human_disposition",
        "Accountable human review or disposition",
        ["human.disposition"],
      ),
    ],
  };
}

export function sealEvidenceProfile(body: EvidenceProfileBody): EvidenceProfile {
  validateProfileBody(body);
  const cloned = JSON.parse(canonicalJson(body)) as EvidenceProfileBody;
  return { ...cloned, profile_sha256: digestCanonical(cloned) };
}

export function loadEvidenceProfile(path: string): EvidenceProfile {
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error("evidence_profile_invalid_json");
  }
  const profile = requireObject(value, "evidence_profile");
  assertExactKeys(
    profile,
    [
      "profile_id",
      "profile_sha256",
      "profile_version",
      "requirements",
      "schema_version",
      "source_bytes_sha256",
      "source_reference",
    ],
    "evidence_profile",
  );
  const body = {
    schema_version: profile["schema_version"],
    profile_id: profile["profile_id"],
    profile_version: profile["profile_version"],
    source_reference: profile["source_reference"],
    source_bytes_sha256: profile["source_bytes_sha256"],
    requirements: profile["requirements"],
  } as EvidenceProfileBody;
  validateProfileBody(body);
  const supplied = profile["profile_sha256"];
  if (!isSha256(supplied) || supplied !== digestCanonical(body)) {
    throw new Error("evidence_profile_digest_mismatch");
  }
  return { ...body, profile_sha256: supplied };
}

export function verifyEvidenceProfile(profile: EvidenceProfile): void {
  const body: EvidenceProfileBody = {
    schema_version: profile.schema_version,
    profile_id: profile.profile_id,
    profile_version: profile.profile_version,
    source_reference: profile.source_reference,
    source_bytes_sha256: profile.source_bytes_sha256,
    requirements: profile.requirements,
  };
  validateProfileBody(body);
  if (!isSha256(profile.profile_sha256)) throw new Error("evidence_profile_digest_invalid");
  if (profile.profile_sha256 !== digestCanonical(body)) {
    throw new Error("evidence_profile_digest_mismatch");
  }
}

export function assessEvidenceReadiness(
  bundleDirectory: string,
  profile: EvidenceProfile,
): EvidenceReadinessReport {
  verifyEvidenceProfile(profile);
  const inspection = inspectBundle(bundleDirectory);
  const requirements = profile.requirements.map((item) => assessRequirement(item, inspection));
  const counts: Record<EvidenceReadinessStatus, number> = {
    evidence_ready: 0,
    partial: 0,
    missing: 0,
    indeterminate: 0,
  };
  for (const item of requirements) counts[item.status] += 1;
  const body: EvidenceReadinessReportBody = {
    schema_version: EVIDENCE_READINESS_SCHEMA_VERSION,
    profile_id: profile.profile_id,
    profile_version: profile.profile_version,
    profile_sha256: profile.profile_sha256,
    source_reference: profile.source_reference,
    source_bytes_sha256: profile.source_bytes_sha256,
    bundle: {
      verified: inspection.ok,
      session_id: inspection.integrity.session_id,
      chain_head_sha256: inspection.integrity.chain_head_sha256,
      assurance_tier: inspection.assurance.tier,
    },
    counts,
    requirements,
    blockers: inspection.blockers,
    claim_boundary: CLAIM_BOUNDARY,
  };
  return { ...body, report_sha256: digestCanonical(body) };
}

export function canonicalEvidenceReadiness(report: EvidenceReadinessReport): string {
  return `${canonicalJson(report)}\n`;
}

export function formatEvidenceReadiness(report: EvidenceReadinessReport): string {
  const lines = [
    `Gradia Guard evidence readiness: ${report.bundle.verified ? "VERIFIED BUNDLE" : "INDETERMINATE"}`,
    `Profile: ${report.profile_id}@${report.profile_version}`,
    `Profile digest: ${report.profile_sha256}`,
    `Bundle tier: ${report.bundle.assurance_tier ?? "none"}`,
    `Evidence-ready: ${report.counts.evidence_ready}`,
    `Partial: ${report.counts.partial}`,
    `Missing: ${report.counts.missing}`,
    `Indeterminate: ${report.counts.indeterminate}`,
  ];
  for (const item of report.requirements) {
    lines.push("", `[${item.status}] ${item.requirement_id} — ${item.display_name}`);
    for (const surface of item.missing_required_surfaces) lines.push(`  - missing surface: ${surface}`);
    for (const boundary of item.unmet_boundary_requirements) lines.push(`  - unmet boundary: ${boundary}`);
  }
  if (report.blockers.length > 0) {
    lines.push("", "Bundle blockers:", ...report.blockers.map((item) => `  - ${item}`));
  }
  lines.push("", `Claim boundary: ${report.claim_boundary}`);
  return `${lines.join("\n")}\n`;
}

function requirement(
  requirementId: string,
  displayName: string,
  requiredSurfaces: readonly string[],
  requireIsolationEnforced = false,
  requireVisibilityBoundaryEnforced = false,
  requireFullWorldCapture = false,
): EvidenceRequirement {
  return {
    requirement_id: requirementId,
    display_name: displayName,
    external_control_refs: [],
    required_surfaces: [...requiredSurfaces].sort(),
    require_isolation_enforced: requireIsolationEnforced,
    require_visibility_boundary_enforced: requireVisibilityBoundaryEnforced,
    require_full_world_capture: requireFullWorldCapture,
  };
}

function assessRequirement(
  requirementValue: EvidenceRequirement,
  inspection: GuardInspection,
): EvidenceRequirementAssessment {
  if (!inspection.ok) {
    return {
      requirement_id: requirementValue.requirement_id,
      display_name: requirementValue.display_name,
      external_control_refs: requirementValue.external_control_refs,
      status: "indeterminate",
      observed_required_surfaces: [],
      missing_required_surfaces: requirementValue.required_surfaces,
      unmet_boundary_requirements: ["bundle_integrity_verified"],
    };
  }
  const observed = requirementValue.required_surfaces.filter((surface) =>
    inspection.observed_surfaces.includes(surface),
  );
  const missing = requirementValue.required_surfaces.filter(
    (surface) => !inspection.observed_surfaces.includes(surface),
  );
  const unmet: string[] = [];
  if (requirementValue.require_isolation_enforced && !inspection.assurance.isolation_enforced) {
    unmet.push("isolation_enforced");
  }
  if (
    requirementValue.require_visibility_boundary_enforced &&
    !inspection.assurance.visibility_boundary_enforced
  ) {
    unmet.push("visibility_boundary_enforced");
  }
  if (requirementValue.require_full_world_capture && !inspection.assurance.full_world_capture) {
    unmet.push("full_world_capture");
  }
  const status: EvidenceReadinessStatus =
    missing.length === 0 && unmet.length === 0
      ? "evidence_ready"
      : observed.length > 0
        ? "partial"
        : "missing";
  return {
    requirement_id: requirementValue.requirement_id,
    display_name: requirementValue.display_name,
    external_control_refs: requirementValue.external_control_refs,
    status,
    observed_required_surfaces: observed,
    missing_required_surfaces: missing,
    unmet_boundary_requirements: unmet,
  };
}

function validateProfileBody(body: EvidenceProfileBody): void {
  assertExactKeys(
    body as unknown as Record<string, unknown>,
    [
      "profile_id",
      "profile_version",
      "requirements",
      "schema_version",
      "source_bytes_sha256",
      "source_reference",
    ],
    "evidence_profile_body",
  );
  if (body.schema_version !== EVIDENCE_PROFILE_SCHEMA_VERSION) {
    throw new Error("evidence_profile_schema_unsupported");
  }
  assertStableId(body.profile_id, "evidence_profile_id");
  assertStableId(body.profile_version, "evidence_profile_version");
  assertDisplayText(body.source_reference, "evidence_profile_source_reference", 500);
  if (body.source_bytes_sha256 !== null && !isSha256(body.source_bytes_sha256)) {
    throw new Error("evidence_profile_source_digest_invalid");
  }
  if (!Array.isArray(body.requirements) || body.requirements.length === 0) {
    throw new Error("evidence_profile_requirements_empty");
  }
  if (body.requirements.length > 500) throw new Error("evidence_profile_requirements_too_many");
  const ids: string[] = [];
  for (const [index, item] of body.requirements.entries()) {
    validateRequirement(item, index);
    ids.push(item.requirement_id);
  }
  if (!isSortedUnique(ids)) throw new Error("evidence_profile_requirements_not_canonical");
}

function validateRequirement(value: EvidenceRequirement, index: number): void {
  const item = requireObject(value, `evidence_requirement:${index}`);
  assertExactKeys(
    item,
    [
      "display_name",
      "external_control_refs",
      "require_full_world_capture",
      "require_isolation_enforced",
      "require_visibility_boundary_enforced",
      "required_surfaces",
      "requirement_id",
    ],
    `evidence_requirement:${index}`,
  );
  assertStableId(value.requirement_id, `evidence_requirement_id:${index}`);
  assertDisplayText(value.display_name, `evidence_requirement_display_name:${index}`, 200);
  for (const [refIndex, reference] of value.external_control_refs.entries()) {
    assertStableId(reference, `evidence_requirement_external_ref:${index}:${refIndex}`);
  }
  if (!isSortedUnique(value.external_control_refs)) {
    throw new Error(`evidence_requirement_external_refs_not_canonical:${index}`);
  }
  if (value.required_surfaces.length === 0) {
    throw new Error(`evidence_requirement_surfaces_empty:${index}`);
  }
  for (const [surfaceIndex, surface] of value.required_surfaces.entries()) {
    assertStableId(surface, `evidence_requirement_surface:${index}:${surfaceIndex}`);
  }
  if (!isSortedUnique(value.required_surfaces)) {
    throw new Error(`evidence_requirement_surfaces_not_canonical:${index}`);
  }
  for (const [field, flag] of [
    ["require_isolation_enforced", value.require_isolation_enforced],
    ["require_visibility_boundary_enforced", value.require_visibility_boundary_enforced],
    ["require_full_world_capture", value.require_full_world_capture],
  ] as const) {
    if (typeof flag !== "boolean") throw new Error(`evidence_requirement_flag_invalid:${index}:${field}`);
  }
}

function assertDisplayText(value: unknown, field: string, maxLength: number): asserts value is string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maxLength ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new Error(`${field}_invalid`);
  }
}

function isSortedUnique(values: readonly string[]): boolean {
  return isStrictCanonicalStringOrder(values);
}

function requireObject(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label}_invalid`);
  }
  return value as Record<string, unknown>;
}

function assertExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((item, index) => item !== wanted[index])) {
    throw new Error(`${label}_fields_invalid`);
  }
}
