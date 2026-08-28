import type { CaptureTier, CoverageAttestation } from "./types.js";

const REQUIRED_SURFACES: Readonly<Record<CaptureTier, readonly string[]>> = {
  process: ["process.dispatch", "process.lifecycle", "process.stdio"],
  gateway: ["model.identity", "model.request", "model.response", "model.usage"],
  sdk: [
    "application.state_root.identity",
    "decision.identity",
    "decision.input",
    "decision.output",
    "policy.receipt",
    "tool.identity",
    "tool.request",
    "tool.result",
  ],
  runtime: ["process.lifecycle", "filesystem.effects", "network.effects", "credential.scopes"],
  universe: [
    "agent.projection",
    "auditor.projection",
    "world.root",
    "evolution.witness",
    "snapshot.restore",
  ],
};

const PROCESS_BLIND_SPOTS = [
  "agent.internal_state",
  "filesystem.effects",
  "model.request",
  "model.response",
  "network.effects",
  "tool.semantics",
  "world.root",
] as const;

const GATEWAY_BLIND_SPOTS = [
  "agent.internal_state",
  "calls.outside_recorder",
  "credential.values",
  "filesystem.effects",
  "network.effects",
  "tool.semantics",
  "world.root",
] as const;

const SDK_BLIND_SPOTS = [
  "agent.internal_state",
  "calls.outside_sdk",
  "credential.values",
  "filesystem.effects",
  "model.gateway_wire",
  "network.effects",
  "subprocess.lifecycle",
  "tool.unregistered_direct_io",
  "world.root",
] as const;

export function processCoverage(): CoverageAttestation {
  return {
    schema_version: "gradia.guard.coverage.v1",
    tier: "process",
    observed_surfaces: REQUIRED_SURFACES.process,
    unobserved_surfaces: PROCESS_BLIND_SPOTS,
    isolation_enforced: false,
    visibility_boundary_enforced: false,
    full_world_capture: false,
  };
}

export function gatewayCoverage(): CoverageAttestation {
  return {
    schema_version: "gradia.guard.coverage.v1",
    tier: "gateway",
    observed_surfaces: REQUIRED_SURFACES.gateway,
    unobserved_surfaces: GATEWAY_BLIND_SPOTS,
    isolation_enforced: false,
    visibility_boundary_enforced: false,
    full_world_capture: false,
  };
}

export function sdkCoverage(): CoverageAttestation {
  return {
    schema_version: "gradia.guard.coverage.v1",
    tier: "sdk",
    observed_surfaces: REQUIRED_SURFACES.sdk,
    unobserved_surfaces: SDK_BLIND_SPOTS,
    isolation_enforced: false,
    visibility_boundary_enforced: false,
    full_world_capture: false,
  };
}

export function requiredSurfaces(tier: CaptureTier): readonly string[] {
  return REQUIRED_SURFACES[tier];
}

export function coverageBlockers(value: CoverageAttestation): string[] {
  const blockers: string[] = [];
  if (value.schema_version !== "gradia.guard.coverage.v1") blockers.push("coverage_schema_invalid");
  if (!(value.tier in REQUIRED_SURFACES)) return [...blockers, "coverage_tier_invalid"];
  const observed = value.observed_surfaces;
  const unobserved = value.unobserved_surfaces;
  if (!isSortedUnique(observed)) blockers.push("coverage_observed_surfaces_not_canonical");
  if (!isSortedUnique(unobserved)) blockers.push("coverage_unobserved_surfaces_not_canonical");
  if (observed.some((surface) => unobserved.includes(surface))) blockers.push("coverage_surface_conflict");
  for (const surface of REQUIRED_SURFACES[value.tier]) {
    if (!observed.includes(surface)) blockers.push(`coverage_required_surface_missing:${surface}`);
  }
  if (value.tier !== "universe" && value.full_world_capture) {
    blockers.push("coverage_full_world_overclaim");
  }
  if (value.tier === "universe") {
    if (!value.isolation_enforced) blockers.push("coverage_universe_isolation_missing");
    if (!value.visibility_boundary_enforced) blockers.push("coverage_universe_visibility_missing");
    if (!value.full_world_capture) blockers.push("coverage_universe_world_capture_missing");
  }
  return blockers;
}

function isSortedUnique(values: readonly string[]): boolean {
  return values.every((value, index) =>
    index === 0 ? true : (values[index - 1] as string).localeCompare(value) < 0,
  );
}
