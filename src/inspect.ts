import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalJson } from "./canonical.js";
import type { CaptureTier, CoverageAttestation, VerificationResult } from "./types.js";
import { verifyBundle } from "./verify.js";

export const INSPECTION_SCHEMA_VERSION = "gradia.guard.inspection.v1" as const;

export interface GuardInspection {
  schema_version: typeof INSPECTION_SCHEMA_VERSION;
  ok: boolean;
  blockers: readonly string[];
  integrity: {
    session_id: string | null;
    frame_count: number;
    chain_head_sha256: string | null;
    payloads_checked: number;
    payloads_unavailable: number;
  };
  assurance: {
    tier: CaptureTier | null;
    claim_ceiling: string;
    isolation_enforced: boolean;
    visibility_boundary_enforced: boolean;
    full_world_capture: boolean;
  };
  observed_surfaces: readonly string[];
  unobserved_surfaces: readonly string[];
  useful_now: readonly string[];
  next_steps: readonly string[];
}

const CLAIM_CEILINGS: Readonly<Record<CaptureTier, string>> = {
  process:
    "process dispatch, lifecycle, and covered stdio byte identities only; no model, tool, file, network, or world-state claim",
  gateway:
    "model calls that crossed this explicit recorder only; calls around it and application/tool/world state remain unobserved",
  sdk:
    "application decisions and registered tools explicitly reported through this SDK only; direct or uninstrumented I/O remains unobserved",
  runtime:
    "the exact runtime surfaces named as observed under proved isolation; external systems and semantic truth remain outside the boundary",
  universe:
    "the frozen Universe, declared projections, world roots, witness chain, and snapshot/restore surfaces named as observed; undeclared external facts remain outside the boundary",
};

const USEFUL_NOW: Readonly<Record<CaptureTier, readonly string[]>> = {
  process: [
    "prove the exact command identity and lifecycle",
    "detect missing, reordered, truncated, or modified process evidence",
    "bind covered stdout and stderr by digest without retaining raw bytes by default",
  ],
  gateway: [
    "prove covered request and response byte identities",
    "bind requested and provider-resolved model identity, usage, retry lineage, and pre-dispatch policy",
    "separate policy, budget, provider, transport, protocol, and identity outcomes",
  ],
  sdk: [
    "prove explicitly reported decision and registered-tool input/output identities",
    "bind actor, principal, authority scope, policy, operation, retry, and parent lineage",
    "bind optional application-declared before and after state-root identities",
  ],
  runtime: [
    "prove the exact declared process, filesystem, network, and credential-scope coverage",
    "detect evidence loss or bypass inside the admitted isolation boundary",
    "carry runtime side-effect identities into managed evaluation and replay",
  ],
  universe: [
    "replay separate agent-visible and auditor-visible projections",
    "bind world evolution, interruptions, snapshot, fork, and restore lineage",
    "support proof-bound evaluation and counterfactual experiments over the frozen world",
  ],
};

const NEXT_STEPS: Readonly<Record<CaptureTier, readonly string[]>> = {
  process: [
    "add GatewayRecorder at every model dispatch boundary",
    "add SdkRecorder around application decisions and registered tools",
    "use a Gradia-controlled runtime when bypass resistance is required",
  ],
  gateway: [
    "add SdkRecorder for application decisions and tool effects",
    "deny direct provider egress before claiming bypass resistance",
    "use a Gradia-controlled runtime for file, process, network, and credential evidence",
  ],
  sdk: [
    "route model calls through GatewayRecorder or an enforcing Gradia gateway",
    "deny unregistered tool, network, filesystem, and subprocess paths",
    "use a Gradia-controlled runtime before making full-runtime claims",
  ],
  runtime: [
    "connect the runtime evidence to a frozen Gradia Universe",
    "bind separate agent and auditor projections plus evolution witnesses",
    "admit snapshot, fork, and restore evidence before counterfactual claims",
  ],
  universe: [
    "anchor the verified bundle in a managed Gradia project",
    "apply independent rights, evaluator, human-review, and release decisions",
    "run release comparison, Analytics+, and certification only from admitted evidence",
  ],
};

export function inspectBundle(directory: string): GuardInspection {
  const verification = verifyBundle(directory);
  if (!verification.ok) return refusedInspection(verification);

  let coverage: CoverageAttestation;
  try {
    const raw = JSON.parse(readFileSync(join(directory, "bundle.json"), "utf8")) as {
      coverage?: CoverageAttestation;
    };
    if (!raw.coverage) throw new Error("coverage_missing");
    coverage = raw.coverage;
  } catch {
    return refusedInspection({
      ...verification,
      ok: false,
      blockers: [...verification.blockers, "inspection_manifest_unreadable"],
    });
  }

  return {
    schema_version: INSPECTION_SCHEMA_VERSION,
    ok: true,
    blockers: [],
    integrity: integrityFrom(verification),
    assurance: {
      tier: coverage.tier,
      claim_ceiling: CLAIM_CEILINGS[coverage.tier],
      isolation_enforced: coverage.isolation_enforced,
      visibility_boundary_enforced: coverage.visibility_boundary_enforced,
      full_world_capture: coverage.full_world_capture,
    },
    observed_surfaces: coverage.observed_surfaces,
    unobserved_surfaces: coverage.unobserved_surfaces,
    useful_now: USEFUL_NOW[coverage.tier],
    next_steps: NEXT_STEPS[coverage.tier],
  };
}

function refusedInspection(verification: VerificationResult): GuardInspection {
  return {
    schema_version: INSPECTION_SCHEMA_VERSION,
    ok: false,
    blockers: verification.blockers,
    integrity: integrityFrom(verification),
    assurance: {
      tier: null,
      claim_ceiling: "none: bundle integrity did not verify",
      isolation_enforced: false,
      visibility_boundary_enforced: false,
      full_world_capture: false,
    },
    observed_surfaces: [],
    unobserved_surfaces: [],
    useful_now: [],
    next_steps: ["repair or reproduce the evidence bundle, then run inspection again"],
  };
}

function integrityFrom(verification: VerificationResult): GuardInspection["integrity"] {
  return {
    session_id: verification.session_id,
    frame_count: verification.frame_count,
    chain_head_sha256: verification.chain_head_sha256,
    payloads_checked: verification.payloads_checked,
    payloads_unavailable: verification.payloads_unavailable,
  };
}

export function canonicalInspection(inspection: GuardInspection): string {
  return `${canonicalJson(inspection)}\n`;
}

export function formatInspection(inspection: GuardInspection): string {
  const lines = [
    `Gradia Guard inspection: ${inspection.ok ? "VERIFIED" : "REFUSED"}`,
    `Assurance tier: ${inspection.assurance.tier ?? "none"}`,
    `Claim ceiling: ${inspection.assurance.claim_ceiling}`,
    `Frames: ${inspection.integrity.frame_count}`,
    `Chain head: ${inspection.integrity.chain_head_sha256 ?? "unavailable"}`,
  ];
  if (inspection.blockers.length > 0) {
    lines.push("", "Blockers:", ...inspection.blockers.map((item) => `  - ${item}`));
  }
  if (inspection.observed_surfaces.length > 0) {
    lines.push("", "Captured:", ...inspection.observed_surfaces.map((item) => `  + ${item}`));
  }
  if (inspection.unobserved_surfaces.length > 0) {
    lines.push("", "Still unobserved:", ...inspection.unobserved_surfaces.map((item) => `  - ${item}`));
  }
  if (inspection.useful_now.length > 0) {
    lines.push("", "Useful now:", ...inspection.useful_now.map((item) => `  + ${item}`));
  }
  lines.push("", "Next evidence door:", ...inspection.next_steps.map((item) => `  -> ${item}`));
  return `${lines.join("\n")}\n`;
}
