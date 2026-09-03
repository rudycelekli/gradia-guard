import { canonicalJson, digestCanonical, isSha256 } from "./canonical.js";

export const CAPABILITY_CATALOG_SCHEMA_VERSION =
  "gradia.guard.capability-catalog.v2" as const;
export const GUARD_PACKAGE_VERSION = "0.1.0-beta.6" as const;

export type GuardCapabilityTier = "free_local" | "managed_service";

export interface GuardCapability {
  capability_id: string;
  tier: GuardCapabilityTier;
  access_boundary: "local_account_free" | "authenticated_deployment_specific";
  implementation_references: readonly string[];
  value: readonly string[];
  assurance_rule: string;
}

export interface GuardCapabilityCatalogBody {
  schema_version: typeof CAPABILITY_CATALOG_SCHEMA_VERSION;
  package_boundary: {
    package_name: "@gradia/guard";
    package_version: typeof GUARD_PACKAGE_VERSION;
    private: false;
    license: "Apache-2.0";
    release_channel: "beta";
    distribution_status: "public_beta";
    registry_publication_proved_by_catalog: false;
  };
  commercial_boundary: {
    payment_can_change_service_availability: true;
    payment_can_change_evidence_coverage: false;
    payment_can_change_claim_truth: false;
    payment_can_bypass_admission_gates: false;
    evidence_coverage_source:
      "explicit_observation_or_new_verified_receipts_never_plan_entitlement";
  };
  free_capabilities: readonly GuardCapability[];
  managed_capabilities: readonly GuardCapability[];
  excluded_claims: readonly string[];
}

export interface GuardCapabilityCatalog extends GuardCapabilityCatalogBody {
  catalog_sha256: string;
}

/**
 * A source-bound product catalogue, not an entitlement response.
 *
 * The free section describes what this Apache-2.0 package can do locally
 * without an account. The managed section names repository-implemented API
 * surfaces whose availability remains deployment- and authorization-specific.
 * Neither section can promote evidence coverage: stronger claims require new,
 * verified observations or receipts rather than payment or catalogue text.
 */
export function guardCapabilityCatalog(): GuardCapabilityCatalog {
  const body: GuardCapabilityCatalogBody = {
    schema_version: CAPABILITY_CATALOG_SCHEMA_VERSION,
    package_boundary: {
      package_name: "@gradia/guard",
      package_version: GUARD_PACKAGE_VERSION,
      private: false,
      license: "Apache-2.0",
      release_channel: "beta",
      distribution_status: "public_beta",
      registry_publication_proved_by_catalog: false,
    },
    commercial_boundary: {
      payment_can_change_service_availability: true,
      payment_can_change_evidence_coverage: false,
      payment_can_change_claim_truth: false,
      payment_can_bypass_admission_gates: false,
      evidence_coverage_source:
        "explicit_observation_or_new_verified_receipts_never_plan_entitlement",
    },
    free_capabilities: [
      free(
        "free.process_run",
        ["CLI: run", "runGuardedProcess"],
        ["process dispatch and lifecycle receipts", "digest-only or encrypted local output spool"],
        "records_only_the_explicitly_wrapped_process_boundary_and_remains_bypassable",
      ),
      free(
        "free.bundle_verify",
        ["CLI: verify", "verifyBundle", "verifySdkBundle", "verifyGatewayBundle"],
        ["portable hash-chain integrity", "coverage and capture-boundary validation"],
        "verification_proves_bundle_integrity_and_declared_coverage_not_system_completeness",
      ),
      free(
        "free.proof_pack_verify",
        ["CLI: proof-pack verify", "verifyProofPack", "verifyProofPackDirectory"],
        ["portable research-frame integrity", "independent recomputation of declared aggregates"],
        "proof_pack_verification_proves_integrity_and_derivation_not_authorship_rights_or_scientific_validity",
      ),
      free(
        "free.bundle_inspect",
        ["CLI: inspect", "inspectBundle"],
        ["verified observed-surface inventory", "explicit assurance ceiling and next gap"],
        "inspection_derives_no_new_evidence_coverage",
      ),
      free(
        "free.bundle_compare",
        ["CLI: compare", "compareBundles"],
        ["verified structural and digest comparison", "coverage and frame-count deltas"],
        "structural_difference_is_not_behavioral_drift_or_regression",
      ),
      free(
        "free.actor_graph",
        ["CLI: actors", "analyzeSdkActorGraph"],
        ["payload-free declared actor topology", "parent execution state and declared-parent depth"],
        "labels_are_application_declared_and_parent_links_prove_no_delegation_or_causal_contribution",
      ),
      free(
        "free.readiness_assessment",
        ["CLI: readiness", "assessEvidenceReadiness"],
        ["organization-controlled evidence profile", "verified requirement-to-surface gap analysis"],
        "readiness_is_not_control_effectiveness_legal_compliance_or_auditor_acceptance",
      ),
      free(
        "free.policy_simulation",
        ["CLI: policy", "evaluateModelPolicy", "evaluateToolPolicy"],
        ["deny-by-default exact-route simulation", "scope byte attempt and identity checks"],
        "simulation_does_not_enforce_calls_that_bypass_the_policy_adapter",
      ),
      free(
        "free.provider_and_framework_adapters",
        [
          "AuthenticatedProviderGateway",
          "LocalHttpEgressDispatcher",
          "runProviderCredentiallessChild",
        ],
        ["exact-provider and pinned-framework adapters", "pre-dispatch policy and credentialless-child receipts"],
        "only_calls_proved_to_cross_an_explicit_adapter_are_observed_or_enforced",
      ),
      free(
        "free.mcp_authorization_adapter",
        [
          "AuthenticatedMcpToolAdapter",
          "AuthenticatedMcpHttpProxy",
          "AuthenticatedMcpStdioProxy",
          "McpHttpAccessRecorder.recover",
          "CLI: mcp-http verify/recover",
          "CLI: mcp-stdio verify/recover",
        ],
        [
          "exact registry tool and version authorization",
          "request response and refusal receipts",
          "durable HTTP and stdio pre-dispatch authorization evidence",
          "atomic interrupted-prefix finalization with HTTP v1 finalized-bundle compatibility",
        ],
        "mcp_calls_around_the_adapter_or_proxies_and_requests_not_durably_appended_remain_unobserved_and_unenforced;stdio_coverage_is_the_exact_spawned_child_and_stateless_tools_call_subset_only;recovery_does_not_prove_interruption_cause",
      ),
      free(
        "free.portable_runtime_receipts",
        ["DurableRuntimeEvidenceRecorder", "verifyRuntimeEvidenceBundle", "composeRuntimeEvidence"],
        ["file process network credential side-effect and terminal receipts", "crash-safe finalization and local replay"],
        "declared_runtime_receipts_prove_recorded_events_not_root_ownership_or_complete_host_capture",
      ),
      free(
        "free.enforcement_reference_receipts",
        ["collectDockerContainerEnforcement", "verifyKubernetesEnforcementReceipt"],
        ["measured container and Kubernetes boundary receipts", "finite bypass and workload-identity evidence"],
        "reference_receipts_cover_only_the_exact_measured_runtime_and_do_not_remove_operator_bypass",
      ),
      free(
        "free.portable_anchor_verify",
        ["CLI: anchor verify-guard", "CLI: anchor verify-universe", "verifyGuardRemoteAnchor", "verifyUniverseAnchor"],
        ["offline Ed25519 verification of issued managed anchors", "exact expectation binding"],
        "local_verification_does_not_issue_or_revoke_an_anchor",
      ),
    ],
    managed_capabilities: [
      managed(
        "managed.authenticated_ingestion",
        ["POST /v1/projects/{project_id}/guard/evidence-editions"],
        ["authenticated evidence ingestion", "server re-verification and immutable edition digest"],
        "ingestion_refuses_unverified_or_conflicting_bundles_and_does_not_expand_source_coverage",
      ),
      managed(
        "managed.proof_pack_verify",
        ["POST /v1/proof-packs/verify"],
        ["authenticated hosted profile verification", "structured blockers without artifact storage"],
        "hosted_verification_issues_no_anchor_rights_decision_retention_claim_or_scientific_judgment",
      ),
      managed(
        "managed.remote_anchor_issuance",
        ["Guard evidence edition remote_anchor response"],
        ["issuer-signed edition and retention-declaration anchor", "account-free offline verification"],
        "anchor_attests_to_the_admitted_edition_not_unobserved_execution",
      ),
      managed(
        "managed.retention_declaration",
        ["GuardEvidenceCreate.retention_policy_id", "GuardRemoteAnchor.retention_execution_proved=false"],
        ["retention-policy declaration bound to an edition"],
        "retention_declaration_is_not_deletion_residency_or_retention_execution_proof",
      ),
      managed(
        "managed.human_review",
        [
          "GET /v1/guard/evidence-editions/{edition_id}/dispositions",
          "POST /v1/guard/evidence-editions/{edition_id}/dispositions",
        ],
        ["role-gated append-only human use decisions", "decision-to-edition integrity binding"],
        "human_approval_cannot_repair_missing_coverage_or_failed_integrity",
      ),
      managed(
        "managed.analytics_plus",
        [
          "POST /v1/projects/{project_id}/analytics/measurement-contracts",
          "POST /v1/analytics/measurement-contracts/{contract_id}/findings",
          "POST /v1/analytics/findings/{finding_id}/reviews",
        ],
        ["frozen measurement contracts", "reviewed evidence-bound findings and packages"],
        "analytics_findings_require_their_declared_evidence_and_remain_separate_from_raw_observation",
      ),
      managed(
        "managed.regression_evaluation",
        ["GET /v1/comparisons", "GET /v1/drift", "POST /v1/runs/{run_id}/report"],
        ["admitted run comparison", "report-bound drift and regression analysis"],
        "regression_requires_a_frozen_evaluation_contract_not_merely_two_different_bundles",
      ),
      managed(
        "managed.certification",
        ["POST /v1/reports/{report_id}/certificate", "POST /v1/certificates/verify"],
        ["signed certificate over an eligible frozen report", "portable certificate verification"],
        "payment_never_mints_an_ineligible_certificate_or_strengthens_its_attested_claims",
      ),
      managed(
        "managed.universe_composition",
        [
          "POST /v1/universes/substrate-closures",
          "POST /v1/universes/multi-actor-executions/materialize",
          "verifyUniverseAnchor",
        ],
        ["world-state and visibility evidence composition", "multi-actor and Universe anchor binding"],
        "universe_claims_require_exact_world_projection_witness_and_restore_receipts",
      ),
    ],
    excluded_claims: [
      "a_paid_plan_makes_an_unobserved_surface_observed",
      "actor_parentage_proves_delegation_or_causal_contribution",
      "declared_retention_proves_deletion_residency_or_execution",
      "human_or_model_review_repairs_failed_evidence_integrity",
      "local_wrappers_prove_non_bypassable_host_or_cluster_enforcement",
      "payment_or_catalog_presence_establishes_legal_compliance_or_certification",
      "structural_bundle_difference_is_behavioral_drift_or_regression",
    ],
  };
  return { ...body, catalog_sha256: digestCanonical(body) };
}

export function verifyGuardCapabilityCatalog(value: unknown): asserts value is GuardCapabilityCatalog {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("guard_capability_catalog_shape_invalid");
  }
  const record = value as Record<string, unknown>;
  const expectedKeys = [
    "catalog_sha256",
    "commercial_boundary",
    "excluded_claims",
    "free_capabilities",
    "managed_capabilities",
    "package_boundary",
    "schema_version",
  ].sort();
  if (canonicalJson(Object.keys(record).sort()) !== canonicalJson(expectedKeys)) {
    throw new Error("guard_capability_catalog_keys_invalid");
  }
  if (record["schema_version"] !== CAPABILITY_CATALOG_SCHEMA_VERSION) {
    throw new Error("guard_capability_catalog_schema_unsupported");
  }
  if (!isSha256(record["catalog_sha256"])) {
    throw new Error("guard_capability_catalog_digest_invalid");
  }
  if (canonicalJson(value) !== canonicalJson(guardCapabilityCatalog())) {
    throw new Error("guard_capability_catalog_mismatch");
  }
}

export function canonicalGuardCapabilityCatalog(catalog: GuardCapabilityCatalog): string {
  verifyGuardCapabilityCatalog(catalog);
  return `${canonicalJson(catalog)}\n`;
}

export function formatGuardCapabilityCatalog(catalog: GuardCapabilityCatalog): string {
  verifyGuardCapabilityCatalog(catalog);
  const lines = [
    "Gradia Guard capability catalog: VERIFIED STATIC BOUNDARIES",
    `Package: ${catalog.package_boundary.package_name}@${catalog.package_boundary.package_version}`,
    "Distribution: Apache-2.0 public beta; registry presence is not proved by this catalog",
    "",
    `Free local/account-free capabilities (${catalog.free_capabilities.length}):`,
    ...catalog.free_capabilities.map((item) => `  - ${item.capability_id}: ${item.value.join("; ")}`),
    "",
    `Managed deployment-specific capabilities (${catalog.managed_capabilities.length}):`,
    ...catalog.managed_capabilities.map((item) => `  - ${item.capability_id}: ${item.value.join("; ")}`),
    "",
    "Commercial boundary: payment may change service availability, never evidence coverage,",
    "claim truth, or admission-gate outcomes. Stronger claims require new verified receipts.",
    `Catalog SHA-256: ${catalog.catalog_sha256}`,
  ];
  return `${lines.join("\n")}\n`;
}

function free(
  capabilityId: string,
  implementationReferences: readonly string[],
  value: readonly string[],
  assuranceRule: string,
): GuardCapability {
  return {
    capability_id: capabilityId,
    tier: "free_local",
    access_boundary: "local_account_free",
    implementation_references: implementationReferences,
    value,
    assurance_rule: assuranceRule,
  };
}

function managed(
  capabilityId: string,
  implementationReferences: readonly string[],
  value: readonly string[],
  assuranceRule: string,
): GuardCapability {
  return {
    capability_id: capabilityId,
    tier: "managed_service",
    access_boundary: "authenticated_deployment_specific",
    implementation_references: implementationReferences,
    value,
    assurance_rule: assuranceRule,
  };
}
