import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  canonicalGuardCapabilityCatalog,
  digestCanonical,
  guardCapabilityCatalog,
  verifyGuardCapabilityCatalog,
  type GuardCapabilityCatalog,
} from "../src/index.js";

test("capability catalog keeps the local tier useful and the managed tier deployment-specific", () => {
  const catalog = guardCapabilityCatalog();
  verifyGuardCapabilityCatalog(catalog);

  assert.deepEqual(
    catalog.free_capabilities.map((item) => item.capability_id),
    [
      "free.process_run",
      "free.bundle_verify",
      "free.proof_pack_verify",
      "free.bundle_inspect",
      "free.bundle_compare",
      "free.actor_graph",
      "free.readiness_assessment",
      "free.policy_simulation",
      "free.provider_and_framework_adapters",
      "free.mcp_authorization_adapter",
      "free.portable_runtime_receipts",
      "free.enforcement_reference_receipts",
      "free.portable_anchor_verify",
    ],
  );
  assert.equal(
    catalog.free_capabilities.every(
      (item) => item.tier === "free_local" && item.access_boundary === "local_account_free",
    ),
    true,
  );
  assert.deepEqual(
    catalog.managed_capabilities.map((item) => item.capability_id),
    [
      "managed.authenticated_ingestion",
      "managed.proof_pack_verify",
      "managed.remote_anchor_issuance",
      "managed.retention_declaration",
      "managed.human_review",
      "managed.analytics_plus",
      "managed.regression_evaluation",
      "managed.certification",
      "managed.universe_composition",
    ],
  );
  assert.equal(
    catalog.managed_capabilities.every(
      (item) =>
        item.tier === "managed_service" &&
        item.access_boundary === "authenticated_deployment_specific",
    ),
    true,
  );
  assert.equal(canonicalGuardCapabilityCatalog(catalog), canonicalGuardCapabilityCatalog(guardCapabilityCatalog()));
});

test("commercial boundary makes payment assurance-neutral and preserves admission gates", () => {
  const catalog = guardCapabilityCatalog();
  assert.deepEqual(catalog.commercial_boundary, {
    payment_can_change_service_availability: true,
    payment_can_change_evidence_coverage: false,
    payment_can_change_claim_truth: false,
    payment_can_bypass_admission_gates: false,
    evidence_coverage_source:
      "explicit_observation_or_new_verified_receipts_never_plan_entitlement",
  });
  assert.ok(catalog.excluded_claims.includes("a_paid_plan_makes_an_unobserved_surface_observed"));
  assert.ok(
    catalog.excluded_claims.includes(
      "payment_or_catalog_presence_establishes_legal_compliance_or_certification",
    ),
  );
  assert.match(
    catalog.managed_capabilities.find(
      (item) => item.capability_id === "managed.retention_declaration",
    )?.assurance_rule ?? "",
    /not_deletion_residency_or_retention_execution_proof/,
  );
});

test("catalog verifier refuses payment overclaim even after the attacker recomputes its digest", () => {
  const mutated = clone(guardCapabilityCatalog());
  const mutable = mutated as unknown as {
    commercial_boundary: { payment_can_change_evidence_coverage: boolean };
    catalog_sha256: string;
  };
  mutable.commercial_boundary.payment_can_change_evidence_coverage = true;
  mutable.catalog_sha256 = bodyDigest(mutated);

  assert.throws(() => verifyGuardCapabilityCatalog(mutated), /guard_capability_catalog_mismatch/);
});

test("catalog verifier refuses managed claim inflation and unknown fields", () => {
  const inflated = clone(guardCapabilityCatalog());
  const capabilities = inflated.managed_capabilities as unknown as Array<{ assurance_rule: string }>;
  capabilities[0]!.assurance_rule = "payment_proves_complete_non_bypassable_coverage";
  (inflated as unknown as { catalog_sha256: string }).catalog_sha256 = bodyDigest(inflated);
  assert.throws(() => verifyGuardCapabilityCatalog(inflated), /guard_capability_catalog_mismatch/);

  const unknown = Object.assign(clone(guardCapabilityCatalog()), { paid_claims_are_true: true });
  assert.throws(() => verifyGuardCapabilityCatalog(unknown), /guard_capability_catalog_keys_invalid/);
});

test("catalog package boundary remains aligned with public beta package metadata", () => {
  const packageMetadata = JSON.parse(readFileSync("package.json", "utf8")) as {
    name: string;
    version: string;
    private: boolean;
    license: string;
  };
  const boundary = guardCapabilityCatalog().package_boundary;
  assert.equal(packageMetadata.name, boundary.package_name);
  assert.equal(packageMetadata.version, boundary.package_version);
  assert.equal(packageMetadata.private, boundary.private);
  assert.equal(packageMetadata.license, boundary.license);
  assert.equal(boundary.distribution_status, "public_beta");
  assert.equal(boundary.release_channel, "beta");
  assert.equal(boundary.registry_publication_proved_by_catalog, false);
});

test("capabilities CLI emits human and canonical machine-readable boundaries without an account", () => {
  const human = execFileSync(process.execPath, ["dist/src/cli.js", "capabilities"], {
    cwd: process.cwd(),
    encoding: "utf8",
  });
  assert.match(human, /capability catalog: VERIFIED STATIC BOUNDARIES/);
  assert.match(human, /Free local\/account-free capabilities \(13\)/);
  assert.match(human, /Managed deployment-specific capabilities \(9\)/);
  assert.match(human, /payment may change service availability, never evidence coverage/);

  const machine = JSON.parse(
    execFileSync(process.execPath, ["dist/src/cli.js", "capabilities", "--json"], {
      cwd: process.cwd(),
      encoding: "utf8",
    }),
  ) as GuardCapabilityCatalog;
  verifyGuardCapabilityCatalog(machine);
  assert.equal(machine.catalog_sha256, guardCapabilityCatalog().catalog_sha256);

  const refused = spawnSync(
    process.execPath,
    ["dist/src/cli.js", "capabilities", "--json", "--json"],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(refused.status, 2);
  assert.match(refused.stderr, /capabilities_option_invalid/);
});

function clone(catalog: GuardCapabilityCatalog): GuardCapabilityCatalog {
  return JSON.parse(JSON.stringify(catalog)) as GuardCapabilityCatalog;
}

function bodyDigest(catalog: GuardCapabilityCatalog): string {
  const { catalog_sha256: _old, ...body } = catalog;
  return digestCanonical(body);
}
