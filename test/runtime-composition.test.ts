import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  composeRuntimeEvidence,
  digestCanonical,
  DurableRuntimeEvidenceRecorder,
  issueWorkloadIdentity,
  runProviderCredentiallessChild,
  sealHttpEgressConfiguration,
  sealPolicy,
  sha256,
  verifyRuntimeCompositionReceipt,
  type ContainerEnforcementReceiptBody,
  type ContainerSecurityPosture,
  type GuardWorkloadIdentityClaims,
  type RuntimeEvidenceBundle,
} from "../src/index.js";

const runtimeId = "composition-runtime-01";
const now = 1_787_549_400;
const observedAt = "2026-08-27T14:00:00.000Z";
const model = "gpt-5.6-2026-08-01";
const targetUrl = "https://api.openai.example/v1/responses";

async function credentiallessRun() {
  const keys = generateKeyPairSync("ed25519");
  const policy = sealPolicy({
    schema_version: "gradia.guard.policy.v1",
    policy_id: "composition-policy",
    policy_version: "v1",
    default_decision: "blocked",
    model_routes: [
      {
        provider: "openai",
        requested_model: model,
        authority_scope_ids: ["model.invoke"],
        max_request_bytes: 10_000,
        max_attempt_number: 1,
      },
    ],
    tool_routes: [],
  });
  const configuration = sealHttpEgressConfiguration({
    schema_version: "gradia.guard.local-http-egress-configuration.v1",
    configuration_id: "composition-egress",
    configuration_version: "v1",
    default_decision: "blocked",
    model_routes: [
      {
        provider: "openai",
        target_url: targetUrl,
        method: "POST",
        request_media_type: "application/json",
        redirect_mode: "error",
        timeout_ms: 5_000,
        max_response_bytes: 100_000,
      },
    ],
  });
  const claims: GuardWorkloadIdentityClaims = {
    issuer_id: "gradia-managed",
    organization_id: "org-1",
    project_id: "project-1",
    workload_id: "composition-agent-1",
    deployment_id: "deployment-1",
    audience: "guard-runtime",
    policy_sha256: policy.policy_sha256,
    image_sha256: digestCanonical({ image: "v1" }),
    configuration_sha256: configuration.configuration_sha256,
    collector_sha256: digestCanonical({ collector: "v1" }),
    authority_scope_ids: ["model.invoke"],
    issued_at_unix: now,
    not_before_unix: now,
    expires_at_unix: now + 300,
    nonce_sha256: digestCanonical({ nonce: "composition" }),
  };
  const identity = issueWorkloadIdentity(claims, "issuer-key-v1", keys.privateKey);
  const run = await runProviderCredentiallessChild({
    directory: join(mkdtempSync(join(tmpdir(), "gradia-composition-")), "credentialless"),
    runtimeId,
    command: [
      process.execPath,
      join(process.cwd(), "test/fixtures/credentialless-child.mjs"),
      "success",
    ],
    cwd: process.cwd(),
    policy,
    configuration,
    workloadIdentity: identity,
    trustedPublicKeys: { "issuer-key-v1": keys.publicKey },
    workloadExpectation: {
      issuerId: claims.issuer_id,
      organizationId: claims.organization_id,
      projectId: claims.project_id,
      workloadId: claims.workload_id,
      deploymentId: claims.deployment_id,
      audience: claims.audience,
      policySha256: claims.policy_sha256,
      imageSha256: claims.image_sha256,
      configurationSha256: claims.configuration_sha256,
      collectorSha256: claims.collector_sha256,
    },
    maxIdentityLifetimeSeconds: 600,
    nowUnix: () => now + 1,
    transport: async () => ({
      responseBody: Buffer.from(
        JSON.stringify({
          id: "response-1",
          model,
          usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 },
          output: [],
        }),
      ),
      responseMediaType: "application/json",
      httpStatus: 200,
      finalUrl: targetUrl,
      redirected: false,
    }),
  });
  assert.equal(run.verification.ok, true);
  return { run, policy, configuration, identity };
}

function posture(networks: readonly string[], credentials: readonly string[] = []): ContainerSecurityPosture {
  return {
    container_id_sha256: "1".repeat(64),
    image_id_sha256: "2".repeat(64),
    configured_image_sha256: "3".repeat(64),
    user: "65532:65532",
    non_root_user: true,
    read_only_rootfs: true,
    privileged: false,
    cap_drop_all: true,
    no_new_privileges: true,
    host_network: false,
    host_pid: false,
    docker_socket_mounted: false,
    provider_credential_names_present: credentials,
    network_id_sha256s: networks,
  };
}

function containerReceipt(
  policySha256: string,
  configurationSha256: string,
  workloadIdentitySha256: string,
) {
  const internal = "4".repeat(64);
  const body: ContainerEnforcementReceiptBody = {
    schema_version: "gradia.guard.container-enforcement-receipt.v1",
    runtime_id: runtimeId,
    observed_at: observedAt,
    orchestrator: "docker",
    collector_authority: "docker_daemon_inspection_and_root_launched_probes",
    policy_sha256: policySha256,
    configuration_sha256: configurationSha256,
    workload_identity_sha256: workloadIdentitySha256,
    agent: posture([internal]),
    gateway: posture([internal, "8".repeat(64)], ["OPENAI_API_KEY"]),
    network: {
      internal_network_id_sha256: internal,
      internal_network_flag: true,
      agent_network_count: 1,
      gateway_network_count: 2,
      gateway_dual_homed: true,
      direct_egress_probe: "blocked",
      gateway_reachability_probe: "allowed",
      direct_probe_command_sha256: "9".repeat(64),
      gateway_probe_command_sha256: "a".repeat(64),
    },
    coverage: {
      model_network_egress_enforced: true,
      provider_credentials_withheld_from_agent: true,
      agent_root_filesystem_read_only: true,
      unprivileged_workload: true,
      workload_network_bypass_possible: false,
      operator_or_docker_daemon_bypass_possible: true,
      process_spawn_capture_complete: false,
      file_read_capture_complete: false,
      side_effect_capture_complete: false,
      full_world_state_capture: false,
      full_host_enforcement: false,
    },
  };
  return { ...body, receipt_sha256: digestCanonical(body) };
}

function runtimeBundle(policySha256: string, identitySha256: string): RuntimeEvidenceBundle {
  const directory = join(mkdtempSync(join(tmpdir(), "gradia-composition-g3-")), "runtime");
  const recorder = new DurableRuntimeEvidenceRecorder({
    directory,
    runtimeVersion: "1.0.0",
    sessionId: "composition-session-01",
    createdAt: observedAt,
    runtimeIdentitySha256: sha256(Buffer.from(runtimeId)),
    policySha256,
    credentialPolicySha256: digestCanonical({ identity_sha256: identitySha256 }),
    declaredCredentialScopeIds: ["model.invoke"],
  });
  recorder.append(
    {
      kind: "process",
      operation: "spawn",
      process_identity_sha256: "b".repeat(64),
      parent_process_identity_sha256: null,
      command_identity_sha256: "c".repeat(64),
      outcome: "running",
      exit_code: null,
      signal: null,
      reason_codes: ["runtime_started"],
    },
    { logicalTime: 1, observedAt, occurrenceId: "process-1" },
  );
  recorder.terminalize({
    logicalTime: 2,
    observedAt: "2026-08-27T14:00:01.000Z",
    occurrenceId: "terminal-1",
    terminalStatus: "completed",
    reasonCodes: ["runtime_completed"],
    crashRecovery: false,
  });
  return recorder.finalize("2026-08-27T14:00:02.000Z");
}

test("composition binds credentialless dispatch, Docker enforcement, and G3 to one runtime", async () => {
  const source = await credentiallessRun();
  const container = containerReceipt(
    source.policy.policy_sha256,
    source.configuration.configuration_sha256,
    source.run.receipt.workload_identity_sha256,
  );
  const g3 = runtimeBundle(
    source.policy.policy_sha256,
    source.run.receipt.workload_identity_sha256,
  );
  const sources = {
    credentiallessRuntimeDirectory: source.run.directory,
    containerEnforcementReceipt: container,
    runtimeEvidenceBundle: g3,
    createdAt: "2026-08-27T14:00:03.000Z",
  };
  const receipt = composeRuntimeEvidence(sources);
  const verification = verifyRuntimeCompositionReceipt(receipt, sources);
  assert.equal(verification.ok, true);
  assert.equal(receipt.runtime_id, runtimeId);
  assert.equal(receipt.coverage.measured_agent_direct_egress_blocked, true);
  assert.equal(receipt.coverage.parent_forwarded_provider_credentials_to_child, false);
  assert.equal(receipt.coverage.operator_or_docker_daemon_bypass_possible, true);
  assert.equal(receipt.coverage.declared_recorder_bypass_possible, true);
  assert.equal(receipt.coverage.full_host_enforcement, false);
  assert.equal(receipt.coverage.full_world_state_capture, false);

  const cliDirectory = mkdtempSync(join(tmpdir(), "gradia-composition-cli-"));
  const containerPath = join(cliDirectory, "container.json");
  const bundlePath = join(cliDirectory, "runtime.json");
  const compositionPath = join(cliDirectory, "composition.json");
  writeFileSync(containerPath, `${JSON.stringify(container)}\n`);
  writeFileSync(bundlePath, `${JSON.stringify(g3)}\n`);
  const composed = JSON.parse(
    execFileSync(
      process.execPath,
      [
        "dist/src/cli.js",
        "runtime",
        "compose",
        "--credentialless",
        source.run.directory,
        "--container",
        containerPath,
        "--bundle",
        bundlePath,
        "--created-at",
        sources.createdAt,
        "--out",
        compositionPath,
      ],
      { cwd: process.cwd(), encoding: "utf8" },
    ),
  ) as { receipt_sha256: string };
  assert.equal(composed.receipt_sha256, receipt.receipt_sha256);
  const cliVerified = JSON.parse(
    execFileSync(
      process.execPath,
      [
        "dist/src/cli.js",
        "runtime",
        "verify-composition",
        "--receipt",
        compositionPath,
        "--credentialless",
        source.run.directory,
        "--container",
        containerPath,
        "--bundle",
        bundlePath,
      ],
      { cwd: process.cwd(), encoding: "utf8" },
    ),
  ) as { ok: boolean; receipt_sha256: string };
  assert.equal(cliVerified.ok, true);
  assert.equal(cliVerified.receipt_sha256, receipt.receipt_sha256);
});

test("composition refuses cross-runtime substitution and rehashed coverage inflation", async () => {
  const source = await credentiallessRun();
  const container = containerReceipt(
    source.policy.policy_sha256,
    source.configuration.configuration_sha256,
    source.run.receipt.workload_identity_sha256,
  );
  const g3 = runtimeBundle(
    source.policy.policy_sha256,
    source.run.receipt.workload_identity_sha256,
  );
  const sources = {
    credentiallessRuntimeDirectory: source.run.directory,
    containerEnforcementReceipt: container,
    runtimeEvidenceBundle: g3,
    createdAt: "2026-08-27T14:00:03.000Z",
  };
  const receipt = composeRuntimeEvidence(sources);
  const inflated = structuredClone(receipt) as unknown as Record<string, unknown>;
  (inflated["coverage"] as Record<string, unknown>)["full_host_enforcement"] = true;
  const { receipt_sha256: _old, ...inflatedBody } = inflated;
  inflated["receipt_sha256"] = digestCanonical(inflatedBody);
  assert.equal(verifyRuntimeCompositionReceipt(inflated, sources).ok, false);

  const foreign = structuredClone(container) as unknown as Record<string, unknown>;
  foreign["runtime_id"] = "foreign-runtime";
  const { receipt_sha256: _foreignOld, ...foreignBody } = foreign;
  foreign["receipt_sha256"] = digestCanonical(foreignBody);
  assert.throws(
    () =>
      composeRuntimeEvidence({
        ...sources,
        containerEnforcementReceipt: foreign,
      }),
    /runtime_composition_container_runtime_mismatch/,
  );
});
