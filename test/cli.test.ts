import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { canonicalJson } from "../src/canonical.js";
import { sealPolicy, type GuardPolicyBody } from "../src/policy.js";

test("CLI run and verify provide the one-line contract", () => {
  const outputRoot = mkdtempSync(join(tmpdir(), "gradia-guard-cli-"));
  const run = spawnSync(
    process.execPath,
    ["dist/src/cli.js", "run", "--out", outputRoot, "--", process.execPath, "test/fixtures/child.mjs", "0"],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(run.status, 0, run.stderr);
  const directory = join(outputRoot, readdirSync(outputRoot)[0] as string);
  const verified = JSON.parse(
    execFileSync(process.execPath, ["dist/src/cli.js", "verify", directory], {
      cwd: process.cwd(),
      encoding: "utf8",
    }),
  ) as { ok: boolean; frame_count: number };
  assert.equal(verified.ok, true);
  assert.ok(verified.frame_count >= 4);

  const inspected = execFileSync(process.execPath, ["dist/src/cli.js", "inspect", directory], {
    cwd: process.cwd(),
    encoding: "utf8",
  });
  assert.match(inspected, /Gradia Guard inspection: VERIFIED/);
  assert.match(inspected, /Assurance tier: process/);
  assert.match(inspected, /Still unobserved:/);
  assert.match(inspected, /Next evidence door:/);

  const inspectedJson = JSON.parse(
    execFileSync(process.execPath, ["dist/src/cli.js", "inspect", "--json", directory], {
      cwd: process.cwd(),
      encoding: "utf8",
    }),
  ) as { ok: boolean; assurance: { tier: string } };
  assert.equal(inspectedJson.ok, true);
  assert.equal(inspectedJson.assurance.tier, "process");

  const compared = execFileSync(
    process.execPath,
    ["dist/src/cli.js", "compare", directory, directory],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.match(compared, /Gradia Guard comparison: VERIFIED/);
  assert.match(compared, /Exact bundle identity: yes/);
  assert.match(compared, /Behavioral regression claim: not eligible/);
});

test("CLI refuses likely command-line credentials before launch", () => {
  const outputRoot = mkdtempSync(join(tmpdir(), "gradia-guard-cli-secret-"));
  const run = spawnSync(
    process.execPath,
    ["dist/src/cli.js", "run", "--out", outputRoot, "--", process.execPath, "--api-key=not-recordable"],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(run.status, 2);
  assert.match(run.stderr, /command_secret_flag_refused/);
  assert.deepEqual(readdirSync(outputRoot), []);
});

test("CLI refuses env-style credential assignment before launch", () => {
  const outputRoot = mkdtempSync(join(tmpdir(), "gradia-guard-cli-secret-env-"));
  const run = spawnSync(
    process.execPath,
    [
      "dist/src/cli.js",
      "run",
      "--out",
      outputRoot,
      "--",
      "env",
      "OPENAI_API_KEY=not-recordable",
      process.execPath,
      "test/fixtures/child.mjs",
    ],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(run.status, 2);
  assert.match(run.stderr, /command_secret_assignment_refused/);
  assert.deepEqual(readdirSync(outputRoot), []);
});

test("CLI initializes, verifies, and simulates a deny-by-default policy", () => {
  const directory = mkdtempSync(join(tmpdir(), "gradia-guard-policy-cli-"));
  const policyPath = join(directory, "policy.json");
  execFileSync(process.execPath, ["dist/src/cli.js", "policy", "init", "--out", policyPath], {
    cwd: process.cwd(),
  });
  const initialized = JSON.parse(readFileSync(policyPath, "utf8")) as { policy_sha256: string };
  const verified = JSON.parse(
    execFileSync(process.execPath, ["dist/src/cli.js", "policy", "verify", policyPath], {
      cwd: process.cwd(),
      encoding: "utf8",
    }),
  ) as { ok: boolean; policy_sha256: string };
  assert.equal(verified.ok, true);
  assert.equal(verified.policy_sha256, initialized.policy_sha256);

  const blocked = spawnSync(
    process.execPath,
    [
      "dist/src/cli.js",
      "policy",
      "check-model",
      policyPath,
      "--provider",
      "openai",
      "--model",
      "gpt-5.6-2026-08-01",
      "--request-bytes",
      "10",
      "--attempt",
      "1",
      "--scope",
      "case.read",
    ],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(blocked.status, 1, blocked.stderr);
  assert.equal(JSON.parse(blocked.stdout).decision, "blocked");
});

test("CLI policy simulator allows an exact admitted model route", () => {
  const directory = mkdtempSync(join(tmpdir(), "gradia-guard-policy-cli-allow-"));
  const policyPath = join(directory, "policy.json");
  const body: GuardPolicyBody = {
    schema_version: "gradia.guard.policy.v1",
    policy_id: "cli-policy",
    policy_version: "v1",
    default_decision: "blocked",
    model_routes: [
      {
        provider: "openai",
        requested_model: "gpt-5.6-2026-08-01",
        authority_scope_ids: ["case.read"],
        max_request_bytes: 100,
        max_attempt_number: 1,
      },
    ],
    tool_routes: [],
  };
  writeFileSync(policyPath, canonicalJson(sealPolicy(body)) + "\n");
  const allowed = execFileSync(
    process.execPath,
    [
      "dist/src/cli.js",
      "policy",
      "check-model",
      policyPath,
      "--provider",
      "openai",
      "--model",
      "gpt-5.6-2026-08-01",
      "--request-bytes",
      "10",
      "--attempt",
      "1",
      "--scope",
      "case.read",
    ],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(JSON.parse(allowed).decision, "allowed");
});

test("CLI creates, verifies, and assesses an evidence-readiness profile locally", () => {
  const directory = mkdtempSync(join(tmpdir(), "gradia-guard-readiness-cli-"));
  const profilePath = join(directory, "profile.json");
  execFileSync(process.execPath, ["dist/src/cli.js", "readiness", "init", "--out", profilePath], {
    cwd: process.cwd(),
  });
  const verified = JSON.parse(
    execFileSync(process.execPath, ["dist/src/cli.js", "readiness", "verify", profilePath], {
      cwd: process.cwd(),
      encoding: "utf8",
    }),
  ) as { ok: boolean; profile_sha256: string };
  assert.equal(verified.ok, true);
  assert.match(verified.profile_sha256, /^[0-9a-f]{64}$/);

  const report = JSON.parse(
    execFileSync(
      process.execPath,
      [
        "dist/src/cli.js",
        "readiness",
        "assess",
        "--json",
        profilePath,
        "test/fixtures/gateway-reference-bundle",
      ],
      { cwd: process.cwd(), encoding: "utf8" },
    ),
  ) as {
    bundle: { verified: boolean; assurance_tier: string };
    counts: { evidence_ready: number; missing: number };
    claim_boundary: string;
  };
  assert.equal(report.bundle.verified, true);
  assert.equal(report.bundle.assurance_tier, "gateway");
  assert.ok(report.counts.evidence_ready > 0);
  assert.ok(report.counts.missing > 0);
  assert.match(report.claim_boundary, /does not establish control effectiveness/);
});

test("CLI verifies the portable G3 runtime ABI and refuses a rehashed-looking mutation", () => {
  const fixture = join(process.cwd(), "test/fixtures/runtime-reference-bundle.json");
  const verified = JSON.parse(
    execFileSync(process.execPath, ["dist/src/cli.js", "runtime", "verify", fixture], {
      cwd: process.cwd(),
      encoding: "utf8",
    }),
  ) as {
    ok: boolean;
    receipt_count: number;
    terminal_status: string;
    claim_boundary: string;
  };
  assert.equal(verified.ok, true);
  assert.equal(verified.receipt_count, 2);
  assert.equal(verified.terminal_status, "completed");
  assert.equal(
    verified.claim_boundary,
    "declared_runtime_observation_not_container_or_kubernetes_enforcement",
  );

  const directory = mkdtempSync(join(tmpdir(), "gradia-runtime-cli-mutation-"));
  const mutationPath = join(directory, "runtime.json");
  const mutation = JSON.parse(readFileSync(fixture, "utf8")) as Record<string, unknown>;
  mutation["unexpected"] = true;
  writeFileSync(mutationPath, canonicalJson(mutation) + "\n");
  const refused = spawnSync(
    process.execPath,
    ["dist/src/cli.js", "runtime", "verify", mutationPath],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(refused.status, 1, refused.stderr);
  assert.equal(JSON.parse(refused.stdout).ok, false);
});
