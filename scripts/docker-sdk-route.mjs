import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const agent = "gradia-guard-agent-proof";
const gateway = "gradia-guard-gateway-proof";
const providers = ["anthropic", "gemini", "openai", "xai"];
const frameworks = [
  {
    id: "vercel_ai_sdk",
    compose: ["compose", "-f", "test/fixtures/container-enforcement/compose.yml"],
  },
  {
    id: "langchain",
    compose: ["compose", "-f", "test/fixtures/container-enforcement/compose.langchain.yml"],
  },
];
const output = mkdtempSync(join(tmpdir(), "gradia-docker-sdk-route-"));

function docker(args, environment, options = {}) {
  return execFileSync("docker", args, {
    cwd: process.cwd(),
    encoding: "utf8",
    timeout: 30_000,
    env: environment,
    ...options,
  });
}

function cli(args, env = process.env) {
  return execFileSync(process.execPath, ["dist/src/cli.js", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    timeout: 60_000,
    env,
  });
}

function waitForStatus() {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const result = spawnSync(
      "docker",
      ["exec", gateway, "cat", "/tmp/guard-status.json"],
      { encoding: "utf8", timeout: 2_000 },
    );
    if (result.status === 0) return JSON.parse(result.stdout);
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
  }
  throw new Error("docker_sdk_gateway_readiness_timeout");
}

const cells = [];
for (const framework of frameworks) {
  for (const provider of providers) {
    const capability = randomBytes(32).toString("base64url");
    const composeEnvironment = {
      ...process.env,
      GRADIA_GUARD_LOCAL_CAPABILITY: capability,
      GRADIA_GUARD_PROOF_PROVIDER: provider,
    };
    const cellOutput = join(output, framework.id, provider);
    mkdirSync(cellOutput, { recursive: true, mode: 0o700 });
    try {
      docker([...framework.compose, "down"], composeEnvironment, { stdio: "ignore" });
      docker([...framework.compose, "up", "-d", "--build"], composeEnvironment, {
        stdio: "ignore",
        timeout: 180_000,
      });
      const status = waitForStatus();
      if (status.provider !== provider) throw new Error("docker_sdk_gateway_provider_mismatch");
      cli([
      "runtime",
      "collect-docker",
      "--runtime-id",
      status.runtime_id,
      "--agent",
      agent,
      "--gateway",
      gateway,
      "--internal-network",
      "gradia-guard-proof-internal",
      "--policy-sha256",
      status.policy_sha256,
      "--probe-runtime",
      framework.id === "langchain" ? "python" : "node",
      "--configuration-sha256",
      status.configuration_sha256,
      "--workload-identity-sha256",
      status.workload_identity_sha256,
      "--direct-url",
      "https://1.1.1.1/",
      "--gateway-url",
      "http://gateway:8787/health",
      "--out",
      join(cellOutput, "container.json"),
      ]);
      const probe = JSON.parse(
        cli(
        [
          "runtime",
          "probe-docker-sdk",
          "--agent",
          agent,
          "--gateway",
          gateway,
          "--container-receipt",
          join(cellOutput, "container.json"),
          "--framework",
          framework.id,
          "--provider",
          provider,
          "--local-origin",
          "http://gateway:8787",
          "--capability-env",
          "GRADIA_PROOF_LOCAL_CAPABILITY",
          "--gateway-evidence-out",
          join(cellOutput, "gateway-evidence"),
          "--out",
          join(cellOutput, "sdk-route.json"),
        ],
        { ...process.env, GRADIA_PROOF_LOCAL_CAPABILITY: capability },
        ),
      );
      const verification = JSON.parse(
        cli([
        "runtime",
        "verify-docker-sdk",
        "--receipt",
        join(cellOutput, "sdk-route.json"),
        "--container-receipt",
        join(cellOutput, "container.json"),
        "--gateway-evidence",
        join(cellOutput, "gateway-evidence"),
        ]),
      );
      cells.push({
        framework: framework.id,
        provider,
        ok: verification.ok,
        receipt_sha256: probe.receipt_sha256,
        gateway_chain_head_sha256: probe.gateway_chain_head_sha256,
        probe_output: probe.probe_output,
      });
    } finally {
      docker([...framework.compose, "down"], composeEnvironment, { stdio: "ignore" });
    }
  }
}

process.stdout.write(`${JSON.stringify({
  ok: cells.length === providers.length * frameworks.length && cells.every((cell) => cell.ok),
  output_directory: output,
  cells,
})}\n`);
