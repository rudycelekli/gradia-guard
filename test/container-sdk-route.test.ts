import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { digestCanonical } from "../src/canonical.js";
import { verifyContainerSdkRouteReceipt } from "../src/container-sdk-route.js";

const fixtureRoot = join(process.cwd(), "test/fixtures/container-enforcement");
const liveRoot = join(fixtureRoot, "live-docker-sdk");
const cells = [
  { framework: "vercel_ai_sdk", provider: "anthropic", receipt: "ca191a1c4c0b31afa52abff98ae20588e42d42c6bb7e5597a8029226794c57cd", gateway: "0164db9d14d7e58603a344a16c9bc5058a795ad9315728213a476dcc406ab784" },
  { framework: "vercel_ai_sdk", provider: "gemini", receipt: "ce3b9318a9149be40f5eeecede095082f6f31a3222a4dd7be1b7e63bd37d2d73", gateway: "1ed1e87bdfe92c8e74e14f0586920fb7a9fe75071faeaa0747d4351074ae6020" },
  { framework: "vercel_ai_sdk", provider: "openai", receipt: "30101bdb4c3efd8316d71fcc834bacea07f69ffe224c2b1128cff60ad9fbb2f7", gateway: "f7b37f2657ce1cc976eb1153fbb280c18844a6b4a07cb68fc1407d6cb813ba32" },
  { framework: "vercel_ai_sdk", provider: "xai", receipt: "8d5a6eab6c0443dc661b279e17724d3bfc538aa3357c200c60e04b713df6d6ed", gateway: "bd8f9983c5461ddcd9af27e5fd907851fba8d2772621cc0d88de30840f85b5ba" },
  { framework: "langchain", provider: "anthropic", receipt: "faee66462bbe09ee6f5cdbdc62247e884de15e4a2bb23e786ffff54cc69309e8", gateway: "4acd1efa06304b17e892d3e94f686c0e433aca244fbfe4b013fee786fa099fd8" },
  { framework: "langchain", provider: "gemini", receipt: "9341a4f9fa77b2b0b23217478fa0d63c4f3a15c0c6aa969afda45ae29eaf439e", gateway: "b9c9a56502675d681886164e326c2d4eff35990fa7fd7d1a51750540c8b4ba8a" },
  { framework: "langchain", provider: "openai", receipt: "f9a4cf9db9bec099b54449dfc9588589937c7cd559fe67d3ff8c9b4b5d39e475", gateway: "4f79d7c793be38efab3a71894c95e99c02ff7f1e11e9e8641d239b0d1bc1ad47" },
  { framework: "langchain", provider: "xai", receipt: "e6362490085c52b5be0cb2a68f085f51e366738baab0434f434a71f2c0ac9554", gateway: "a93c26f5e841f5af0fc14ac07d18faf15bb88ff577b34c6d0408d14d5d57982e" },
] as const;

type Cell = (typeof cells)[number];

function cellPaths(framework: Cell["framework"], provider: Cell["provider"]): {
  container: string;
  receipt: string;
  gateway: string;
} {
  const root = join(liveRoot, framework, provider);
  return {
    container: join(root, "container.json"),
    receipt: join(root, "sdk-route.json"),
    gateway: join(root, "gateway-evidence"),
  };
}

function artifact(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8")) as unknown;
}

for (const cell of cells) {
  test(`checked-in ${cell.framework}/${cell.provider} same-container SDK and Guard proof replays independently`, () => {
    const paths = cellPaths(cell.framework, cell.provider);
    const verification = verifyContainerSdkRouteReceipt(
      artifact(paths.receipt),
      artifact(paths.container),
      paths.gateway,
    );
    assert.equal(verification.ok, true, verification.blockers.join(","));
    assert.equal(verification.receipt_sha256, cell.receipt);
    assert.equal(verification.gateway_chain_head_sha256, cell.gateway);

    const cli = JSON.parse(
      execFileSync(
        process.execPath,
        [
          "dist/src/cli.js",
          "runtime",
          "verify-docker-sdk",
          "--receipt",
          paths.receipt,
          "--container-receipt",
          paths.container,
          "--gateway-evidence",
          paths.gateway,
        ],
        { cwd: process.cwd(), encoding: "utf8" },
      ),
    ) as { ok: boolean; receipt_sha256: string };
    assert.equal(cli.ok, true);
    assert.equal(cli.receipt_sha256, verification.receipt_sha256);
  });
}

test("same-container SDK receipt refuses rehashed coverage and package overclaims", () => {
  const paths = cellPaths("vercel_ai_sdk", "openai");
  const receiptPath = paths.receipt;
  const containerPath = paths.container;
  const gatewayPath = paths.gateway;
  const coverageOverclaim = structuredClone(artifact(receiptPath)) as Record<string, unknown>;
  (coverageOverclaim["coverage"] as Record<string, unknown>)["live_provider_behavior_proved"] = true;
  const { receipt_sha256: _coverageDigest, ...coverageBody } = coverageOverclaim;
  coverageOverclaim["receipt_sha256"] = digestCanonical(coverageBody);
  assert.equal(
    verifyContainerSdkRouteReceipt(coverageOverclaim, artifact(containerPath), gatewayPath).ok,
    false,
  );

  const packageOverclaim = structuredClone(artifact(receiptPath)) as Record<string, unknown>;
  const output = packageOverclaim["probe_output"] as Record<string, unknown>;
  output["provider_package_version"] = "999.0.0";
  packageOverclaim["probe_output_sha256"] = digestCanonical(output);
  const { receipt_sha256: _packageDigest, ...packageBody } = packageOverclaim;
  packageOverclaim["receipt_sha256"] = digestCanonical(packageBody);
  assert.equal(
    verifyContainerSdkRouteReceipt(packageOverclaim, artifact(containerPath), gatewayPath).ok,
    false,
  );
});

test("same-container SDK receipt refuses a changed gateway evidence chain", () => {
  const paths = cellPaths("vercel_ai_sdk", "openai");
  const receiptPath = paths.receipt;
  const containerPath = paths.container;
  const gatewayPath = paths.gateway;
  const directory = join(mkdtempSync(join(tmpdir(), "gradia-container-sdk-tamper-")), "gateway");
  mkdirSync(directory, { mode: 0o700 });
  copyFileSync(join(gatewayPath, "bundle.json"), join(directory, "bundle.json"));
  const frames = readFileSync(join(gatewayPath, "frames.ndjson"), "utf8");
  writeFileSync(join(directory, "frames.ndjson"), frames.replace("gpt-5.6-2026-08-01", "gpt-5.6-2026-08-02"));
  const verification = verifyContainerSdkRouteReceipt(
    artifact(receiptPath),
    artifact(containerPath),
    directory,
  );
  assert.equal(verification.ok, false);
  assert.match(verification.blockers.join(","), /container_sdk_gateway_bundle_invalid/);
});

test("same-container SDK receipt refuses framework substitution and excess capability aliases", () => {
  const paths = cellPaths("langchain", "gemini");
  const frameworkSubstitution = structuredClone(artifact(paths.receipt)) as Record<string, unknown>;
  const substitutedOutput = frameworkSubstitution["probe_output"] as Record<string, unknown>;
  substitutedOutput["framework"] = "vercel_ai_sdk";
  frameworkSubstitution["probe_output_sha256"] = digestCanonical(substitutedOutput);
  const { receipt_sha256: _frameworkDigest, ...frameworkBody } = frameworkSubstitution;
  frameworkSubstitution["receipt_sha256"] = digestCanonical(frameworkBody);
  assert.equal(
    verifyContainerSdkRouteReceipt(frameworkSubstitution, artifact(paths.container), paths.gateway).ok,
    false,
  );

  const excessAlias = structuredClone(artifact(paths.receipt)) as Record<string, unknown>;
  (excessAlias["probe_environment_names"] as string[]).push("GOOGLE_API_KEY");
  const { receipt_sha256: _aliasDigest, ...aliasBody } = excessAlias;
  excessAlias["receipt_sha256"] = digestCanonical(aliasBody);
  assert.equal(
    verifyContainerSdkRouteReceipt(excessAlias, artifact(paths.container), paths.gateway).ok,
    false,
  );
});
