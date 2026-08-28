import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import {
  frameworkSdkCompatibilityCatalog,
  verifyFrameworkSdkCompatibilityCatalog,
} from "../src/framework-sdk-compatibility.js";

test("framework catalog is self-digested and exact package pins match installed metadata", () => {
  const catalog = verifyFrameworkSdkCompatibilityCatalog(frameworkSdkCompatibilityCatalog());
  const packageDocument = JSON.parse(readFileSync("package.json", "utf8")) as {
    devDependencies?: Record<string, string>;
  };
  for (const entry of catalog.entries.filter((candidate) => candidate.language === "javascript")) {
    for (const [packageName, version] of [
      [entry.framework_core_package, entry.framework_core_version],
      [entry.provider_package, entry.provider_package_version],
    ] as const) {
      assert.equal(packageDocument.devDependencies?.[packageName], version);
      const installed = JSON.parse(
        readFileSync(join("node_modules", packageName, "package.json"), "utf8"),
      ) as { version?: string };
      assert.equal(installed.version, version);
    }
  }
  assert.equal(catalog.live_provider_behavior_proved, false);
  assert.equal(catalog.arbitrary_framework_version_compatibility_proved, false);
  assert.equal(catalog.framework_telemetry_capture_proved, false);
  assert.equal(catalog.direct_network_bypass_possible_outside_enforced_runtime, true);
  assert.deepEqual(
    catalog.entries.map((entry) => `${entry.language}:${entry.framework}:${entry.provider}`),
    [
      "javascript:vercel_ai_sdk:anthropic",
      "javascript:vercel_ai_sdk:gemini",
      "javascript:vercel_ai_sdk:openai",
      "javascript:vercel_ai_sdk:xai",
      "python:langchain:anthropic",
      "python:langchain:gemini",
      "python:langchain:openai",
      "python:langchain:xai",
    ],
  );
});

test("framework matrix CLI exposes the same exact catalog locally", () => {
  const output = JSON.parse(
    execFileSync(process.execPath, ["dist/src/cli.js", "framework-matrix", "--json"], {
      encoding: "utf8",
    }),
  ) as unknown;
  assert.deepEqual(output, frameworkSdkCompatibilityCatalog());
  const human = execFileSync(process.execPath, ["dist/src/cli.js", "framework-matrix"], {
    encoding: "utf8",
  });
  assert.match(human, /exact pinned framework-provider-to-local-gateway compatibility only/);
});

test("framework catalog refuses a rehashed-looking telemetry-capture overclaim", () => {
  const mutation = structuredClone(frameworkSdkCompatibilityCatalog()) as unknown as Record<
    string,
    unknown
  >;
  mutation["framework_telemetry_capture_proved"] = true;
  assert.throws(
    () => verifyFrameworkSdkCompatibilityCatalog(mutation),
    /framework_sdk_compatibility_catalog_invalid/,
  );
});
