import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import {
  providerSdkCompatibilityCatalog,
  verifyProviderSdkCompatibilityCatalog,
} from "../src/provider-sdk-compatibility.js";

test("SDK catalog is exact, self-digested, and package pins match installed metadata", () => {
  const catalog = verifyProviderSdkCompatibilityCatalog(providerSdkCompatibilityCatalog());
  const packageDocument = JSON.parse(readFileSync("package.json", "utf8")) as {
    devDependencies?: Record<string, string>;
  };
  for (const entry of catalog.entries) {
    assert.equal(packageDocument.devDependencies?.[entry.package_name], entry.package_version);
    const installed = JSON.parse(
      readFileSync(join("node_modules", entry.package_name, "package.json"), "utf8"),
    ) as { version?: string };
    assert.equal(installed.version, entry.package_version);
  }
  assert.equal(catalog.live_provider_behavior_proved, false);
  assert.equal(catalog.arbitrary_sdk_version_compatibility_proved, false);
  assert.equal(catalog.direct_network_bypass_possible_outside_enforced_runtime, true);
});

test("SDK matrix CLI exposes the same exact catalog locally", () => {
  const output = JSON.parse(
    execFileSync(process.execPath, ["dist/src/cli.js", "sdk-matrix", "--json"], {
      encoding: "utf8",
    }),
  ) as unknown;
  assert.deepEqual(output, providerSdkCompatibilityCatalog());
  const human = execFileSync(process.execPath, ["dist/src/cli.js", "sdk-matrix"], {
    encoding: "utf8",
  });
  assert.match(human, /exact pinned SDK-to-local-gateway compatibility only/);
});

test("SDK catalog refuses a rehashed-looking compatibility overclaim", () => {
  const mutation = structuredClone(providerSdkCompatibilityCatalog()) as unknown as Record<
    string,
    unknown
  >;
  mutation["arbitrary_sdk_version_compatibility_proved"] = true;
  assert.throws(
    () => verifyProviderSdkCompatibilityCatalog(mutation),
    /provider_sdk_compatibility_catalog_invalid/,
  );
});
