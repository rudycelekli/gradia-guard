import { canonicalJson, digestCanonical } from "./canonical.js";

export const FRAMEWORK_SDK_COMPATIBILITY_SCHEMA_VERSION =
  "gradia.guard.framework-sdk-compatibility.v2" as const;

export interface FrameworkSdkCompatibilityEntry {
  provider: "anthropic" | "gemini" | "openai" | "xai";
  framework: "vercel_ai_sdk" | "langchain";
  language: "javascript" | "python";
  verification_gate: "package_prepack" | "monorepo_cross_language";
  framework_core_package: "ai" | "langchain-core";
  framework_core_version: string;
  provider_package:
    | "@ai-sdk/anthropic"
    | "@ai-sdk/google"
    | "@ai-sdk/openai"
    | "@ai-sdk/xai"
    | "langchain-anthropic"
    | "langchain-google-genai"
    | "langchain-openai"
    | "langchain-xai";
  provider_package_version: string;
  model_factory: "messages" | "chat" | "responses" | "invoke";
  route_id:
    | "anthropic.messages"
    | "gemini.generateContent"
    | "openai.responses"
    | "xai.responses";
  retries_disabled_in_gate: true;
}

export interface FrameworkSdkCompatibilityCatalogBody {
  schema_version: typeof FRAMEWORK_SDK_COMPATIBILITY_SCHEMA_VERSION;
  runtime_requirements: readonly ["node>=20.12", "python>=3.12"];
  entries: readonly FrameworkSdkCompatibilityEntry[];
  credential_delivery: "local_capability_only_not_provider_credential";
  transport_boundary: "parent_owned_ipv4_loopback_gateway";
  request_policy_timing: "before_upstream_dispatch";
  live_provider_behavior_proved: false;
  arbitrary_framework_version_compatibility_proved: false;
  framework_telemetry_capture_proved: false;
  direct_network_bypass_possible_outside_enforced_runtime: true;
  claim_boundary: "exact_pinned_framework_provider_to_local_gateway_compatibility_only";
}

export interface FrameworkSdkCompatibilityCatalog
  extends FrameworkSdkCompatibilityCatalogBody {
  catalog_sha256: string;
}

const ENTRIES: readonly FrameworkSdkCompatibilityEntry[] = Object.freeze([
  Object.freeze({
    provider: "anthropic",
    framework: "vercel_ai_sdk",
    language: "javascript",
    verification_gate: "package_prepack",
    framework_core_package: "ai",
    framework_core_version: "7.0.83",
    provider_package: "@ai-sdk/anthropic",
    provider_package_version: "4.0.44",
    model_factory: "messages",
    route_id: "anthropic.messages",
    retries_disabled_in_gate: true,
  }),
  Object.freeze({
    provider: "gemini",
    framework: "vercel_ai_sdk",
    language: "javascript",
    verification_gate: "package_prepack",
    framework_core_package: "ai",
    framework_core_version: "7.0.83",
    provider_package: "@ai-sdk/google",
    provider_package_version: "4.0.56",
    model_factory: "chat",
    route_id: "gemini.generateContent",
    retries_disabled_in_gate: true,
  }),
  Object.freeze({
    provider: "openai",
    framework: "vercel_ai_sdk",
    language: "javascript",
    verification_gate: "package_prepack",
    framework_core_package: "ai",
    framework_core_version: "7.0.83",
    provider_package: "@ai-sdk/openai",
    provider_package_version: "4.0.50",
    model_factory: "responses",
    route_id: "openai.responses",
    retries_disabled_in_gate: true,
  }),
  Object.freeze({
    provider: "xai",
    framework: "vercel_ai_sdk",
    language: "javascript",
    verification_gate: "package_prepack",
    framework_core_package: "ai",
    framework_core_version: "7.0.83",
    provider_package: "@ai-sdk/xai",
    provider_package_version: "4.0.48",
    model_factory: "responses",
    route_id: "xai.responses",
    retries_disabled_in_gate: true,
  }),
  Object.freeze({
    provider: "anthropic",
    framework: "langchain",
    language: "python",
    verification_gate: "monorepo_cross_language",
    framework_core_package: "langchain-core",
    framework_core_version: "1.6.1",
    provider_package: "langchain-anthropic",
    provider_package_version: "1.7.0",
    model_factory: "invoke",
    route_id: "anthropic.messages",
    retries_disabled_in_gate: true,
  }),
  Object.freeze({
    provider: "gemini",
    framework: "langchain",
    language: "python",
    verification_gate: "monorepo_cross_language",
    framework_core_package: "langchain-core",
    framework_core_version: "1.6.1",
    provider_package: "langchain-google-genai",
    provider_package_version: "4.3.7",
    model_factory: "invoke",
    route_id: "gemini.generateContent",
    retries_disabled_in_gate: true,
  }),
  Object.freeze({
    provider: "openai",
    framework: "langchain",
    language: "python",
    verification_gate: "monorepo_cross_language",
    framework_core_package: "langchain-core",
    framework_core_version: "1.6.1",
    provider_package: "langchain-openai",
    provider_package_version: "1.6.0",
    model_factory: "invoke",
    route_id: "openai.responses",
    retries_disabled_in_gate: true,
  }),
  Object.freeze({
    provider: "xai",
    framework: "langchain",
    language: "python",
    verification_gate: "monorepo_cross_language",
    framework_core_package: "langchain-core",
    framework_core_version: "1.6.1",
    provider_package: "langchain-xai",
    provider_package_version: "1.3.0",
    model_factory: "invoke",
    route_id: "xai.responses",
    retries_disabled_in_gate: true,
  }),
]);

export function frameworkSdkCompatibilityCatalog(): FrameworkSdkCompatibilityCatalog {
  const body: FrameworkSdkCompatibilityCatalogBody = {
    schema_version: FRAMEWORK_SDK_COMPATIBILITY_SCHEMA_VERSION,
    runtime_requirements: ["node>=20.12", "python>=3.12"],
    entries: ENTRIES,
    credential_delivery: "local_capability_only_not_provider_credential",
    transport_boundary: "parent_owned_ipv4_loopback_gateway",
    request_policy_timing: "before_upstream_dispatch",
    live_provider_behavior_proved: false,
    arbitrary_framework_version_compatibility_proved: false,
    framework_telemetry_capture_proved: false,
    direct_network_bypass_possible_outside_enforced_runtime: true,
    claim_boundary: "exact_pinned_framework_provider_to_local_gateway_compatibility_only",
  };
  return Object.freeze({ ...body, catalog_sha256: digestCanonical(body) });
}

export function verifyFrameworkSdkCompatibilityCatalog(
  value: unknown,
): FrameworkSdkCompatibilityCatalog {
  if (canonicalJson(value) !== canonicalJson(frameworkSdkCompatibilityCatalog())) {
    throw new Error("framework_sdk_compatibility_catalog_invalid");
  }
  return value as FrameworkSdkCompatibilityCatalog;
}

export function formatFrameworkSdkCompatibilityCatalog(
  catalog: FrameworkSdkCompatibilityCatalog,
): string {
  verifyFrameworkSdkCompatibilityCatalog(catalog);
  const lines = [
    "Gradia Guard pinned framework compatibility matrix",
    `Catalog SHA-256: ${catalog.catalog_sha256}`,
    "",
  ];
  for (const entry of catalog.entries) {
    lines.push(
      `${entry.language}/${entry.framework}/${entry.provider}: ${entry.framework_core_package}@${entry.framework_core_version} + ${entry.provider_package}@${entry.provider_package_version} -> ${entry.route_id} (${entry.verification_gate})`,
    );
  }
  lines.push(
    "",
    "Claim boundary: exact pinned framework-provider-to-local-gateway compatibility only.",
    "Live provider behavior, arbitrary framework versions, framework telemetry capture, and direct-network non-bypassability are not proved.",
  );
  return `${lines.join("\n")}\n`;
}
