import { canonicalJson, digestCanonical } from "./canonical.js";

export const PROVIDER_SDK_COMPATIBILITY_SCHEMA_VERSION =
  "gradia.guard.provider-sdk-compatibility.v1" as const;

export interface ProviderSdkCompatibilityEntry {
  provider: "anthropic" | "gemini" | "openai" | "xai";
  package_name: "@anthropic-ai/sdk" | "@google/genai" | "openai";
  package_version: string;
  route_id:
    | "anthropic.messages"
    | "gemini.generateContent"
    | "openai.responses"
    | "xai.responses";
  client_surface:
    | "messages.create"
    | "models.generateContent"
    | "responses.create";
  compatibility_mode: "official_provider_sdk" | "openai_compatible_sdk";
  retries_disabled_in_gate: true;
}

export interface ProviderSdkCompatibilityCatalogBody {
  schema_version: typeof PROVIDER_SDK_COMPATIBILITY_SCHEMA_VERSION;
  node_runtime: ">=20.12";
  entries: readonly ProviderSdkCompatibilityEntry[];
  credential_delivery: "local_capability_only_not_provider_credential";
  transport_boundary: "parent_owned_ipv4_loopback_gateway";
  request_policy_timing: "before_upstream_dispatch";
  live_provider_behavior_proved: false;
  arbitrary_sdk_version_compatibility_proved: false;
  direct_network_bypass_possible_outside_enforced_runtime: true;
  claim_boundary: "exact_pinned_sdk_to_local_gateway_compatibility_only";
}

export interface ProviderSdkCompatibilityCatalog
  extends ProviderSdkCompatibilityCatalogBody {
  catalog_sha256: string;
}

const ENTRIES: readonly ProviderSdkCompatibilityEntry[] = Object.freeze([
  Object.freeze({
    provider: "anthropic",
    package_name: "@anthropic-ai/sdk",
    package_version: "0.122.0",
    route_id: "anthropic.messages",
    client_surface: "messages.create",
    compatibility_mode: "official_provider_sdk",
    retries_disabled_in_gate: true,
  }),
  Object.freeze({
    provider: "gemini",
    package_name: "@google/genai",
    package_version: "2.19.0",
    route_id: "gemini.generateContent",
    client_surface: "models.generateContent",
    compatibility_mode: "official_provider_sdk",
    retries_disabled_in_gate: true,
  }),
  Object.freeze({
    provider: "openai",
    package_name: "openai",
    package_version: "7.8.0",
    route_id: "openai.responses",
    client_surface: "responses.create",
    compatibility_mode: "official_provider_sdk",
    retries_disabled_in_gate: true,
  }),
  Object.freeze({
    provider: "xai",
    package_name: "openai",
    package_version: "7.8.0",
    route_id: "xai.responses",
    client_surface: "responses.create",
    compatibility_mode: "openai_compatible_sdk",
    retries_disabled_in_gate: true,
  }),
]);

export function providerSdkCompatibilityCatalog(): ProviderSdkCompatibilityCatalog {
  const body: ProviderSdkCompatibilityCatalogBody = {
    schema_version: PROVIDER_SDK_COMPATIBILITY_SCHEMA_VERSION,
    node_runtime: ">=20.12",
    entries: ENTRIES,
    credential_delivery: "local_capability_only_not_provider_credential",
    transport_boundary: "parent_owned_ipv4_loopback_gateway",
    request_policy_timing: "before_upstream_dispatch",
    live_provider_behavior_proved: false,
    arbitrary_sdk_version_compatibility_proved: false,
    direct_network_bypass_possible_outside_enforced_runtime: true,
    claim_boundary: "exact_pinned_sdk_to_local_gateway_compatibility_only",
  };
  return Object.freeze({ ...body, catalog_sha256: digestCanonical(body) });
}

export function verifyProviderSdkCompatibilityCatalog(
  value: unknown,
): ProviderSdkCompatibilityCatalog {
  if (canonicalJson(value) !== canonicalJson(providerSdkCompatibilityCatalog())) {
    throw new Error("provider_sdk_compatibility_catalog_invalid");
  }
  return value as ProviderSdkCompatibilityCatalog;
}

export function formatProviderSdkCompatibilityCatalog(
  catalog: ProviderSdkCompatibilityCatalog,
): string {
  verifyProviderSdkCompatibilityCatalog(catalog);
  const lines = [
    "Gradia Guard pinned provider SDK matrix",
    `Catalog SHA-256: ${catalog.catalog_sha256}`,
    "",
  ];
  for (const entry of catalog.entries) {
    lines.push(
      `${entry.provider}: ${entry.package_name}@${entry.package_version} -> ${entry.route_id} (${entry.compatibility_mode})`,
    );
  }
  lines.push(
    "",
    "Claim boundary: exact pinned SDK-to-local-gateway compatibility only.",
    "Live provider behavior, arbitrary SDK releases, and direct-network non-bypassability are not proved.",
  );
  return `${lines.join("\n")}\n`;
}
