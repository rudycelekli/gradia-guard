import { readFileSync } from "node:fs";
import { canonicalJson, digestCanonical, isSha256 } from "./canonical.js";
import { assertModelPin, type GatewayPolicyDecisionInput } from "./gateway.js";
import type { SdkPolicyDecisionInput } from "./sdk.js";
import { assertStableId } from "./security.js";
import type { GatewayProvider, SdkToolIdentity } from "./types.js";

export const POLICY_SCHEMA_VERSION = "gradia.guard.policy.v1" as const;

export interface GuardModelRoutePolicy {
  provider: GatewayProvider;
  requested_model: string;
  authority_scope_ids: readonly string[];
  max_request_bytes: number;
  max_attempt_number: number;
}

export interface GuardToolRoutePolicy {
  registry_id: string;
  tool_id: string;
  tool_version: string;
  interface_sha256: string;
  authority_scope_ids: readonly string[];
  max_request_bytes: number;
  max_attempt_number: number;
}

export interface GuardPolicyBody {
  schema_version: typeof POLICY_SCHEMA_VERSION;
  policy_id: string;
  policy_version: string;
  default_decision: "blocked";
  model_routes: readonly GuardModelRoutePolicy[];
  tool_routes: readonly GuardToolRoutePolicy[];
}

export interface GuardPolicy extends GuardPolicyBody {
  policy_sha256: string;
}

export interface EvaluateModelPolicyInput {
  provider: GatewayProvider;
  requestedModel: string;
  requestByteLength: number;
  attemptNumber: number;
  authorityScopeIds: readonly string[];
}

export interface EvaluateToolPolicyInput {
  toolIdentity: SdkToolIdentity;
  requestByteLength: number;
  attemptNumber: number;
  authorityScopeIds: readonly string[];
}

export function starterPolicyBody(): GuardPolicyBody {
  return {
    schema_version: POLICY_SCHEMA_VERSION,
    policy_id: "local-starter",
    policy_version: "v1",
    default_decision: "blocked",
    model_routes: [],
    tool_routes: [],
  };
}

export function sealPolicy(body: GuardPolicyBody): GuardPolicy {
  validatePolicyBody(body);
  const cloned = JSON.parse(canonicalJson(body)) as GuardPolicyBody;
  return { ...cloned, policy_sha256: digestCanonical(cloned) };
}

export function loadPolicy(path: string): GuardPolicy {
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error("guard_policy_invalid_json");
  }
  const policy = requireObject(value, "guard_policy");
  assertExactKeys(
    policy,
    [
      "default_decision",
      "model_routes",
      "policy_id",
      "policy_sha256",
      "policy_version",
      "schema_version",
      "tool_routes",
    ],
    "guard_policy",
  );
  const supplied = policy["policy_sha256"];
  const body = {
    schema_version: policy["schema_version"],
    policy_id: policy["policy_id"],
    policy_version: policy["policy_version"],
    default_decision: policy["default_decision"],
    model_routes: policy["model_routes"],
    tool_routes: policy["tool_routes"],
  } as GuardPolicyBody;
  validatePolicyBody(body);
  if (!isSha256(supplied) || supplied !== digestCanonical(body)) {
    throw new Error("guard_policy_digest_mismatch");
  }
  return { ...body, policy_sha256: supplied };
}

export function evaluateModelPolicy(
  policy: GuardPolicy,
  input: EvaluateModelPolicyInput,
): GatewayPolicyDecisionInput {
  verifyPolicy(policy);
  validateEvaluationNumbers(input.requestByteLength, input.attemptNumber);
  const scopes = normalizedScopes(input.authorityScopeIds);
  const route = policy.model_routes.find(
    (candidate) =>
      candidate.provider === input.provider && candidate.requested_model === input.requestedModel,
  );
  const reasons: string[] = [];
  if (!route) reasons.push("model_route_not_allowed");
  if (route && !scopeSubset(scopes, route.authority_scope_ids)) {
    reasons.push("authority_scope_not_allowed");
  }
  if (route && input.requestByteLength > route.max_request_bytes) {
    reasons.push("request_bytes_exceeded");
  }
  if (route && input.attemptNumber > route.max_attempt_number) {
    reasons.push("attempt_limit_exceeded");
  }
  if (reasons.length > 0) {
    return {
      decision: "blocked",
      censorKind: "policy",
      reasonCodes: reasons.sort(),
      policySha256: policy.policy_sha256,
    };
  }
  return {
    decision: "allowed",
    censorKind: null,
    reasonCodes: ["authority_scopes_allowed", "model_route_allowed", "request_limits_allowed"],
    policySha256: policy.policy_sha256,
  };
}

export function evaluateToolPolicy(
  policy: GuardPolicy,
  input: EvaluateToolPolicyInput,
): SdkPolicyDecisionInput {
  verifyPolicy(policy);
  validateToolIdentity(input.toolIdentity);
  validateEvaluationNumbers(input.requestByteLength, input.attemptNumber);
  const scopes = normalizedScopes(input.authorityScopeIds);
  const route = policy.tool_routes.find(
    (candidate) =>
      candidate.registry_id === input.toolIdentity.registry_id &&
      candidate.tool_id === input.toolIdentity.tool_id &&
      candidate.tool_version === input.toolIdentity.tool_version &&
      candidate.interface_sha256 === input.toolIdentity.interface_sha256,
  );
  const reasons: string[] = [];
  if (!route) reasons.push("tool_route_not_allowed");
  if (route && !scopeSubset(scopes, route.authority_scope_ids)) {
    reasons.push("authority_scope_not_allowed");
  }
  if (route && input.requestByteLength > route.max_request_bytes) {
    reasons.push("request_bytes_exceeded");
  }
  if (route && input.attemptNumber > route.max_attempt_number) {
    reasons.push("attempt_limit_exceeded");
  }
  if (reasons.length > 0) {
    return {
      decision: "blocked",
      censorKind: reasons.includes("authority_scope_not_allowed") ? "authority" : "policy",
      reasonCodes: reasons.sort(),
      policySha256: policy.policy_sha256,
    };
  }
  return {
    decision: "allowed",
    censorKind: null,
    reasonCodes: ["authority_scopes_allowed", "request_limits_allowed", "tool_route_allowed"],
    policySha256: policy.policy_sha256,
  };
}

export function verifyPolicy(policy: GuardPolicy): void {
  const body: GuardPolicyBody = {
    schema_version: policy.schema_version,
    policy_id: policy.policy_id,
    policy_version: policy.policy_version,
    default_decision: policy.default_decision,
    model_routes: policy.model_routes,
    tool_routes: policy.tool_routes,
  };
  validatePolicyBody(body);
  if (!isSha256(policy.policy_sha256)) throw new Error("guard_policy_digest_invalid");
  if (policy.policy_sha256 !== digestCanonical(body)) throw new Error("guard_policy_digest_mismatch");
}

function validatePolicyBody(body: GuardPolicyBody): void {
  assertExactKeys(
    body as unknown as Record<string, unknown>,
    [
      "default_decision",
      "model_routes",
      "policy_id",
      "policy_version",
      "schema_version",
      "tool_routes",
    ],
    "guard_policy_body",
  );
  if (body.schema_version !== POLICY_SCHEMA_VERSION) throw new Error("guard_policy_schema_unsupported");
  assertStableId(body.policy_id, "guard_policy_id");
  assertStableId(body.policy_version, "guard_policy_version");
  if (body.default_decision !== "blocked") throw new Error("guard_policy_must_default_blocked");
  if (!Array.isArray(body.model_routes) || !Array.isArray(body.tool_routes)) {
    throw new Error("guard_policy_routes_invalid");
  }
  const modelKeys = new Set<string>();
  for (const route of body.model_routes) {
    validateModelRoute(route);
    const key = `${route.provider}\0${route.requested_model}`;
    if (modelKeys.has(key)) throw new Error("guard_policy_model_route_duplicate");
    modelKeys.add(key);
  }
  const toolKeys = new Set<string>();
  for (const route of body.tool_routes) {
    validateToolRoute(route);
    const key = `${route.registry_id}\0${route.tool_id}\0${route.tool_version}\0${route.interface_sha256}`;
    if (toolKeys.has(key)) throw new Error("guard_policy_tool_route_duplicate");
    toolKeys.add(key);
  }
}

function validateModelRoute(route: GuardModelRoutePolicy): void {
  assertExactKeys(
    route as unknown as Record<string, unknown>,
    ["authority_scope_ids", "max_attempt_number", "max_request_bytes", "provider", "requested_model"],
    "guard_policy_model_route",
  );
  if (!["anthropic", "openai", "xai", "gemini"].includes(route.provider)) {
    if (!route.provider.startsWith("custom:")) throw new Error("guard_policy_provider_invalid");
  }
  assertStableId(route.requested_model, "guard_policy_requested_model");
  assertModelPin(route.requested_model, "guard_policy_requested_model");
  normalizedScopes(route.authority_scope_ids);
  validateLimit(route.max_request_bytes, "guard_policy_max_request_bytes");
  validateLimit(route.max_attempt_number, "guard_policy_max_attempt_number");
}

function validateToolRoute(route: GuardToolRoutePolicy): void {
  assertExactKeys(
    route as unknown as Record<string, unknown>,
    [
      "authority_scope_ids",
      "interface_sha256",
      "max_attempt_number",
      "max_request_bytes",
      "registry_id",
      "tool_id",
      "tool_version",
    ],
    "guard_policy_tool_route",
  );
  validateToolIdentity({
    schema_version: "gradia.guard.sdk-tool-identity.v1",
    registry_id: route.registry_id,
    tool_id: route.tool_id,
    tool_version: route.tool_version,
    interface_sha256: route.interface_sha256,
  });
  normalizedScopes(route.authority_scope_ids);
  validateLimit(route.max_request_bytes, "guard_policy_max_request_bytes");
  validateLimit(route.max_attempt_number, "guard_policy_max_attempt_number");
}

function validateToolIdentity(identity: SdkToolIdentity): void {
  if (identity.schema_version !== "gradia.guard.sdk-tool-identity.v1") {
    throw new Error("guard_policy_tool_identity_schema_invalid");
  }
  assertStableId(identity.registry_id, "guard_policy_registry_id");
  assertStableId(identity.tool_id, "guard_policy_tool_id");
  assertStableId(identity.tool_version, "guard_policy_tool_version");
  if (/^(latest|current|default|auto)$/i.test(identity.tool_version)) {
    throw new Error("guard_policy_tool_version_unpinned");
  }
  if (!isSha256(identity.interface_sha256)) throw new Error("guard_policy_interface_digest_invalid");
}

function normalizedScopes(scopes: readonly string[]): readonly string[] {
  if (!Array.isArray(scopes) || scopes.length === 0) throw new Error("guard_policy_scopes_missing");
  for (const scope of scopes) assertStableId(scope, "guard_policy_scope_id");
  const normalized = [...new Set(scopes)].sort();
  if (normalized.length !== scopes.length || normalized.some((scope, index) => scope !== scopes[index])) {
    throw new Error("guard_policy_scopes_not_canonical");
  }
  return normalized;
}

function scopeSubset(requested: readonly string[], allowed: readonly string[]): boolean {
  const allowedSet = new Set(allowed);
  return requested.every((scope) => allowedSet.has(scope));
}

function validateEvaluationNumbers(requestByteLength: number, attemptNumber: number): void {
  if (!Number.isSafeInteger(requestByteLength) || requestByteLength < 0) {
    throw new Error("guard_policy_request_byte_length_invalid");
  }
  if (!Number.isSafeInteger(attemptNumber) || attemptNumber < 1) {
    throw new Error("guard_policy_attempt_number_invalid");
  }
}

function validateLimit(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${field}_invalid`);
}

function requireObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label}_invalid`);
  return value as Record<string, unknown>;
}

function assertExactKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...allowed].sort();
  if (canonicalJson(actual) !== canonicalJson(expected)) throw new Error(`${label}_keys_invalid`);
}
