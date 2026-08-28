import {
  createHash,
  randomBytes,
  timingSafeEqual,
  type KeyLike,
} from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { basename, isAbsolute, join } from "node:path";
import { canonicalJson, digestCanonical, isSha256, sha256 } from "./canonical.js";
import {
  LocalHttpEgressDispatcher,
  type GuardHttpEgressConfiguration,
  type GuardHttpEgressTransport,
} from "./http-egress.js";
import type { GuardPolicy } from "./policy.js";
import { requestedModelFromProviderRequest, type NativeGatewayProvider } from "./provider-adapters.js";
import { runGuardedProcessWithExplicitEnvironment } from "./run.js";
import { assertCommandSafe, assertStableId } from "./security.js";
import { loadManifest } from "./spool.js";
import type { GatewayEvidenceBundleManifest, VerificationResult } from "./types.js";
import { verifyBundle } from "./verify.js";
import { verifyGatewayBundle } from "./gateway-verify.js";
import {
  verifyWorkloadIdentity,
  type GuardWorkloadIdentity,
  type WorkloadIdentityExpectation,
} from "./workload-identity.js";

export const CREDENTIALLESS_RUNTIME_SCHEMA_VERSION =
  "gradia.guard.credentialless-child-runtime.v2" as const;
export const CREDENTIALLESS_RUNTIME_BOUNDARY_SCHEMA_VERSION =
  "gradia.guard.credentialless-child-boundary.v2" as const;

const LOCAL_REQUEST_MAX_BYTES = 16 * 1024 * 1024;
const INJECTED_ENVIRONMENT_NAMES = Object.freeze([
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_BASE_URL",
  "GEMINI_API_KEY",
  "GOOGLE_API_KEY",
  "GOOGLE_GEMINI_BASE_URL",
  "GRADIA_GUARD_LOCAL_CAPABILITY",
  "GRADIA_GUARD_LOCAL_ORIGIN",
  "GRADIA_GUARD_RUNTIME_ID",
  "OPENAI_API_KEY",
  "OPENAI_BASE_URL",
  "XAI_API_KEY",
  "XAI_BASE_URL",
]);

const NATIVE_PROVIDER_ROUTE_IDS = Object.freeze([
  "anthropic.messages",
  "gemini.generateContent",
  "openai.responses",
  "xai.responses",
]);

export interface CredentiallessChildBoundary {
  schema_version: typeof CREDENTIALLESS_RUNTIME_BOUNDARY_SCHEMA_VERSION;
  capture_boundary: "parent_owned_native_provider_loopback_gateway";
  parent_supplied_environment_mode: "fixed_guard_and_local_sdk_variables_only";
  provider_credentials_forwarded_in_child_argv: false;
  provider_credentials_forwarded_by_parent_environment: false;
  provider_sdk_auth_values_are_local_capability_only: true;
  native_provider_route_ids: readonly string[];
  operating_system_environment_additions_measured: false;
  local_gateway_authentication: "ephemeral_random_bearer";
  local_gateway_bind: "ipv4_loopback";
  direct_provider_credentials_retained_by: "parent_transport_closure";
  bypass_possible: true;
  bypass_declaration: "child_file_process_and_direct_network_routes_remain_unenforced";
  operating_system_process_isolation_proved: false;
  full_host_enforcement: false;
  kubernetes_network_policy_enforced: false;
  boundary_sha256: string;
}

export interface CredentiallessRuntimeBundleIdentity {
  session_id: string;
  frame_count: number;
  chain_head_sha256: string;
  verification_ok: boolean;
}

export interface CredentiallessRuntimeReceiptBody {
  schema_version: typeof CREDENTIALLESS_RUNTIME_SCHEMA_VERSION;
  runtime_id: string;
  boundary: CredentiallessChildBoundary;
  policy_sha256: string;
  configuration_sha256: string;
  workload_identity_sha256: string;
  gateway_enforcement_boundary_sha256: string;
  command_identity_sha256: string;
  process_bundle_name: string;
  process_bundle: CredentiallessRuntimeBundleIdentity;
  gateway_bundle: CredentiallessRuntimeBundleIdentity;
  environment_variable_names: readonly string[];
  environment_sha256: string;
  local_capability_sha256: string;
  local_origin: string;
  local_origin_sha256: string;
  accepted_local_requests: number;
  explicit_envelope_requests: number;
  native_provider_requests: number;
  unauthorized_local_requests: number;
  malformed_local_requests: number;
  child_exit_code: number;
  child_signal: string | null;
  finalized_at: string;
}

export interface CredentiallessRuntimeReceipt extends CredentiallessRuntimeReceiptBody {
  receipt_sha256: string;
}

export interface CredentiallessRuntimeVerification {
  ok: boolean;
  blockers: readonly string[];
  receipt_sha256: string | null;
  process: VerificationResult | null;
  gateway: VerificationResult | null;
}

export interface CredentiallessChildRuntimeOptions {
  directory: string;
  runtimeId?: string;
  command: readonly string[];
  cwd?: string;
  policy: GuardPolicy;
  configuration: GuardHttpEgressConfiguration;
  workloadIdentity: GuardWorkloadIdentity;
  trustedPublicKeys: Readonly<Record<string, KeyLike>>;
  workloadExpectation: Omit<WorkloadIdentityExpectation, "requiredAuthorityScopeIds">;
  maxIdentityLifetimeSeconds: number;
  clockSkewSeconds?: number;
  nowUnix?: () => number;
  transport: GuardHttpEgressTransport;
}

export interface CredentiallessChildRuntimeResult {
  directory: string;
  receipt: CredentiallessRuntimeReceipt;
  verification: CredentiallessRuntimeVerification;
}

interface LocalDispatchEnvelope {
  provider: "anthropic" | "openai" | "xai" | "gemini";
  target_url: string;
  request_body_base64: string;
  request_media_type: "application/json";
  requested_model_from_route: string | null;
  logical_request_id: string;
  attempt_number: number;
  retry_of_occurrence_sha256: string | null;
  authority_scope_ids: readonly string[];
}

export interface CredentiallessGatewayCounters {
  accepted: number;
  explicitEnvelope: number;
  nativeProvider: number;
  unauthorized: number;
  malformed: number;
}

interface NativeProviderRoute {
  provider: NativeGatewayProvider;
  targetUrl: string;
  requestedModelFromRoute: string | null;
  authorityScopeIds: readonly string[];
}

export function credentiallessChildBoundary(): CredentiallessChildBoundary {
  const body = {
    schema_version: CREDENTIALLESS_RUNTIME_BOUNDARY_SCHEMA_VERSION,
    capture_boundary: "parent_owned_native_provider_loopback_gateway" as const,
    parent_supplied_environment_mode: "fixed_guard_and_local_sdk_variables_only" as const,
    provider_credentials_forwarded_in_child_argv: false as const,
    provider_credentials_forwarded_by_parent_environment: false as const,
    provider_sdk_auth_values_are_local_capability_only: true as const,
    native_provider_route_ids: NATIVE_PROVIDER_ROUTE_IDS,
    operating_system_environment_additions_measured: false as const,
    local_gateway_authentication: "ephemeral_random_bearer" as const,
    local_gateway_bind: "ipv4_loopback" as const,
    direct_provider_credentials_retained_by: "parent_transport_closure" as const,
    bypass_possible: true as const,
    bypass_declaration:
      "child_file_process_and_direct_network_routes_remain_unenforced" as const,
    operating_system_process_isolation_proved: false as const,
    full_host_enforcement: false as const,
    kubernetes_network_policy_enforced: false as const,
  };
  return Object.freeze({ ...body, boundary_sha256: digestCanonical(body) });
}

export function verifyCredentiallessChildBoundary(boundary: CredentiallessChildBoundary): void {
  assertExactKeys(
    boundary as unknown as Record<string, unknown>,
    [
      "boundary_sha256",
      "bypass_declaration",
      "bypass_possible",
      "capture_boundary",
      "direct_provider_credentials_retained_by",
      "full_host_enforcement",
      "kubernetes_network_policy_enforced",
      "local_gateway_authentication",
      "local_gateway_bind",
      "operating_system_environment_additions_measured",
      "operating_system_process_isolation_proved",
      "parent_supplied_environment_mode",
      "provider_credentials_forwarded_by_parent_environment",
      "provider_credentials_forwarded_in_child_argv",
      "provider_sdk_auth_values_are_local_capability_only",
      "native_provider_route_ids",
      "schema_version",
    ],
    "credentialless_runtime_boundary",
  );
  if (canonicalJson(boundary) !== canonicalJson(credentiallessChildBoundary())) {
    throw new Error("credentialless_runtime_boundary_mismatch");
  }
}

export async function runProviderCredentiallessChild(
  options: CredentiallessChildRuntimeOptions,
): Promise<CredentiallessChildRuntimeResult> {
  if (existsSync(options.directory)) throw new Error("credentialless_runtime_directory_exists");
  if (options.command.length === 0 || !isAbsolute(options.command[0] as string)) {
    throw new Error("credentialless_runtime_absolute_command_required");
  }
  assertCommandSafe(options.command);
  mkdirSync(options.directory, { recursive: false, mode: 0o700 });
  const runtimeId = options.runtimeId ?? randomBytes(16).toString("hex");
  assertStableId(runtimeId, "credentialless_runtime_id");
  const localCapability = randomBytes(32).toString("base64url");
  const boundary = credentiallessChildBoundary();
  const nowUnix = options.nowUnix ?? (() => Math.floor(Date.now() / 1000));
  const verifiedIdentity = verifyWorkloadIdentity(options.workloadIdentity, {
    trustedPublicKeys: options.trustedPublicKeys,
    expectation: {
      ...options.workloadExpectation,
      requiredAuthorityScopeIds: options.workloadIdentity.claims.authority_scope_ids,
    },
    nowUnix: nowUnix(),
    maxLifetimeSeconds: options.maxIdentityLifetimeSeconds,
    clockSkewSeconds: options.clockSkewSeconds ?? 0,
  });
  const gatewayDirectory = join(options.directory, "model-gateway");
  const dispatcher = new LocalHttpEgressDispatcher({
    directory: gatewayDirectory,
    policy: options.policy,
    configuration: options.configuration,
    workloadIdentity: options.workloadIdentity,
    trustedPublicKeys: options.trustedPublicKeys,
    workloadExpectation: options.workloadExpectation,
    maxIdentityLifetimeSeconds: options.maxIdentityLifetimeSeconds,
    clockSkewSeconds: options.clockSkewSeconds ?? 0,
    nowUnix,
    transport: options.transport,
  });
  const counters: CredentiallessGatewayCounters = {
    accepted: 0,
    explicitEnvelope: 0,
    nativeProvider: 0,
    unauthorized: 0,
    malformed: 0,
  };
  const server = createProviderCredentiallessGatewayServer(
    dispatcher,
    localCapability,
    counters,
    options.policy,
    options.configuration,
    runtimeId,
    verifiedIdentity.claims.authority_scope_ids,
  );
  const port = await listenLoopback(server);
  const localOrigin = `http://127.0.0.1:${port}`;
  const environment = {
    ANTHROPIC_API_KEY: localCapability,
    ANTHROPIC_BASE_URL: `${localOrigin}/anthropic`,
    GEMINI_API_KEY: localCapability,
    GOOGLE_API_KEY: localCapability,
    GOOGLE_GEMINI_BASE_URL: `${localOrigin}/gemini`,
    GRADIA_GUARD_LOCAL_CAPABILITY: localCapability,
    GRADIA_GUARD_LOCAL_ORIGIN: localOrigin,
    GRADIA_GUARD_RUNTIME_ID: runtimeId,
    OPENAI_API_KEY: localCapability,
    OPENAI_BASE_URL: `${localOrigin}/openai/v1`,
    XAI_API_KEY: localCapability,
    XAI_BASE_URL: `${localOrigin}/xai/v1`,
  };
  const environmentSha256 = digestCanonical({
    entries: Object.entries(environment)
      .map(([name, value]) => ({ name, value_sha256: sha256(Buffer.from(value)) }))
      .sort((left, right) => left.name.localeCompare(right.name)),
  });
  let processDirectory: string | null = null;
  let childExitCode = 125;
  let childSignal: string | null = null;
  try {
    const child = await runGuardedProcessWithExplicitEnvironment(
      {
        command: options.command,
        outputRoot: join(options.directory, "process"),
        captureMode: "digest-only",
        ...(options.cwd ? { cwd: options.cwd } : {}),
        onBundle: (directory) => {
          processDirectory = directory;
        },
      },
      environment,
    );
    processDirectory = child.directory;
    childExitCode = child.exitCode;
    childSignal = child.signal;
  } finally {
    await closeServer(server);
    try {
      dispatcher.finalize();
    } catch (error) {
      if (!(error instanceof Error) || error.message !== "gateway_empty_bundle_cannot_finalize") {
        throw error;
      }
    }
  }
  if (processDirectory === null) throw new Error("credentialless_runtime_process_bundle_missing");
  const processVerification = verifyBundle(processDirectory);
  const gatewayVerification = verifyGatewayBundle(gatewayDirectory);
  const processManifest = loadManifest(processDirectory);
  const gatewayManifest = JSON.parse(
    readFileSync(join(gatewayDirectory, "bundle.json"), "utf8"),
  ) as GatewayEvidenceBundleManifest;
  const finalizedAt = new Date().toISOString();
  const body: CredentiallessRuntimeReceiptBody = {
    schema_version: CREDENTIALLESS_RUNTIME_SCHEMA_VERSION,
    runtime_id: runtimeId,
    boundary,
    policy_sha256: options.policy.policy_sha256,
    configuration_sha256: options.configuration.configuration_sha256,
    workload_identity_sha256: verifiedIdentity.identitySha256,
    gateway_enforcement_boundary_sha256: dispatcher.boundary.boundary_sha256,
    command_identity_sha256: processManifest.command_identity_sha256,
    process_bundle_name: basename(processDirectory),
    process_bundle: bundleIdentity(processVerification),
    gateway_bundle: bundleIdentity(gatewayVerification),
    environment_variable_names: INJECTED_ENVIRONMENT_NAMES,
    environment_sha256: environmentSha256,
    local_capability_sha256: sha256(Buffer.from(localCapability)),
    local_origin: localOrigin,
    local_origin_sha256: sha256(Buffer.from(localOrigin)),
    accepted_local_requests: counters.accepted,
    explicit_envelope_requests: counters.explicitEnvelope,
    native_provider_requests: counters.nativeProvider,
    unauthorized_local_requests: counters.unauthorized,
    malformed_local_requests: counters.malformed,
    child_exit_code: childExitCode,
    child_signal: childSignal,
    finalized_at: finalizedAt,
  };
  const receipt = { ...body, receipt_sha256: digestCanonical(body) };
  writeCanonicalAtomically(join(options.directory, "runtime.json"), receipt);
  return {
    directory: options.directory,
    receipt,
    verification: verifyCredentiallessRuntime(options.directory),
  };
}

export function verifyCredentiallessRuntime(directory: string): CredentiallessRuntimeVerification {
  let receipt: CredentiallessRuntimeReceipt;
  try {
    receipt = JSON.parse(readFileSync(join(directory, "runtime.json"), "utf8")) as CredentiallessRuntimeReceipt;
  } catch {
    return runtimeVerification(["credentialless_runtime_receipt_unreadable"], null, null, null);
  }
  const blockers: string[] = [];
  try {
    assertReceiptShape(receipt);
    verifyCredentiallessChildBoundary(receipt.boundary);
  } catch (error) {
    blockers.push(error instanceof Error ? error.message : "credentialless_runtime_receipt_invalid");
  }
  const { receipt_sha256: _digest, ...body } = receipt;
  if (!isSha256(receipt.receipt_sha256)) blockers.push("credentialless_runtime_receipt_digest_invalid");
  else if (receipt.receipt_sha256 !== digestCanonical(body)) {
    blockers.push("credentialless_runtime_receipt_digest_mismatch");
  }
  let process: VerificationResult | null = null;
  let gateway: VerificationResult | null = null;
  let processBundleDirectory: string | null = null;
  if (!/^[A-Za-z0-9_.-]{1,200}$/.test(receipt.process_bundle_name)) {
    blockers.push("credentialless_runtime_process_bundle_name_invalid");
  } else {
    processBundleDirectory = join(directory, "process", receipt.process_bundle_name);
    process = verifyBundle(processBundleDirectory);
    if (!process.ok) blockers.push("credentialless_runtime_process_bundle_invalid");
    if (canonicalJson(receipt.process_bundle) !== canonicalJson(bundleIdentity(process))) {
      blockers.push("credentialless_runtime_process_bundle_binding_mismatch");
    }
  }
  gateway = verifyGatewayBundle(join(directory, "model-gateway"));
  if (!gateway.ok) blockers.push("credentialless_runtime_gateway_bundle_invalid");
  if (canonicalJson(receipt.gateway_bundle) !== canonicalJson(bundleIdentity(gateway))) {
    blockers.push("credentialless_runtime_gateway_bundle_binding_mismatch");
  }
  try {
    const firstGatewayFrame = JSON.parse(
      readFileSync(join(directory, "model-gateway", "frames.ndjson"), "utf8").split("\n")[0] as string,
    ) as {
      frame_kind?: string;
      policy?: { policy_sha256?: string; reason_codes?: readonly string[] };
    };
    if (
      firstGatewayFrame.frame_kind !== "decision" ||
      firstGatewayFrame.policy?.policy_sha256 !== receipt.policy_sha256
    ) {
      blockers.push("credentialless_runtime_policy_binding_mismatch");
    }
    const reasons = firstGatewayFrame.policy?.reason_codes ?? [];
    if (!reasons.includes(`http_configuration_sha256:${receipt.configuration_sha256}`)) {
      blockers.push("credentialless_runtime_configuration_binding_mismatch");
    }
    if (!reasons.includes(`workload_identity_sha256:${receipt.workload_identity_sha256}`)) {
      blockers.push("credentialless_runtime_workload_identity_binding_mismatch");
    }
    if (
      !reasons.includes(
        `enforcement_boundary_sha256:${receipt.gateway_enforcement_boundary_sha256}`,
      )
    ) {
      blockers.push("credentialless_runtime_gateway_boundary_binding_mismatch");
    }
  } catch {
    blockers.push("credentialless_runtime_gateway_binding_unreadable");
  }
  if (processBundleDirectory !== null) {
    try {
      const processManifest = loadManifest(processBundleDirectory);
      if (processManifest.command_identity_sha256 !== receipt.command_identity_sha256) {
        blockers.push("credentialless_runtime_command_binding_mismatch");
      }
      if (
        processManifest.terminal_disposition !== "completed" ||
        receipt.child_exit_code !== 0 ||
        receipt.child_signal !== null
      ) {
        blockers.push("credentialless_runtime_child_not_completed");
      }
      const firstFrame = JSON.parse(
        readFileSync(join(processBundleDirectory, "frames.ndjson"), "utf8")
          .split("\n")[0] as string,
      ) as { decision?: { reason_codes?: readonly string[] } };
      const processReasons = firstFrame.decision?.reason_codes ?? [];
      if (!processReasons.includes("explicit_child_environment_enforced")) {
        blockers.push("credentialless_runtime_explicit_environment_receipt_missing");
      }
      if (!processReasons.includes(`explicit_environment_sha256:${receipt.environment_sha256}`)) {
        blockers.push("credentialless_runtime_environment_binding_mismatch");
      }
    } catch {
      blockers.push("credentialless_runtime_process_binding_unreadable");
    }
  }
  if (canonicalJson(receipt.environment_variable_names) !== canonicalJson(INJECTED_ENVIRONMENT_NAMES)) {
    blockers.push("credentialless_runtime_environment_names_mismatch");
  }
  const expectedEnvironmentSha256 = digestCanonical({
    entries: INJECTED_ENVIRONMENT_NAMES.map((name) => ({
      name,
      value_sha256:
        name === "GRADIA_GUARD_RUNTIME_ID"
          ? sha256(Buffer.from(receipt.runtime_id))
          : name === "GRADIA_GUARD_LOCAL_ORIGIN"
            ? receipt.local_origin_sha256
          : name.endsWith("BASE_URL")
            ? sha256(Buffer.from(providerBaseUrlValue(name, receipt.local_origin)))
            : receipt.local_capability_sha256,
    })).sort((left, right) => left.name.localeCompare(right.name)),
  });
  if (receipt.environment_sha256 !== expectedEnvironmentSha256) {
    blockers.push("credentialless_runtime_environment_composition_mismatch");
  }
  for (const digest of [
    receipt.policy_sha256,
    receipt.configuration_sha256,
    receipt.workload_identity_sha256,
    receipt.gateway_enforcement_boundary_sha256,
    receipt.command_identity_sha256,
    receipt.environment_sha256,
    receipt.local_capability_sha256,
    receipt.local_origin_sha256,
  ]) {
    if (!isSha256(digest)) blockers.push("credentialless_runtime_bound_digest_invalid");
  }
  if (receipt.accepted_local_requests !== (gateway?.frame_count ?? 0) / 2) {
    blockers.push("credentialless_runtime_accepted_request_count_mismatch");
  }
  if (
    receipt.accepted_local_requests !==
    receipt.explicit_envelope_requests + receipt.native_provider_requests
  ) {
    blockers.push("credentialless_runtime_request_kind_count_mismatch");
  }
  if (receipt.accepted_local_requests < 1) blockers.push("credentialless_runtime_no_model_dispatch");
  if (receipt.unauthorized_local_requests !== 0) {
    blockers.push("credentialless_runtime_unauthorized_local_request");
  }
  if (receipt.malformed_local_requests !== 0) {
    blockers.push("credentialless_runtime_malformed_local_request");
  }
  return runtimeVerification(
    [...new Set(blockers)].sort(),
    receipt.receipt_sha256,
    process,
    gateway,
  );
}

/**
 * Build the authenticated native-provider HTTP surface around an already
 * configured Guard dispatcher. The caller owns the socket, dispatcher
 * lifecycle, and capability delivery. This lets a root-owned sidecar run the
 * exact pre-dispatch path without inflating a loopback-child claim.
 */
export function createProviderCredentiallessGatewayServer(
  dispatcher: LocalHttpEgressDispatcher,
  capability: string,
  counters: CredentiallessGatewayCounters,
  policy: GuardPolicy,
  configuration: GuardHttpEgressConfiguration,
  runtimeId: string,
  workloadAuthorityScopeIds: readonly string[],
): Server {
  if (!/^[A-Za-z0-9_-]{24,512}$/.test(capability)) {
    throw new Error("credentialless_runtime_local_capability_invalid");
  }
  assertStableId(runtimeId, "credentialless_runtime_id");
  if (
    counters.accepted !== 0 ||
    counters.explicitEnvelope !== 0 ||
    counters.nativeProvider !== 0 ||
    counters.unauthorized !== 0 ||
    counters.malformed !== 0
  ) {
    throw new Error("credentialless_runtime_counters_not_empty");
  }
  return createServer(async (request, response) => {
    response.setHeader("cache-control", "no-store");
    response.setHeader("connection", "close");
    const requestUrl = exactLocalRequestUrl(request.url);
    if (request.method === "GET" && requestUrl?.pathname === "/health") {
      response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
      response.end("ok");
      return;
    }
    const explicitEnvelope = requestUrl?.pathname === "/v1/model-dispatch";
    const capabilityHeader = explicitEnvelope
      ? request.headers.authorization
      : nativeCapabilityHeader(request, requestUrl?.pathname ?? "");
    if (!matchesCapability(capabilityHeader, capability, explicitEnvelope)) {
      counters.unauthorized += 1;
      sendJson(response, 401, { error: "local_gateway_unauthorized" });
      return;
    }
    try {
      if (
        request.method !== "POST" ||
        requestUrl === null ||
        request.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase() !==
          "application/json"
      ) {
        throw new Error("credentialless_runtime_request_invalid");
      }
      const requestBody = await readIncomingRequest(request);
      const dispatchInput = explicitEnvelope
        ? explicitDispatchInput(requestBody)
        : nativeDispatchInput(
            requestUrl.pathname,
            requestBody,
            policy,
            configuration,
            `${runtimeId}-native-${counters.nativeProvider + 1}`,
            workloadAuthorityScopeIds,
          );
      const result = await dispatcher.dispatch(dispatchInput);
      counters.accepted += 1;
      if (explicitEnvelope) {
        counters.explicitEnvelope += 1;
        sendJson(response, result.disposition === "completed" ? 200 : 409, {
          disposition: result.disposition,
          occurrence_sha256: result.occurrenceSha256,
          response_body_base64:
            result.response === null
              ? null
              : Buffer.from(result.response.responseBody).toString("base64"),
          response_media_type: result.response?.responseMediaType ?? null,
          http_status: result.response?.httpStatus ?? null,
        });
        return;
      }
      counters.nativeProvider += 1;
      sendNativeProviderResponse(response, result);
    } catch (error) {
      counters.malformed += 1;
      sendJson(response, 400, {
        error: "local_gateway_request_invalid",
        reason_code: safeLocalGatewayReason(error),
      });
    }
  });
}

function safeLocalGatewayReason(error: unknown): string {
  const message = error instanceof Error ? error.message : "";
  return /^(?:credentialless_runtime|guard_)[A-Za-z0-9_.:-]{1,199}$/.test(message)
    ? message
    : "local_gateway_request_refused";
}

function explicitDispatchInput(value: Uint8Array) {
  const envelope = parseEnvelope(value);
  return {
    provider: envelope.provider,
    targetUrl: envelope.target_url,
    requestBody: decodeCanonicalBase64(envelope.request_body_base64),
    requestMediaType: envelope.request_media_type,
    requestedModelFromRoute: envelope.requested_model_from_route,
    logicalRequestId: envelope.logical_request_id,
    attemptNumber: envelope.attempt_number,
    retryOfOccurrenceSha256: envelope.retry_of_occurrence_sha256,
    authorityScopeIds: envelope.authority_scope_ids,
  };
}

function nativeDispatchInput(
  path: string,
  requestBody: Uint8Array,
  policy: GuardPolicy,
  configuration: GuardHttpEgressConfiguration,
  logicalRequestId: string,
  workloadAuthorityScopeIds: readonly string[],
) {
  const route = resolveNativeProviderRoute(
    path,
    requestBody,
    policy,
    configuration,
    workloadAuthorityScopeIds,
  );
  return {
    provider: route.provider,
    targetUrl: route.targetUrl,
    requestBody,
    requestMediaType: "application/json" as const,
    requestedModelFromRoute: route.requestedModelFromRoute,
    logicalRequestId,
    attemptNumber: 1,
    retryOfOccurrenceSha256: null,
    authorityScopeIds: route.authorityScopeIds,
  };
}

function resolveNativeProviderRoute(
  path: string,
  requestBody: Uint8Array,
  policy: GuardPolicy,
  configuration: GuardHttpEgressConfiguration,
  workloadAuthorityScopeIds: readonly string[],
): NativeProviderRoute {
  let provider: NativeGatewayProvider;
  let upstreamPath: string;
  let requestedModelFromRoute: string | null = null;
  if (path === "/openai/v1/responses") {
    provider = "openai";
    upstreamPath = "/v1/responses";
  } else if (path === "/xai/v1/responses") {
    provider = "xai";
    upstreamPath = "/v1/responses";
  } else if (path === "/anthropic/v1/messages") {
    provider = "anthropic";
    upstreamPath = "/v1/messages";
  } else {
    const gemini = /^\/gemini\/v1beta\/models\/([A-Za-z0-9._:-]{1,200}):generateContent$/.exec(
      path,
    );
    if (!gemini?.[1]) throw new Error("credentialless_runtime_native_route_invalid");
    provider = "gemini";
    requestedModelFromRoute = decodeURIComponent(gemini[1]);
    assertStableId(requestedModelFromRoute, "credentialless_runtime_gemini_model");
    upstreamPath = `/v1beta/models/${requestedModelFromRoute}:generateContent`;
  }
  const requestedModel = requestedModelFromProviderRequest(
    provider,
    requestBody,
    requestedModelFromRoute,
  );
  const configuredRoutes = configuration.model_routes.filter((candidate) => {
    if (candidate.provider !== provider) return false;
    return new URL(candidate.target_url).pathname === upstreamPath;
  });
  if (configuredRoutes.length > 1) {
    throw new Error("credentialless_runtime_native_route_ambiguous");
  }
  const configuredRoute = configuredRoutes[0];
  const policyRoute = policy.model_routes.find(
    (candidate) =>
      candidate.provider === provider && candidate.requested_model === requestedModel,
  );
  const authorityScopeIds = policyRoute
    ? [...policyRoute.authority_scope_ids]
    : [...workloadAuthorityScopeIds];
  return {
    provider,
    targetUrl:
      configuredRoute?.target_url ?? `https://${provider}.blocked.invalid${upstreamPath}`,
    requestedModelFromRoute,
    authorityScopeIds,
  };
}

function exactLocalRequestUrl(value: string | undefined): URL | null {
  if (!value || value.includes("\\")) return null;
  let parsed: URL;
  try {
    parsed = new URL(value, "http://guard.local");
  } catch {
    return null;
  }
  if (parsed.origin !== "http://guard.local" || parsed.search || parsed.hash) return null;
  return parsed;
}

function nativeCapabilityHeader(request: IncomingMessage, path: string): string | undefined {
  if (path.startsWith("/openai/") || path.startsWith("/xai/")) {
    return request.headers.authorization;
  }
  if (path.startsWith("/anthropic/")) return singleHeader(request.headers["x-api-key"]);
  if (path.startsWith("/gemini/")) return singleHeader(request.headers["x-goog-api-key"]);
  return undefined;
}

function singleHeader(value: string | string[] | undefined): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function sendNativeProviderResponse(
  response: ServerResponse,
  result: Awaited<ReturnType<LocalHttpEgressDispatcher["dispatch"]>>,
): void {
  response.setHeader("x-gradia-occurrence-sha256", result.occurrenceSha256);
  if (result.disposition === "completed" && result.response !== null) {
    response.statusCode = result.response.httpStatus;
    response.setHeader("content-type", result.response.responseMediaType);
    response.end(Buffer.from(result.response.responseBody));
    return;
  }
  const status = result.disposition === "blocked" ? 403 : 502;
  sendJson(response, status, {
    error: {
      code: `gradia_${result.disposition}`,
      occurrence_sha256: result.occurrenceSha256,
      type: "gradia_guard_refusal",
    },
  });
}

function parseEnvelope(value: Uint8Array): LocalDispatchEnvelope {
  const parsed = JSON.parse(Buffer.from(value).toString("utf8")) as Record<string, unknown>;
  assertExactKeys(
    parsed,
    [
      "attempt_number",
      "authority_scope_ids",
      "logical_request_id",
      "provider",
      "request_body_base64",
      "request_media_type",
      "requested_model_from_route",
      "retry_of_occurrence_sha256",
      "target_url",
    ],
    "credentialless_runtime_local_request",
  );
  if (!["anthropic", "openai", "xai", "gemini"].includes(String(parsed["provider"]))) {
    throw new Error("credentialless_runtime_provider_invalid");
  }
  if (typeof parsed["target_url"] !== "string") {
    throw new Error("credentialless_runtime_target_invalid");
  }
  if (typeof parsed["request_body_base64"] !== "string") {
    throw new Error("credentialless_runtime_request_body_invalid");
  }
  decodeCanonicalBase64(parsed["request_body_base64"]);
  if (parsed["request_media_type"] !== "application/json") {
    throw new Error("credentialless_runtime_media_type_invalid");
  }
  if (
    parsed["requested_model_from_route"] !== null &&
    typeof parsed["requested_model_from_route"] !== "string"
  ) {
    throw new Error("credentialless_runtime_model_route_invalid");
  }
  if (typeof parsed["logical_request_id"] !== "string") {
    throw new Error("credentialless_runtime_logical_request_invalid");
  }
  assertStableId(parsed["logical_request_id"], "credentialless_runtime_logical_request_id");
  if (
    !Number.isSafeInteger(parsed["attempt_number"]) ||
    Number(parsed["attempt_number"]) < 1
  ) {
    throw new Error("credentialless_runtime_attempt_invalid");
  }
  if (
    parsed["retry_of_occurrence_sha256"] !== null &&
    !isSha256(parsed["retry_of_occurrence_sha256"])
  ) {
    throw new Error("credentialless_runtime_retry_invalid");
  }
  if (
    !Array.isArray(parsed["authority_scope_ids"]) ||
    !parsed["authority_scope_ids"].every((item) => typeof item === "string")
  ) {
    throw new Error("credentialless_runtime_scope_invalid");
  }
  return parsed as unknown as LocalDispatchEnvelope;
}

async function readIncomingRequest(request: IncomingMessage): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const value of request) {
    const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
    length += chunk.length;
    if (length > LOCAL_REQUEST_MAX_BYTES) throw new Error("credentialless_runtime_request_too_large");
    chunks.push(chunk);
  }
  if (length === 0) throw new Error("credentialless_runtime_request_empty");
  return Buffer.concat(chunks);
}

function decodeCanonicalBase64(value: string): Uint8Array {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error("credentialless_runtime_request_base64_invalid");
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.length === 0 || decoded.toString("base64") !== value) {
    throw new Error("credentialless_runtime_request_base64_invalid");
  }
  return decoded;
}

function matchesCapability(
  header: string | undefined,
  capability: string,
  bearerRequired: boolean,
): boolean {
  const supplied =
    typeof header !== "string"
      ? ""
      : bearerRequired
        ? header.startsWith("Bearer ")
          ? header.slice(7)
          : ""
        : header.startsWith("Bearer ")
          ? header.slice(7)
          : header;
  const expectedDigest = createHash("sha256").update(capability).digest();
  const suppliedDigest = createHash("sha256").update(supplied).digest();
  return supplied.length > 0 && timingSafeEqual(expectedDigest, suppliedDigest);
}

function providerBaseUrlValue(name: string, localOrigin: string): string {
  if (name === "ANTHROPIC_BASE_URL") return `${localOrigin}/anthropic`;
  if (name === "GOOGLE_GEMINI_BASE_URL") return `${localOrigin}/gemini`;
  if (name === "OPENAI_BASE_URL") return `${localOrigin}/openai/v1`;
  if (name === "XAI_BASE_URL") return `${localOrigin}/xai/v1`;
  throw new Error("credentialless_runtime_sdk_base_url_name_invalid");
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  response.statusCode = status;
  response.setHeader("content-type", "application/json");
  response.end(`${canonicalJson(body)}\n`);
}

async function listenLoopback(server: Server): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("credentialless_runtime_loopback_bind_failed");
  }
  return address.port;
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

function bundleIdentity(verification: VerificationResult): CredentiallessRuntimeBundleIdentity {
  return {
    session_id: verification.session_id ?? "unverified",
    frame_count: verification.frame_count,
    chain_head_sha256: verification.chain_head_sha256 ?? "0".repeat(64),
    verification_ok: verification.ok,
  };
}

function assertReceiptShape(receipt: CredentiallessRuntimeReceipt): void {
  assertExactKeys(
    receipt as unknown as Record<string, unknown>,
    [
      "accepted_local_requests",
      "boundary",
      "child_exit_code",
      "child_signal",
      "command_identity_sha256",
      "configuration_sha256",
      "environment_sha256",
      "environment_variable_names",
      "explicit_envelope_requests",
      "finalized_at",
      "gateway_enforcement_boundary_sha256",
      "gateway_bundle",
      "local_capability_sha256",
      "local_origin",
      "local_origin_sha256",
      "malformed_local_requests",
      "native_provider_requests",
      "policy_sha256",
      "process_bundle",
      "process_bundle_name",
      "receipt_sha256",
      "runtime_id",
      "schema_version",
      "unauthorized_local_requests",
      "workload_identity_sha256",
    ],
    "credentialless_runtime_receipt",
  );
  if (receipt.schema_version !== CREDENTIALLESS_RUNTIME_SCHEMA_VERSION) {
    throw new Error("credentialless_runtime_schema_unsupported");
  }
  assertStableId(receipt.runtime_id, "credentialless_runtime_id");
  if (!/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(receipt.local_origin)) {
    throw new Error("credentialless_runtime_local_origin_invalid");
  }
  const port = Number(new URL(receipt.local_origin).port);
  if (port > 65_535 || sha256(Buffer.from(receipt.local_origin)) !== receipt.local_origin_sha256) {
    throw new Error("credentialless_runtime_local_origin_binding_invalid");
  }
  for (const [label, value] of [
    ["accepted", receipt.accepted_local_requests],
    ["explicit_envelope", receipt.explicit_envelope_requests],
    ["native_provider", receipt.native_provider_requests],
    ["unauthorized", receipt.unauthorized_local_requests],
    ["malformed", receipt.malformed_local_requests],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`credentialless_runtime_${label}_count_invalid`);
    }
  }
  if (!Number.isSafeInteger(receipt.child_exit_code) || receipt.child_exit_code < 0) {
    throw new Error("credentialless_runtime_child_exit_invalid");
  }
  if (receipt.child_signal !== null && !/^SIG[A-Z0-9]+$/.test(receipt.child_signal)) {
    throw new Error("credentialless_runtime_child_signal_invalid");
  }
  if (
    !Number.isFinite(Date.parse(receipt.finalized_at)) ||
    new Date(receipt.finalized_at).toISOString() !== receipt.finalized_at
  ) {
    throw new Error("credentialless_runtime_finalized_at_invalid");
  }
}

function runtimeVerification(
  blockers: readonly string[],
  receiptSha256: string | null,
  process: VerificationResult | null,
  gateway: VerificationResult | null,
): CredentiallessRuntimeVerification {
  return { ok: blockers.length === 0, blockers, receipt_sha256: receiptSha256, process, gateway };
}

function assertExactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (canonicalJson(actual) !== canonicalJson(wanted)) throw new Error(`${label}_keys_invalid`);
}

function writeCanonicalAtomically(path: string, value: unknown): void {
  const temporary = `${path}.tmp`;
  writeFileSync(temporary, `${canonicalJson(value)}\n`, { encoding: "utf8", mode: 0o600 });
  renameSync(temporary, path);
}
