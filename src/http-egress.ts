import type { KeyLike } from "node:crypto";
import { canonicalJson, digestCanonical, isSha256 } from "./canonical.js";
import {
  enforcementBoundary,
  verifyEnforcementBoundary,
  type GuardEnforcementBoundary,
} from "./enforcement-boundary.js";
import {
  GatewayIdentityMismatchError,
  GatewayRecorder,
  type GatewayPolicyDecisionInput,
} from "./gateway.js";
import { evaluateModelPolicy, verifyPolicy, type GuardPolicy } from "./policy.js";
import {
  completeProviderAttempt,
  failProviderTransport,
  prepareProviderAttempt,
  requestedModelFromProviderRequest,
  type NativeGatewayProvider,
  type PreparedProviderAttempt,
} from "./provider-adapters.js";
import { assertStableId } from "./security.js";
import type { GatewayActionFrame, GatewayProvider } from "./types.js";
import {
  verifyWorkloadIdentity,
  type GuardWorkloadIdentity,
  type WorkloadIdentityExpectation,
} from "./workload-identity.js";

export const HTTP_EGRESS_CONFIGURATION_SCHEMA_VERSION =
  "gradia.guard.local-http-egress-configuration.v1" as const;

export interface GuardHttpModelRoute {
  provider: NativeGatewayProvider;
  target_url: string;
  method: "POST";
  request_media_type: "application/json";
  redirect_mode: "error";
  timeout_ms: number;
  max_response_bytes: number;
}

export interface GuardHttpEgressConfigurationBody {
  schema_version: typeof HTTP_EGRESS_CONFIGURATION_SCHEMA_VERSION;
  configuration_id: string;
  configuration_version: string;
  default_decision: "blocked";
  model_routes: readonly GuardHttpModelRoute[];
}

export interface GuardHttpEgressConfiguration extends GuardHttpEgressConfigurationBody {
  configuration_sha256: string;
}

export interface LocalHttpEgressDispatcherOptions {
  directory: string;
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

export interface LocalHttpEgressRequest {
  provider: NativeGatewayProvider;
  targetUrl: string;
  requestBody: Uint8Array;
  requestMediaType: "application/json";
  requestedModelFromRoute: string | null;
  logicalRequestId: string;
  attemptNumber: number;
  retryOfOccurrenceSha256: string | null;
  authorityScopeIds: readonly string[];
}

export interface GuardHttpTransportInput {
  provider: NativeGatewayProvider;
  targetUrl: string;
  method: "POST";
  requestBody: Uint8Array;
  requestMediaType: "application/json";
  requestedModel: string;
  timeoutMs: number;
  maxResponseBytes: number;
}

export interface GuardHttpTransportResponse {
  responseBody: Uint8Array;
  responseMediaType: string;
  httpStatus: number;
  finalUrl: string;
  redirected: boolean;
}

export type GuardHttpEgressTransport = (
  input: GuardHttpTransportInput,
) => Promise<GuardHttpTransportResponse>;

export interface LocalHttpEgressResult {
  disposition:
    | "blocked"
    | "completed"
    | "provider_failure"
    | "transport_failure"
    | "protocol_failure"
    | "identity_mismatch";
  occurrenceSha256: string;
  identitySha256: string | null;
  action: GatewayActionFrame | null;
  response: GuardHttpTransportResponse | null;
  boundary: GuardEnforcementBoundary;
}

export interface NoRedirectFetchTransportOptions {
  fetchImpl?: typeof fetch;
  credentialHeaders?: (
    input: Readonly<{ provider: NativeGatewayProvider; targetUrl: string }>,
  ) => Promise<Readonly<Record<string, string>>> | Readonly<Record<string, string>>;
}

export function sealHttpEgressConfiguration(
  body: GuardHttpEgressConfigurationBody,
): GuardHttpEgressConfiguration {
  validateConfigurationBody(body);
  const cloned = JSON.parse(canonicalJson(body)) as GuardHttpEgressConfigurationBody;
  return { ...cloned, configuration_sha256: digestCanonical(cloned) };
}

export function verifyHttpEgressConfiguration(configuration: GuardHttpEgressConfiguration): void {
  assertExactKeys(
    configuration as unknown as Record<string, unknown>,
    [
      "configuration_id",
      "configuration_sha256",
      "configuration_version",
      "default_decision",
      "model_routes",
      "schema_version",
    ],
    "guard_http_egress_configuration",
  );
  const body: GuardHttpEgressConfigurationBody = {
    schema_version: configuration.schema_version,
    configuration_id: configuration.configuration_id,
    configuration_version: configuration.configuration_version,
    default_decision: configuration.default_decision,
    model_routes: configuration.model_routes,
  };
  validateConfigurationBody(body);
  if (!isSha256(configuration.configuration_sha256)) {
    throw new Error("guard_http_egress_configuration_digest_invalid");
  }
  if (configuration.configuration_sha256 !== digestCanonical(body)) {
    throw new Error("guard_http_egress_configuration_digest_mismatch");
  }
}

export class LocalHttpEgressDispatcher {
  readonly recorder: GatewayRecorder;
  readonly boundary: GuardEnforcementBoundary;
  private readonly policy: GuardPolicy;
  private readonly configuration: GuardHttpEgressConfiguration;
  private readonly workloadIdentity: GuardWorkloadIdentity;
  private readonly trustedPublicKeys: Readonly<Record<string, KeyLike>>;
  private readonly workloadExpectation: Omit<
    WorkloadIdentityExpectation,
    "requiredAuthorityScopeIds"
  >;
  private readonly maxIdentityLifetimeSeconds: number;
  private readonly clockSkewSeconds: number;
  private readonly nowUnix: () => number;
  private readonly transport: GuardHttpEgressTransport;
  private finalized = false;

  constructor(options: LocalHttpEgressDispatcherOptions) {
    verifyPolicy(options.policy);
    verifyHttpEgressConfiguration(options.configuration);
    if (options.workloadExpectation.policySha256 !== options.policy.policy_sha256) {
      throw new Error("guard_http_egress_expected_policy_mismatch");
    }
    if (
      options.workloadExpectation.configurationSha256 !==
      options.configuration.configuration_sha256
    ) {
      throw new Error("guard_http_egress_expected_configuration_mismatch");
    }
    this.policy = JSON.parse(canonicalJson(options.policy)) as GuardPolicy;
    this.configuration = JSON.parse(
      canonicalJson(options.configuration),
    ) as GuardHttpEgressConfiguration;
    this.workloadIdentity = JSON.parse(
      canonicalJson(options.workloadIdentity),
    ) as GuardWorkloadIdentity;
    this.trustedPublicKeys = options.trustedPublicKeys;
    this.workloadExpectation = JSON.parse(
      canonicalJson(options.workloadExpectation),
    ) as Omit<WorkloadIdentityExpectation, "requiredAuthorityScopeIds">;
    this.maxIdentityLifetimeSeconds = options.maxIdentityLifetimeSeconds;
    this.clockSkewSeconds = options.clockSkewSeconds ?? 0;
    this.nowUnix = options.nowUnix ?? (() => Math.floor(Date.now() / 1000));
    this.transport = options.transport;
    this.boundary = enforcementBoundary("local_http_proxy");
    verifyEnforcementBoundary(this.boundary);
    this.recorder = new GatewayRecorder({ directory: options.directory });
  }

  async dispatch(input: LocalHttpEgressRequest): Promise<LocalHttpEgressResult> {
    if (this.finalized) throw new Error("guard_http_egress_dispatcher_finalized");
    assertExactKeys(
      input as unknown as Record<string, unknown>,
      [
        "attemptNumber",
        "authorityScopeIds",
        "logicalRequestId",
        "provider",
        "requestBody",
        "requestMediaType",
        "requestedModelFromRoute",
        "retryOfOccurrenceSha256",
        "targetUrl",
      ],
      "guard_http_egress_request",
    );
    const requestedModel = requestedModelFromProviderRequest(
      input.provider,
      input.requestBody,
      input.requestedModelFromRoute,
    );
    const route = this.route(input.provider, input.targetUrl, input.requestMediaType);
    const authorization = this.authorize(input, requestedModel, route);
    const prepared = prepareProviderAttempt(this.recorder, {
      provider: input.provider,
      requestBody: input.requestBody,
      requestMediaType: input.requestMediaType,
      requestedModelFromRoute: input.requestedModelFromRoute,
      logicalRequestId: input.logicalRequestId,
      attemptNumber: input.attemptNumber,
      retryOfOccurrenceSha256: input.retryOfOccurrenceSha256,
      policy: authorization.policy,
    });
    if (prepared.attempt.censored || route === null) {
      return this.result(
        "blocked",
        prepared.attempt.occurrenceSha256,
        authorization.identitySha256,
        null,
        null,
      );
    }

    prepared.attempt.markDispatched();
    let response: GuardHttpTransportResponse;
    try {
      response = await this.transport({
        provider: input.provider,
        targetUrl: route.target_url,
        method: route.method,
        requestBody: input.requestBody,
        requestMediaType: route.request_media_type,
        requestedModel,
        timeoutMs: route.timeout_ms,
        maxResponseBytes: route.max_response_bytes,
      });
    } catch {
      const action = failProviderTransport(prepared, "upstream_transport_failure");
      return this.result(
        "transport_failure",
        prepared.attempt.occurrenceSha256,
        authorization.identitySha256,
        action,
        null,
      );
    }

    try {
      validateTransportResponse(response);
    } catch {
      const action = failProviderTransport(prepared, "upstream_transport_contract_invalid");
      return this.result(
        "transport_failure",
        prepared.attempt.occurrenceSha256,
        authorization.identitySha256,
        action,
        null,
      );
    }

    if (
      response.redirected ||
      (response.httpStatus >= 300 && response.httpStatus <= 399) ||
      response.finalUrl !== route.target_url
    ) {
      const action = protocolFailure(
        prepared,
        response,
        response.finalUrl !== route.target_url
          ? "upstream_final_url_mismatch"
          : "upstream_redirect_refused",
      );
      return this.result(
        "protocol_failure",
        prepared.attempt.occurrenceSha256,
        authorization.identitySha256,
        action,
        null,
      );
    }
    if (response.responseBody.byteLength > route.max_response_bytes) {
      const action = protocolFailure(prepared, response, "upstream_response_bytes_exceeded");
      return this.result(
        "protocol_failure",
        prepared.attempt.occurrenceSha256,
        authorization.identitySha256,
        action,
        null,
      );
    }

    try {
      const action = completeProviderAttempt(prepared, response);
      if (action.outcome === "provider_failure") {
        return this.result(
          "provider_failure",
          prepared.attempt.occurrenceSha256,
          authorization.identitySha256,
          action,
          null,
        );
      }
      if (action.outcome === "protocol_failure") {
        return this.result(
          "protocol_failure",
          prepared.attempt.occurrenceSha256,
          authorization.identitySha256,
          action,
          null,
        );
      }
      return this.result(
        "completed",
        prepared.attempt.occurrenceSha256,
        authorization.identitySha256,
        action,
        response,
      );
    } catch (error) {
      if (error instanceof GatewayIdentityMismatchError) {
        return this.result(
          "identity_mismatch",
          prepared.attempt.occurrenceSha256,
          authorization.identitySha256,
          error.frame,
          null,
        );
      }
      throw error;
    }
  }

  finalize(): void {
    if (this.finalized) return;
    this.recorder.finalize();
    this.finalized = true;
  }

  private route(
    provider: NativeGatewayProvider,
    targetUrl: string,
    requestMediaType: string,
  ): GuardHttpModelRoute | null {
    return (
      this.configuration.model_routes.find(
        (candidate) =>
          candidate.provider === provider &&
          candidate.target_url === targetUrl &&
          candidate.request_media_type === requestMediaType,
      ) ?? null
    );
  }

  private authorize(
    input: LocalHttpEgressRequest,
    requestedModel: string,
    route: GuardHttpModelRoute | null,
  ): { policy: GatewayPolicyDecisionInput; identitySha256: string | null } {
    const reasons: string[] = [
      `enforcement_boundary_sha256:${this.boundary.boundary_sha256}`,
      `http_configuration_sha256:${this.configuration.configuration_sha256}`,
    ];
    let identitySha256: string | null = null;
    try {
      const verified = verifyWorkloadIdentity(this.workloadIdentity, {
        trustedPublicKeys: this.trustedPublicKeys,
        expectation: {
          ...this.workloadExpectation,
          requiredAuthorityScopeIds: input.authorityScopeIds,
        },
        nowUnix: this.nowUnix(),
        maxLifetimeSeconds: this.maxIdentityLifetimeSeconds,
        clockSkewSeconds: this.clockSkewSeconds,
      });
      identitySha256 = verified.identitySha256;
      reasons.push(`workload_identity_sha256:${identitySha256}`);
    } catch {
      reasons.push("workload_identity_refused");
    }
    if (route === null) reasons.push("http_egress_route_not_allowed");
    const evaluated = evaluateModelPolicy(this.policy, {
      provider: input.provider as GatewayProvider,
      requestedModel,
      requestByteLength: input.requestBody.byteLength,
      attemptNumber: input.attemptNumber,
      authorityScopeIds: input.authorityScopeIds,
    });
    reasons.push(...evaluated.reasonCodes);
    const allowed = identitySha256 !== null && route !== null && evaluated.decision === "allowed";
    return {
      policy: {
        decision: allowed ? "allowed" : "blocked",
        censorKind: allowed ? null : "policy",
        reasonCodes: [...new Set(reasons)].sort(),
        policySha256: this.policy.policy_sha256,
      },
      identitySha256,
    };
  }

  private result(
    disposition: LocalHttpEgressResult["disposition"],
    occurrenceSha256: string,
    identitySha256: string | null,
    action: GatewayActionFrame | null,
    response: GuardHttpTransportResponse | null,
  ): LocalHttpEgressResult {
    return {
      disposition,
      occurrenceSha256,
      identitySha256,
      action,
      response,
      boundary: this.boundary,
    };
  }
}

export function createNoRedirectFetchTransport(
  options: NoRedirectFetchTransportOptions = {},
): GuardHttpEgressTransport {
  const fetchImpl = options.fetchImpl ?? fetch;
  return async (input) => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), input.timeoutMs);
    try {
      const secretHeaders = (await options.credentialHeaders?.({
        provider: input.provider,
        targetUrl: input.targetUrl,
      })) ?? {};
      const headers = safeTransportHeaders(input.provider, secretHeaders);
      headers.set("content-type", input.requestMediaType);
      const response = await fetchImpl(input.targetUrl, {
        method: input.method,
        headers,
        body: Buffer.from(input.requestBody),
        redirect: "manual",
        signal: controller.signal,
      });
      if (!response.url) throw new Error("guard_http_transport_final_url_missing");
      const responseBody = await readLimitedBody(response, input.maxResponseBytes);
      return {
        responseBody,
        responseMediaType: response.headers.get("content-type") ?? "application/octet-stream",
        httpStatus: response.status,
        finalUrl: response.url,
        redirected: response.redirected,
      };
    } finally {
      clearTimeout(timeout);
    }
  };
}

function protocolFailure(
  prepared: PreparedProviderAttempt,
  response: GuardHttpTransportResponse,
  failureCode: string,
): GatewayActionFrame {
  return prepared.attempt.fail({
    outcome: "protocol_failure",
    responseBody: response.responseBody,
    responseMediaType: response.responseMediaType,
    resolvedModel: null,
    usage: null,
    httpStatus: response.httpStatus,
    failureCode,
  });
}

function validateConfigurationBody(body: GuardHttpEgressConfigurationBody): void {
  assertExactKeys(
    body as unknown as Record<string, unknown>,
    [
      "configuration_id",
      "configuration_version",
      "default_decision",
      "model_routes",
      "schema_version",
    ],
    "guard_http_egress_configuration_body",
  );
  if (body.schema_version !== HTTP_EGRESS_CONFIGURATION_SCHEMA_VERSION) {
    throw new Error("guard_http_egress_configuration_schema_unsupported");
  }
  assertStableId(body.configuration_id, "guard_http_egress_configuration_id");
  assertStableId(body.configuration_version, "guard_http_egress_configuration_version");
  if (body.default_decision !== "blocked") {
    throw new Error("guard_http_egress_configuration_must_default_blocked");
  }
  if (!Array.isArray(body.model_routes)) throw new Error("guard_http_egress_routes_invalid");
  const routeKeys = new Set<string>();
  for (const route of body.model_routes) {
    validateHttpRoute(route);
    const key = `${route.provider}\0${route.target_url}`;
    if (routeKeys.has(key)) throw new Error("guard_http_egress_route_duplicate");
    routeKeys.add(key);
  }
}

function validateHttpRoute(route: GuardHttpModelRoute): void {
  assertExactKeys(
    route as unknown as Record<string, unknown>,
    [
      "max_response_bytes",
      "method",
      "provider",
      "redirect_mode",
      "request_media_type",
      "target_url",
      "timeout_ms",
    ],
    "guard_http_egress_route",
  );
  if (!["anthropic", "openai", "xai", "gemini"].includes(route.provider)) {
    throw new Error("guard_http_egress_provider_invalid");
  }
  validateExactTargetUrl(route.target_url);
  if (route.method !== "POST") throw new Error("guard_http_egress_method_invalid");
  if (route.request_media_type !== "application/json") {
    throw new Error("guard_http_egress_request_media_type_invalid");
  }
  if (route.redirect_mode !== "error") throw new Error("guard_http_egress_redirect_mode_invalid");
  validatePositiveInteger(route.timeout_ms, "guard_http_egress_timeout_ms");
  validatePositiveInteger(route.max_response_bytes, "guard_http_egress_max_response_bytes");
}

function validateExactTargetUrl(value: string): void {
  let target: URL;
  try {
    target = new URL(value);
  } catch {
    throw new Error("guard_http_egress_target_url_invalid");
  }
  const loopback = ["localhost", "127.0.0.1", "::1"].includes(target.hostname);
  if (target.protocol !== "https:" && !(target.protocol === "http:" && loopback)) {
    throw new Error("guard_http_egress_target_requires_https");
  }
  if (
    target.username ||
    target.password ||
    target.search ||
    target.hash ||
    target.toString() !== value ||
    value.includes("\\")
  ) {
    throw new Error("guard_http_egress_target_url_not_canonical");
  }
}

function validateTransportResponse(response: GuardHttpTransportResponse): void {
  assertExactKeys(
    response as unknown as Record<string, unknown>,
    ["finalUrl", "httpStatus", "redirected", "responseBody", "responseMediaType"],
    "guard_http_transport_response",
  );
  if (!(response.responseBody instanceof Uint8Array) || response.responseBody.byteLength === 0) {
    throw new Error("guard_http_transport_response_body_invalid");
  }
  if (!/^[\x20-\x7e]{1,200}$/.test(response.responseMediaType)) {
    throw new Error("guard_http_transport_response_media_type_invalid");
  }
  if (!Number.isSafeInteger(response.httpStatus) || response.httpStatus < 100 || response.httpStatus > 599) {
    throw new Error("guard_http_transport_status_invalid");
  }
  if (typeof response.redirected !== "boolean") throw new Error("guard_http_transport_redirected_invalid");
  validateExactTargetUrl(response.finalUrl);
}

const CREDENTIAL_HEADERS_BY_PROVIDER: Readonly<
  Record<NativeGatewayProvider, ReadonlySet<string>>
> = Object.freeze({
  anthropic: new Set(["x-api-key"]),
  gemini: new Set(["x-goog-api-key"]),
  openai: new Set(["authorization"]),
  xai: new Set(["authorization"]),
});

function safeTransportHeaders(
  provider: NativeGatewayProvider,
  values: Readonly<Record<string, string>>,
): Headers {
  if (typeof values !== "object" || values === null || Array.isArray(values)) {
    throw new Error("guard_http_transport_headers_invalid");
  }
  const headers = new Headers();
  const allowed = CREDENTIAL_HEADERS_BY_PROVIDER[provider];
  const seen = new Set<string>();
  for (const [name, value] of Object.entries(values)) {
    const normalizedName = name.toLowerCase();
    if (!allowed.has(normalizedName)) {
      throw new Error("guard_http_transport_credential_header_not_allowed");
    }
    if (seen.has(normalizedName)) {
      throw new Error("guard_http_transport_credential_header_ambiguous");
    }
    seen.add(normalizedName);
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      value.length > 8_192 ||
      value.trim() !== value ||
      /[^\x20-\x7e]/.test(value)
    ) {
      throw new Error("guard_http_transport_credential_value_invalid");
    }
    headers.set(normalizedName, value);
  }
  if (seen.size !== 1) {
    throw new Error("guard_http_transport_credential_header_missing");
  }
  return headers;
}

async function readLimitedBody(response: Response, maximum: number): Promise<Uint8Array> {
  if (response.body === null) throw new Error("guard_http_transport_response_body_missing");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const read = await reader.read();
    if (read.done) break;
    total += read.value.byteLength;
    if (total > maximum) {
      await reader.cancel();
      throw new Error("guard_http_transport_response_bytes_exceeded");
    }
    chunks.push(read.value);
  }
  if (total === 0) throw new Error("guard_http_transport_response_body_missing");
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

function validatePositiveInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${label}_invalid`);
}

function assertExactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (canonicalJson(actual) !== canonicalJson(wanted)) throw new Error(`${label}_keys_invalid`);
}
