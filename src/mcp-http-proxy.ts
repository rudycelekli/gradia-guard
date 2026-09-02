import { createHash, randomBytes, timingSafeEqual, type KeyLike } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { join } from "node:path";
import { canonicalJson, digestCanonical, isSha256 } from "./canonical.js";
import {
  AuthenticatedMcpToolAdapter,
  type AuthenticatedMcpToolResult,
  type GuardMcpInvocationResponse,
  type GuardMcpToolInvoker,
} from "./mcp-adapter.js";
import {
  McpHttpAccessRecorder,
  mcpHttpRequestEvidence,
  mcpHttpRouteTargetSha256,
  type McpHttpAccessOutcome,
  type McpHttpAccessReasonCode,
  type McpHttpRequestKind,
} from "./mcp-http-evidence.js";
import { verifyPolicy, type GuardPolicy } from "./policy.js";
import { assertStableId } from "./security.js";
import type { SdkToolIdentity } from "./types.js";
import {
  verifyWorkloadIdentity,
  type GuardWorkloadIdentity,
  type WorkloadIdentityExpectation,
} from "./workload-identity.js";

export const MCP_HTTP_PROXY_CONFIGURATION_SCHEMA_VERSION =
  "gradia.guard.mcp-http-proxy-configuration.v1" as const;
export const MCP_HTTP_PROXY_PROTOCOL_VERSION = "2026-07-28" as const;

const MAX_MCP_HTTP_REQUEST_BYTES = 16 * 1024 * 1024;

export interface GuardMcpHttpToolRoute {
  server_id: string;
  tool_name: string;
  tool_identity: SdkToolIdentity;
  authority_scope_ids: readonly string[];
  description: string;
  input_schema: Readonly<Record<string, unknown>>;
}

export interface GuardMcpHttpProxyConfigurationBody {
  schema_version: typeof MCP_HTTP_PROXY_CONFIGURATION_SCHEMA_VERSION;
  configuration_id: string;
  configuration_version: string;
  default_decision: "blocked";
  tool_routes: readonly GuardMcpHttpToolRoute[];
}

export interface GuardMcpHttpProxyConfiguration
  extends GuardMcpHttpProxyConfigurationBody {
  configuration_sha256: string;
}

export interface AuthenticatedMcpHttpProxyOptions {
  directory: string;
  policy: GuardPolicy;
  configuration: GuardMcpHttpProxyConfiguration;
  workloadIdentity: GuardWorkloadIdentity;
  trustedPublicKeys: Readonly<Record<string, KeyLike>>;
  workloadExpectation: Omit<WorkloadIdentityExpectation, "requiredAuthorityScopeIds">;
  maxIdentityLifetimeSeconds: number;
  clockSkewSeconds?: number;
  nowUnix?: () => number;
  invokeTool: GuardMcpToolInvoker;
}

export interface AuthenticatedMcpHttpProxyCloseResult {
  sdk_bundle_directory: string | null;
  http_access_bundle_directory: string;
  http_access_receipt_count: number;
  http_access_chain_head_sha256: string;
  accepted_tool_requests: number;
  blocked_tool_requests: number;
  unauthorized_http_requests: number;
  malformed_http_requests: number;
}

interface ProxyCounters {
  acceptedTool: number;
  blockedTool: number;
  unauthorized: number;
  malformed: number;
}

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id: string | number;
  method: string;
  params: Record<string, unknown>;
}

export class AuthenticatedMcpHttpProxy {
  readonly origin: string;
  readonly protocolVersion = MCP_HTTP_PROXY_PROTOCOL_VERSION;
  readonly configuration: GuardMcpHttpProxyConfiguration;
  private readonly server: Server;
  private readonly adapterRef: {
    current: AuthenticatedMcpToolAdapter | null;
  };
  private readonly accessRecorder: McpHttpAccessRecorder;
  private readonly evidenceDirectory: string;
  private readonly accessEvidenceDirectory: string;
  private readonly localCapability: string;
  private readonly counters: ProxyCounters;
  private closed = false;

  constructor(input: {
    origin: string;
    server: Server;
    adapterRef: { current: AuthenticatedMcpToolAdapter | null };
    accessRecorder: McpHttpAccessRecorder;
    evidenceDirectory: string;
    accessEvidenceDirectory: string;
    localCapability: string;
    configuration: GuardMcpHttpProxyConfiguration;
    counters: ProxyCounters;
  }) {
    this.origin = input.origin;
    this.server = input.server;
    this.adapterRef = input.adapterRef;
    this.accessRecorder = input.accessRecorder;
    this.evidenceDirectory = input.evidenceDirectory;
    this.accessEvidenceDirectory = input.accessEvidenceDirectory;
    this.localCapability = input.localCapability;
    this.configuration = input.configuration;
    this.counters = input.counters;
  }

  endpoint(serverId: string): string {
    assertStableId(serverId, "guard_mcp_http_server_id");
    if (!this.configuration.tool_routes.some((route) => route.server_id === serverId)) {
      throw new Error("guard_mcp_http_server_not_configured");
    }
    return `${this.origin}/mcp/${serverId}`;
  }

  childEnvironment(serverId: string): Readonly<Record<string, string>> {
    return Object.freeze({
      GRADIA_GUARD_MCP_AUTHORIZATION: `Bearer ${this.localCapability}`,
      GRADIA_GUARD_MCP_ENDPOINT: this.endpoint(serverId),
      GRADIA_GUARD_MCP_PROTOCOL_VERSION: MCP_HTTP_PROXY_PROTOCOL_VERSION,
    });
  }

  async close(): Promise<AuthenticatedMcpHttpProxyCloseResult> {
    if (this.closed) throw new Error("guard_mcp_http_proxy_already_closed");
    this.closed = true;
    await closeServer(this.server);
    this.adapterRef.current?.finalize();
    const accessBundle = this.accessRecorder.finalize();
    return {
      sdk_bundle_directory:
        this.adapterRef.current === null ? null : this.evidenceDirectory,
      http_access_bundle_directory: this.accessEvidenceDirectory,
      http_access_receipt_count: accessBundle.finalization.receipt_count,
      http_access_chain_head_sha256: accessBundle.finalization.chain_head_sha256,
      accepted_tool_requests: this.counters.acceptedTool,
      blocked_tool_requests: this.counters.blockedTool,
      unauthorized_http_requests: this.counters.unauthorized,
      malformed_http_requests: this.counters.malformed,
    };
  }
}

export function sealMcpHttpProxyConfiguration(
  body: GuardMcpHttpProxyConfigurationBody,
): GuardMcpHttpProxyConfiguration {
  validateConfigurationBody(body);
  const cloned = JSON.parse(canonicalJson(body)) as GuardMcpHttpProxyConfigurationBody;
  return { ...cloned, configuration_sha256: digestCanonical(cloned) };
}

export function verifyMcpHttpProxyConfiguration(
  configuration: GuardMcpHttpProxyConfiguration,
): void {
  assertExactKeys(
    configuration as unknown as Record<string, unknown>,
    [
      "configuration_id",
      "configuration_sha256",
      "configuration_version",
      "default_decision",
      "schema_version",
      "tool_routes",
    ],
    "guard_mcp_http_configuration",
  );
  const body: GuardMcpHttpProxyConfigurationBody = {
    schema_version: configuration.schema_version,
    configuration_id: configuration.configuration_id,
    configuration_version: configuration.configuration_version,
    default_decision: configuration.default_decision,
    tool_routes: configuration.tool_routes,
  };
  validateConfigurationBody(body);
  if (!isSha256(configuration.configuration_sha256)) {
    throw new Error("guard_mcp_http_configuration_digest_invalid");
  }
  if (configuration.configuration_sha256 !== digestCanonical(body)) {
    throw new Error("guard_mcp_http_configuration_digest_mismatch");
  }
}

export async function startAuthenticatedMcpHttpProxy(
  options: AuthenticatedMcpHttpProxyOptions,
): Promise<AuthenticatedMcpHttpProxy> {
  verifyPolicy(options.policy);
  verifyMcpHttpProxyConfiguration(options.configuration);
  if (options.workloadExpectation.policySha256 !== options.policy.policy_sha256) {
    throw new Error("guard_mcp_http_expected_policy_mismatch");
  }
  if (
    options.workloadExpectation.configurationSha256 !==
    options.configuration.configuration_sha256
  ) {
    throw new Error("guard_mcp_http_expected_configuration_mismatch");
  }
  verifyRoutesAgainstPolicy(options.configuration, options.policy);
  const currentUnix = options.nowUnix?.() ?? Math.floor(Date.now() / 1000);
  const verifiedWorkloadIdentity = verifyWorkloadIdentity(options.workloadIdentity, {
    trustedPublicKeys: options.trustedPublicKeys,
    expectation: {
      ...options.workloadExpectation,
      requiredAuthorityScopeIds: options.workloadIdentity.claims.authority_scope_ids,
    },
    nowUnix: currentUnix,
    maxLifetimeSeconds: options.maxIdentityLifetimeSeconds,
    clockSkewSeconds: options.clockSkewSeconds ?? 0,
  });
  const wallTime = (): string =>
    new Date(
      (options.nowUnix?.() ?? Math.floor(Date.now() / 1000)) * 1000,
    ).toISOString();
  const evidenceDirectory = join(options.directory, "mcp-evidence");
  const accessEvidenceDirectory = join(options.directory, "mcp-http-access");
  const accessRecorder = new McpHttpAccessRecorder({
    directory: accessEvidenceDirectory,
    createdAt: wallTime(),
    configurationSha256: options.configuration.configuration_sha256,
    policySha256: options.policy.policy_sha256,
    workloadIdentitySha256: verifiedWorkloadIdentity.identitySha256,
    now: wallTime,
  });
  const adapterRef: { current: AuthenticatedMcpToolAdapter | null } = {
    current: null,
  };
  const adapterForRequest = (): AuthenticatedMcpToolAdapter => {
    adapterRef.current ??= new AuthenticatedMcpToolAdapter({
      directory: evidenceDirectory,
      policy: options.policy,
      workloadIdentity: options.workloadIdentity,
      trustedPublicKeys: options.trustedPublicKeys,
      workloadExpectation: options.workloadExpectation,
      maxIdentityLifetimeSeconds: options.maxIdentityLifetimeSeconds,
      ...(options.clockSkewSeconds === undefined
        ? {}
        : { clockSkewSeconds: options.clockSkewSeconds }),
      ...(options.nowUnix === undefined ? {} : { nowUnix: options.nowUnix }),
      invokeTool: async (input) => {
        const response = await options.invokeTool(input);
        validateNativeToolResult(response);
        return response;
      },
    });
    return adapterRef.current;
  };
  const localCapability = randomBytes(32).toString("base64url");
  const counters: ProxyCounters = {
    acceptedTool: 0,
    blockedTool: 0,
    unauthorized: 0,
    malformed: 0,
  };
  const server = createMcpServer(
    adapterForRequest,
    options.configuration,
    localCapability,
    counters,
    accessRecorder,
  );
  const port = await listenLoopback(server);
  return new AuthenticatedMcpHttpProxy({
    origin: `http://127.0.0.1:${port}`,
    server,
    adapterRef,
    accessRecorder,
    evidenceDirectory,
    accessEvidenceDirectory,
    localCapability,
    configuration: options.configuration,
    counters,
  });
}

function createMcpServer(
  adapterForRequest: () => AuthenticatedMcpToolAdapter,
  configuration: GuardMcpHttpProxyConfiguration,
  localCapability: string,
  counters: ProxyCounters,
  accessRecorder: McpHttpAccessRecorder,
): Server {
  return createServer(async (request, response) => {
    const requestId = `mcp-http-request-${randomBytes(16).toString("hex")}`;
    let requestBody: Uint8Array | null = null;
    let requestKind: McpHttpRequestKind = "unknown";
    let routeTargetSha256: string | null = null;
    let adapterStarted = false;
    let adapterResult: AuthenticatedMcpToolResult | null = null;
    const persist = (outcome: McpHttpAccessOutcome): boolean => {
      try {
        accessRecorder.append({
          requestId,
          request: mcpHttpRequestEvidence({
            method: request.method,
            target: request.url,
            rawHeaders: request.rawHeaders,
            body: requestBody,
          }),
          outcome,
        });
        return true;
      } catch {
        response.destroy();
        return false;
      }
    };
    response.setHeader("cache-control", "no-store");
    response.setHeader("connection", "close");
    if (request.headers.origin !== undefined) {
      if (!persist(accessOutcome({
        requestKind,
        disposition: "refused",
        reasonCode: "origin_not_allowed",
        status: 403,
        routeTargetSha256,
        upstreamInvoked: false,
      }))) return;
      counters.unauthorized += 1;
      sendJsonRpcError(response, 403, null, -32003, "origin_not_allowed");
      return;
    }
    if (!matchesBearer(request.headers.authorization, localCapability)) {
      if (!persist(accessOutcome({
        requestKind,
        disposition: "refused",
        reasonCode: "authorization_refused",
        status: 401,
        routeTargetSha256,
        upstreamInvoked: false,
      }))) return;
      counters.unauthorized += 1;
      sendJsonRpcError(response, 401, null, -32003, "authorization_refused");
      return;
    }
    try {
      if (
        request.method !== "POST" ||
        request.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase() !==
          "application/json"
      ) {
        throw new Error("guard_mcp_http_request_invalid");
      }
      const serverId = configuredServerId(request.url, configuration);
      requestBody = await readIncomingRequest(request);
      const body = parseJsonRpcRequest(requestBody);
      requestKind = requestKindFor(body.method);
      routeTargetSha256 = mcpHttpRouteTargetSha256(
        serverId,
        body.method === "tools/call" && typeof body.params["name"] === "string"
          ? body.params["name"]
          : null,
      );
      verifyModernMcpHeaders(request, body);
      verifyModernRequestEnvelope(body.params);
      if (body.method === "server/discover") {
        assertExactKeys(body.params, ["_meta"], "guard_mcp_http_discover");
        if (!persist(accessOutcome({
          requestKind,
          disposition: "completed",
          reasonCode: "server_discovery_completed",
          status: 200,
          routeTargetSha256,
          upstreamInvoked: false,
        }))) return;
        sendJsonRpcResult(response, body.id, {
          capabilities: { tools: { listChanged: false } },
          cacheScope: "private",
          instructions:
            "Only the exact policy-bound tools returned by tools/list are available.",
          supportedVersions: [MCP_HTTP_PROXY_PROTOCOL_VERSION],
          ttlMs: 0,
        });
        return;
      }
      if (body.method === "tools/list") {
        assertExactKeys(body.params, ["_meta"], "guard_mcp_http_tools_list");
        if (!persist(accessOutcome({
          requestKind,
          disposition: "completed",
          reasonCode: "tool_list_completed",
          status: 200,
          routeTargetSha256,
          upstreamInvoked: false,
        }))) return;
        sendJsonRpcResult(response, body.id, {
          cacheScope: "private",
          ttlMs: 0,
          tools: configuration.tool_routes
            .filter((route) => route.server_id === serverId)
            .map((route) => ({
              description: route.description,
              inputSchema: route.input_schema,
              name: route.tool_name,
            })),
        });
        return;
      }
      if (body.method !== "tools/call") {
        throw new Error("guard_mcp_http_method_unsupported");
      }
      const toolCall = parseToolCall(body.params);
      routeTargetSha256 = mcpHttpRouteTargetSha256(serverId, toolCall.name);
      const route = configuration.tool_routes.find(
        (candidate) =>
          candidate.server_id === serverId && candidate.tool_name === toolCall.name,
      );
      if (!route) {
        if (!persist(accessOutcome({
          requestKind,
          disposition: "refused",
          reasonCode: "tool_route_not_allowed",
          status: 403,
          routeTargetSha256,
          upstreamInvoked: false,
        }))) return;
        counters.blockedTool += 1;
        sendJsonRpcError(response, 403, body.id, -32001, "tool_route_not_allowed");
        return;
      }
      adapterStarted = true;
      const result = await adapterForRequest().invoke({
        serverId: route.server_id,
        toolIdentity: route.tool_identity,
        toolRequestBody: Buffer.from(canonicalJson(toolCall.arguments)),
        toolRequestMediaType: "application/json",
        authorityScopeIds: route.authority_scope_ids,
        logicalOperationId: `mcp-${randomBytes(16).toString("hex")}`,
        attemptNumber: 1,
        retryOfOccurrenceSha256: null,
        parentOccurrenceSha256: null,
        stateRootBefore: null,
      });
      adapterResult = result;
      if (result.disposition === "completed" || result.response !== null) {
        const nativeResult = parseNativeToolResult(result);
        if (!persist(accessOutcomeForAdapter(
          requestKind,
          routeTargetSha256,
          200,
          result,
        ))) return;
        counters.acceptedTool += 1;
        response.setHeader("x-gradia-occurrence-sha256", result.occurrenceSha256);
        sendJsonRpcResult(response, body.id, nativeResult);
        return;
      }
      const refusalStatus = result.disposition === "blocked" ? 403 : 502;
      if (!persist(accessOutcomeForAdapter(
        requestKind,
        routeTargetSha256,
        refusalStatus,
        result,
      ))) return;
      counters.blockedTool += 1;
      response.setHeader("x-gradia-occurrence-sha256", result.occurrenceSha256);
      sendAdapterRefusal(response, body.id, result);
    } catch (error) {
      const reasonCode = classifyRequestFailure(error);
      const status = reasonCode === "proxy_internal_failure" ? 500 : 400;
      if (!persist(accessOutcome({
        requestKind,
        disposition: reasonCode === "proxy_internal_failure" ? "failed" : "refused",
        reasonCode,
        status,
        routeTargetSha256,
        upstreamInvoked:
          adapterResult === null
            ? adapterStarted
              ? null
              : false
            : adapterResult.disposition !== "blocked",
        adapterResult,
      }))) return;
      counters.malformed += 1;
      sendJsonRpcError(response, status, null, -32600, "request_refused");
    }
  });
}

function accessOutcome(input: {
  requestKind: McpHttpRequestKind;
  disposition: McpHttpAccessOutcome["disposition"];
  reasonCode: McpHttpAccessReasonCode;
  status: number;
  routeTargetSha256: string | null;
  upstreamInvoked: boolean | null;
  adapterResult?: AuthenticatedMcpToolResult | null;
}): McpHttpAccessOutcome {
  return {
    request_kind: input.requestKind,
    disposition: input.disposition,
    reason_code: input.reasonCode,
    http_status: input.status,
    route_target_sha256: input.routeTargetSha256,
    upstream_invoked: input.upstreamInvoked,
    sdk_disposition: input.adapterResult?.disposition ?? null,
    sdk_occurrence_sha256: input.adapterResult?.occurrenceSha256 ?? null,
  };
}

function accessOutcomeForAdapter(
  requestKind: McpHttpRequestKind,
  routeTargetSha256: string | null,
  status: number,
  result: AuthenticatedMcpToolResult,
): McpHttpAccessOutcome {
  const mapping: Record<
    AuthenticatedMcpToolResult["disposition"],
    {
      disposition: McpHttpAccessOutcome["disposition"];
      reasonCode: McpHttpAccessReasonCode;
      upstreamInvoked: boolean;
    }
  > = {
    blocked: {
      disposition: "refused",
      reasonCode: "adapter_policy_refused",
      upstreamInvoked: false,
    },
    completed: {
      disposition: "completed",
      reasonCode: "tool_call_completed",
      upstreamInvoked: true,
    },
    tool_failure: {
      disposition: "failed",
      reasonCode: "adapter_tool_failure",
      upstreamInvoked: true,
    },
    protocol_failure: {
      disposition: "failed",
      reasonCode: "adapter_protocol_failed",
      upstreamInvoked: true,
    },
    identity_mismatch: {
      disposition: "failed",
      reasonCode: "adapter_identity_mismatch",
      upstreamInvoked: true,
    },
  };
  const mapped = mapping[result.disposition];
  return accessOutcome({
    requestKind,
    disposition: mapped.disposition,
    reasonCode: mapped.reasonCode,
    status,
    routeTargetSha256,
    upstreamInvoked: mapped.upstreamInvoked,
    adapterResult: result,
  });
}

function requestKindFor(method: string): McpHttpRequestKind {
  if (method === "server/discover") return "server_discovery";
  if (method === "tools/list") return "tool_list";
  if (method === "tools/call") return "tool_call";
  return "unknown";
}

function classifyRequestFailure(error: unknown): McpHttpAccessReasonCode {
  const message = error instanceof Error ? error.message : "";
  if (message === "guard_mcp_http_request_invalid") return "http_request_refused";
  if (message.includes("url_invalid") || message.includes("server_not_configured")) {
    return "target_refused";
  }
  if (
    error instanceof SyntaxError ||
    message.includes("request_too_large") ||
    message.includes("request_empty") ||
    message.includes("jsonrpc") ||
    message.includes("id_invalid") ||
    message.includes("method_invalid") ||
    message.includes("params_invalid") ||
    message.includes("tool_arguments_invalid") ||
    message.includes("tool_name_invalid") ||
    message.includes("keys_invalid")
  ) {
    return "body_refused";
  }
  if (
    message.includes("protocol_version") ||
    message.includes("method_header_mismatch") ||
    message.includes("name_header_mismatch") ||
    message.includes("request_meta_invalid") ||
    message.includes("meta_protocol")
  ) {
    return "protocol_refused";
  }
  if (message.includes("method_unsupported")) return "rpc_method_refused";
  return "proxy_internal_failure";
}

function validateConfigurationBody(body: GuardMcpHttpProxyConfigurationBody): void {
  assertExactKeys(
    body as unknown as Record<string, unknown>,
    [
      "configuration_id",
      "configuration_version",
      "default_decision",
      "schema_version",
      "tool_routes",
    ],
    "guard_mcp_http_configuration_body",
  );
  if (body.schema_version !== MCP_HTTP_PROXY_CONFIGURATION_SCHEMA_VERSION) {
    throw new Error("guard_mcp_http_configuration_schema_unsupported");
  }
  assertStableId(body.configuration_id, "guard_mcp_http_configuration_id");
  assertStableId(body.configuration_version, "guard_mcp_http_configuration_version");
  if (body.default_decision !== "blocked") {
    throw new Error("guard_mcp_http_configuration_must_default_blocked");
  }
  if (!Array.isArray(body.tool_routes) || body.tool_routes.length === 0) {
    throw new Error("guard_mcp_http_routes_missing");
  }
  const keys = new Set<string>();
  for (const route of body.tool_routes) {
    validateRoute(route);
    const key = `${route.server_id}\0${route.tool_name}`;
    if (keys.has(key)) throw new Error("guard_mcp_http_route_duplicate");
    keys.add(key);
  }
}

function validateRoute(route: GuardMcpHttpToolRoute): void {
  assertExactKeys(
    route as unknown as Record<string, unknown>,
    [
      "authority_scope_ids",
      "description",
      "input_schema",
      "server_id",
      "tool_identity",
      "tool_name",
    ],
    "guard_mcp_http_route",
  );
  assertStableId(route.server_id, "guard_mcp_http_server_id");
  assertStableId(route.tool_name, "guard_mcp_http_tool_name");
  if (
    route.server_id !== route.tool_identity.registry_id ||
    route.tool_name !== route.tool_identity.tool_id
  ) {
    throw new Error("guard_mcp_http_route_identity_mismatch");
  }
  if (!isSha256(route.tool_identity.interface_sha256)) {
    throw new Error("guard_mcp_http_interface_digest_invalid");
  }
  assertStableId(route.tool_identity.tool_version, "guard_mcp_http_tool_version");
  if (route.tool_identity.schema_version !== "gradia.guard.sdk-tool-identity.v1") {
    throw new Error("guard_mcp_http_tool_identity_schema_unsupported");
  }
  if (!Array.isArray(route.authority_scope_ids) || route.authority_scope_ids.length === 0) {
    throw new Error("guard_mcp_http_scopes_missing");
  }
  const scopes = [...new Set(route.authority_scope_ids)].sort();
  for (const scope of scopes) assertStableId(scope, "guard_mcp_http_scope_id");
  if (canonicalJson(scopes) !== canonicalJson(route.authority_scope_ids)) {
    throw new Error("guard_mcp_http_scopes_not_canonical");
  }
  if (!/^[\x20-\x7e]{1,500}$/.test(route.description)) {
    throw new Error("guard_mcp_http_description_invalid");
  }
  if (
    typeof route.input_schema !== "object" ||
    route.input_schema === null ||
    Array.isArray(route.input_schema) ||
    route.input_schema["type"] !== "object"
  ) {
    throw new Error("guard_mcp_http_input_schema_invalid");
  }
  canonicalJson(route.input_schema);
}

function verifyRoutesAgainstPolicy(
  configuration: GuardMcpHttpProxyConfiguration,
  policy: GuardPolicy,
): void {
  for (const route of configuration.tool_routes) {
    const matching = policy.tool_routes.find(
      (candidate) =>
        candidate.registry_id === route.tool_identity.registry_id &&
        candidate.tool_id === route.tool_identity.tool_id &&
        candidate.tool_version === route.tool_identity.tool_version &&
        candidate.interface_sha256 === route.tool_identity.interface_sha256,
    );
    if (!matching) throw new Error("guard_mcp_http_policy_route_missing");
    if (canonicalJson(matching.authority_scope_ids) !== canonicalJson(route.authority_scope_ids)) {
      throw new Error("guard_mcp_http_policy_scope_mismatch");
    }
  }
}

function configuredServerId(
  rawUrl: string | undefined,
  configuration: GuardMcpHttpProxyConfiguration,
): string {
  if (!rawUrl || rawUrl.includes("\\")) throw new Error("guard_mcp_http_url_invalid");
  const parsed = new URL(rawUrl, "http://guard.local");
  if (parsed.origin !== "http://guard.local" || parsed.search || parsed.hash) {
    throw new Error("guard_mcp_http_url_invalid");
  }
  const route = configuration.tool_routes.find(
    (candidate) => parsed.pathname === `/mcp/${candidate.server_id}`,
  );
  if (!route) throw new Error("guard_mcp_http_server_not_configured");
  return route.server_id;
}

function parseJsonRpcRequest(bytes: Uint8Array): JsonRpcRequest {
  const value = JSON.parse(Buffer.from(bytes).toString("utf8")) as Record<string, unknown>;
  assertExactKeys(value, ["id", "jsonrpc", "method", "params"], "guard_mcp_http_jsonrpc");
  if (value["jsonrpc"] !== "2.0") throw new Error("guard_mcp_http_jsonrpc_invalid");
  if (
    (typeof value["id"] !== "string" && typeof value["id"] !== "number") ||
    (typeof value["id"] === "number" && !Number.isSafeInteger(value["id"]))
  ) {
    throw new Error("guard_mcp_http_id_invalid");
  }
  if (typeof value["method"] !== "string") throw new Error("guard_mcp_http_method_invalid");
  if (typeof value["params"] !== "object" || value["params"] === null || Array.isArray(value["params"])) {
    throw new Error("guard_mcp_http_params_invalid");
  }
  return value as unknown as JsonRpcRequest;
}

function verifyModernMcpHeaders(request: IncomingMessage, body: JsonRpcRequest): void {
  if (singleHeader(request.headers["mcp-protocol-version"]) !== MCP_HTTP_PROXY_PROTOCOL_VERSION) {
    throw new Error("guard_mcp_http_protocol_version_invalid");
  }
  if (singleHeader(request.headers["mcp-method"]) !== body.method) {
    throw new Error("guard_mcp_http_method_header_mismatch");
  }
  const expectedName =
    body.method === "tools/call" && typeof body.params["name"] === "string"
      ? body.params["name"]
      : undefined;
  if (singleHeader(request.headers["mcp-name"]) !== expectedName) {
    throw new Error("guard_mcp_http_name_header_mismatch");
  }
}

function parseToolCall(params: Record<string, unknown>): {
  name: string;
  arguments: Record<string, unknown>;
} {
  assertExactKeys(params, ["_meta", "arguments", "name"], "guard_mcp_http_tool_call");
  if (typeof params["name"] !== "string") throw new Error("guard_mcp_http_tool_name_invalid");
  assertStableId(params["name"], "guard_mcp_http_tool_name");
  const args = params["arguments"];
  if (typeof args !== "object" || args === null || Array.isArray(args)) {
    throw new Error("guard_mcp_http_tool_arguments_invalid");
  }
  canonicalJson(args);
  return { name: params["name"], arguments: args as Record<string, unknown> };
}

function verifyModernRequestEnvelope(params: Record<string, unknown>): void {
  const meta = params["_meta"];
  if (typeof meta !== "object" || meta === null || Array.isArray(meta)) {
    throw new Error("guard_mcp_http_request_meta_invalid");
  }
  if (
    (meta as Record<string, unknown>)["io.modelcontextprotocol/protocolVersion"] !==
    MCP_HTTP_PROXY_PROTOCOL_VERSION
  ) {
    throw new Error("guard_mcp_http_meta_protocol_version_invalid");
  }
}

function validateNativeToolResult(response: GuardMcpInvocationResponse): void {
  const parsed = JSON.parse(Buffer.from(response.toolResultBody).toString("utf8")) as unknown;
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("guard_mcp_http_native_result_invalid");
  }
  const declared = (parsed as Record<string, unknown>)["isError"];
  if (declared !== undefined && declared !== response.isError) {
    throw new Error("guard_mcp_http_native_result_error_mismatch");
  }
}

function parseNativeToolResult(result: AuthenticatedMcpToolResult): Record<string, unknown> {
  if (result.response === null) throw new Error("guard_mcp_http_native_result_missing");
  const parsed = JSON.parse(Buffer.from(result.response.toolResultBody).toString("utf8")) as unknown;
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("guard_mcp_http_native_result_invalid");
  }
  return parsed as Record<string, unknown>;
}

function sendAdapterRefusal(
  response: ServerResponse,
  id: string | number,
  result: AuthenticatedMcpToolResult,
): void {
  const status = result.disposition === "blocked" ? 403 : 502;
  sendJsonRpcError(response, status, id, -32002, `gradia_${result.disposition}`, {
    occurrence_sha256: result.occurrenceSha256,
  });
}

async function readIncomingRequest(request: IncomingMessage): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const value of request) {
    const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
    length += chunk.length;
    if (length > MAX_MCP_HTTP_REQUEST_BYTES) throw new Error("guard_mcp_http_request_too_large");
    chunks.push(chunk);
  }
  if (length === 0) throw new Error("guard_mcp_http_request_empty");
  return Buffer.concat(chunks);
}

function matchesBearer(header: string | undefined, capability: string): boolean {
  const supplied = typeof header === "string" && header.startsWith("Bearer ")
    ? header.slice(7)
    : "";
  const expectedDigest = createHash("sha256").update(capability).digest();
  const suppliedDigest = createHash("sha256").update(supplied).digest();
  return supplied.length > 0 && timingSafeEqual(expectedDigest, suppliedDigest);
}

function singleHeader(value: string | string[] | undefined): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function sendJsonRpcResult(
  response: ServerResponse,
  id: string | number,
  result: unknown,
): void {
  if (typeof result !== "object" || result === null || Array.isArray(result)) {
    throw new Error("guard_mcp_http_result_invalid");
  }
  const stamped = {
    ...(result as Record<string, unknown>),
    resultType: (result as Record<string, unknown>)["resultType"] ?? "complete",
    _meta: {
      ...(((result as Record<string, unknown>)["_meta"] as Record<string, unknown> | undefined) ??
        {}),
      "io.modelcontextprotocol/serverInfo": {
        name: "gradia-guard-mcp-proxy",
        version: "0.1.0",
      },
    },
  };
  response.statusCode = 200;
  response.setHeader("content-type", "application/json");
  response.end(`${canonicalJson({ id, jsonrpc: "2.0", result: stamped })}\n`);
}

function sendJsonRpcError(
  response: ServerResponse,
  status: number,
  id: string | number | null,
  code: number,
  message: string,
  data?: Record<string, unknown>,
): void {
  response.statusCode = status;
  response.setHeader("content-type", "application/json");
  response.end(
    `${canonicalJson({
      error: { code, ...(data === undefined ? {} : { data }), message },
      id,
      jsonrpc: "2.0",
    })}\n`,
  );
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
    throw new Error("guard_mcp_http_loopback_bind_failed");
  }
  return address.port;
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

function assertExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (canonicalJson(actual) !== canonicalJson(wanted)) {
    throw new Error(`${label}_keys_invalid`);
  }
}
