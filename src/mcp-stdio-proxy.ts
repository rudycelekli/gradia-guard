import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomBytes, type KeyLike } from "node:crypto";
import { isAbsolute, join } from "node:path";
import { canonicalJson, digestCanonical, isSha256, sha256 } from "./canonical.js";
import {
  AuthenticatedMcpToolAdapter,
  type AuthenticatedMcpToolRequest,
  type AuthenticatedMcpToolResult,
  type GuardMcpInvocationInput,
  type GuardMcpInvocationResponse,
} from "./mcp-adapter.js";
import {
  DurableMcpStdioAccessRecorder,
  type McpStdioAccessBundle,
  type McpStdioTransactionInput,
} from "./mcp-stdio-evidence.js";
import { verifyPolicy, type GuardPolicy } from "./policy.js";
import { assertStableId } from "./security.js";
import type { SdkToolIdentity } from "./types.js";
import {
  verifyWorkloadIdentity,
  type GuardWorkloadIdentity,
  type WorkloadIdentityExpectation,
} from "./workload-identity.js";

export const MCP_STDIO_PROXY_CONFIGURATION_SCHEMA_VERSION =
  "gradia.guard.mcp-stdio-proxy-configuration.v1" as const;
export const MCP_STDIO_PROXY_PROTOCOL_VERSION = "2026-07-28" as const;
export const MCP_STDIO_PROXY_PROTOCOL_SUBSET =
  "stateless_newline_delimited_json_rpc_tools_call_only_no_initialize_initialized_discovery_notifications_streaming_or_multi_round" as const;
const MAX_STDIO_LINE_BYTES = 16 * 1024 * 1024;

export interface GuardMcpStdioToolRoute {
  tool_name: string;
  tool_identity: SdkToolIdentity;
  authority_scope_ids: readonly string[];
}

export interface GuardMcpStdioProxyConfigurationBody {
  schema_version: typeof MCP_STDIO_PROXY_CONFIGURATION_SCHEMA_VERSION;
  configuration_id: string;
  configuration_version: string;
  default_decision: "blocked";
  server_id: string;
  tool_routes: readonly GuardMcpStdioToolRoute[];
}

export interface GuardMcpStdioProxyConfiguration
  extends GuardMcpStdioProxyConfigurationBody {
  configuration_sha256: string;
}

export interface AuthenticatedMcpStdioProxyOptions {
  directory: string;
  policy: GuardPolicy;
  configuration: GuardMcpStdioProxyConfiguration;
  workloadIdentity: GuardWorkloadIdentity;
  trustedPublicKeys: Readonly<Record<string, KeyLike>>;
  workloadExpectation: Omit<WorkloadIdentityExpectation, "requiredAuthorityScopeIds">;
  maxIdentityLifetimeSeconds: number;
  clockSkewSeconds?: number;
  nowUnix?: () => number;
  command: string;
  args?: readonly string[];
  responseTimeoutMs?: number;
}

export interface AuthenticatedMcpStdioProxyCloseResult {
  sdk_bundle_directory: string | null;
  stdio_access_bundle_directory: string;
  stdio_access_receipt_count: number;
  stdio_access_chain_head_sha256: string;
  transaction_count: number;
  completed_transactions: number;
  blocked_transactions: number;
  failed_transactions: number;
  child_exit_code: number | null;
  child_signal: NodeJS.Signals | null;
  protocol_subset: typeof MCP_STDIO_PROXY_PROTOCOL_SUBSET;
  claim_boundary:
    "stdio_calls_through_this_spawned_child_only_not_host_or_container_non_bypassability";
}

interface PendingResponse {
  id: string;
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timeout: NodeJS.Timeout;
}

interface InvocationContext {
  requestId: string;
  transaction: McpStdioTransactionInput;
  authorizationPersisted: boolean;
  childStdinWriteCalled: boolean;
}

/**
 * A stateless newline-delimited JSON-RPC `tools/call` enforcement boundary.
 *
 * The child receives no request bytes until the authenticated adapter allows
 * the exact tool identity and the authorization receipt has been fsync'd.
 * It does not implement the MCP initialize handshake, discovery, notifications,
 * streaming, or multi-round protocol. It is not a host sandbox: another
 * process can spawn or write around it.
 */
export class AuthenticatedMcpStdioProxy {
  readonly configuration: GuardMcpStdioProxyConfiguration;
  readonly childLaunchDeclarationSha256: string;
  private readonly child: ChildProcessWithoutNullStreams;
  private readonly options: AuthenticatedMcpStdioProxyOptions;
  private readonly accessRecorder: DurableMcpStdioAccessRecorder;
  private readonly sdkDirectory: string;
  private readonly accessDirectory: string;
  private readonly timeoutMs: number;
  private adapter: AuthenticatedMcpToolAdapter | null = null;
  private activeContext: InvocationContext | null = null;
  private pending: PendingResponse | null = null;
  private stdoutBuffer = Buffer.alloc(0);
  private sequence = 0;
  private tail: Promise<void> = Promise.resolve();
  private closed = false;
  private exitCode: number | null = null;
  private exitSignal: NodeJS.Signals | null = null;
  private exited = false;

  constructor(input: {
    child: ChildProcessWithoutNullStreams;
    options: AuthenticatedMcpStdioProxyOptions;
    accessRecorder: DurableMcpStdioAccessRecorder;
    childLaunchDeclarationSha256: string;
    sdkDirectory: string;
    accessDirectory: string;
    timeoutMs: number;
  }) {
    this.child = input.child;
    this.options = input.options;
    this.accessRecorder = input.accessRecorder;
    this.childLaunchDeclarationSha256 = input.childLaunchDeclarationSha256;
    this.sdkDirectory = input.sdkDirectory;
    this.accessDirectory = input.accessDirectory;
    this.timeoutMs = input.timeoutMs;
    this.configuration = input.options.configuration;
    this.child.stdout.on("data", (chunk: Buffer) => this.onStdout(chunk));
    this.child.stderr.on("data", () => undefined);
    this.child.stdin.on("error", () => {
      this.rejectPending(new Error("guard_mcp_stdio_write_failed"));
    });
    this.child.once("exit", (code, signal) => {
      this.exited = true;
      this.exitCode = code;
      this.exitSignal = signal;
      this.rejectPending(new Error("guard_mcp_stdio_child_exited"));
    });
    this.child.once("error", () => {
      this.rejectPending(new Error("guard_mcp_stdio_child_error"));
    });
  }

  invoke(input: AuthenticatedMcpToolRequest): Promise<AuthenticatedMcpToolResult> {
    if (this.closed) return Promise.reject(new Error("guard_mcp_stdio_proxy_closed"));
    const run = this.tail.then(() => this.invokeSerial(input));
    this.tail = run.then(() => undefined, () => undefined);
    return run;
  }

  async close(): Promise<AuthenticatedMcpStdioProxyCloseResult> {
    if (this.closed) throw new Error("guard_mcp_stdio_proxy_already_closed");
    this.closed = true;
    await this.tail;
    if (!this.exited) {
      const exit = waitForExit(this.child);
      this.child.kill("SIGTERM");
      await exit;
    }
    this.adapter?.finalize();
    const bundle = this.accessRecorder.finalize();
    return closeResult(
      bundle,
      this.adapter === null ? null : this.sdkDirectory,
      this.accessDirectory,
      this.exitCode,
      this.exitSignal,
    );
  }

  private async invokeSerial(
    input: AuthenticatedMcpToolRequest,
  ): Promise<AuthenticatedMcpToolResult> {
    if (this.exited) throw new Error("guard_mcp_stdio_child_not_running");
    const requestId = `mcp-stdio-request-${this.sequence++}-${randomBytes(8).toString("hex")}`;
    const routeSha256 = digestCanonical({
      server_id: input.serverId,
      tool_identity: input.toolIdentity,
    });
    const context: InvocationContext = {
      requestId,
      transaction: {
        requestId,
        logicalOperationId: input.logicalOperationId,
        attemptNumber: input.attemptNumber,
        routeSha256,
        requestSha256: sha256(input.toolRequestBody),
        requestByteLength: input.toolRequestBody.byteLength,
      },
      authorizationPersisted: false,
      childStdinWriteCalled: false,
    };
    this.activeContext = context;
    let result: AuthenticatedMcpToolResult;
    try {
      result = await this.adapterForCall().invoke(input);
      if (!context.authorizationPersisted) {
        if (result.disposition !== "blocked") {
          throw new Error("guard_mcp_stdio_missing_predispatch_authorization");
        }
        this.accessRecorder.authorize(context.transaction, "blocked");
      }
      this.accessRecorder.terminal(
        requestId,
        result.disposition,
        result.occurrenceSha256,
        context.childStdinWriteCalled,
      );
      return result;
    } finally {
      this.activeContext = null;
    }
  }

  private adapterForCall(): AuthenticatedMcpToolAdapter {
    this.adapter ??= new AuthenticatedMcpToolAdapter({
      directory: this.sdkDirectory,
      policy: this.options.policy,
      workloadIdentity: this.options.workloadIdentity,
      trustedPublicKeys: this.options.trustedPublicKeys,
      workloadExpectation: this.options.workloadExpectation,
      maxIdentityLifetimeSeconds: this.options.maxIdentityLifetimeSeconds,
      ...(this.options.clockSkewSeconds === undefined
        ? {}
        : { clockSkewSeconds: this.options.clockSkewSeconds }),
      ...(this.options.nowUnix === undefined ? {} : { nowUnix: this.options.nowUnix }),
      invokeTool: (input) => this.dispatchAuthorized(input),
    });
    return this.adapter;
  }

  private async dispatchAuthorized(
    input: GuardMcpInvocationInput,
  ): Promise<GuardMcpInvocationResponse> {
    const context = this.activeContext;
    if (context === null || context.authorizationPersisted) {
      throw new Error("guard_mcp_stdio_dispatch_context_invalid");
    }
    this.accessRecorder.authorize(context.transaction, "allowed");
    context.authorizationPersisted = true;
    const args = parseArguments(input.toolRequestBody);
    const rpcId = context.requestId;
    const envelope = canonicalJson({
      jsonrpc: "2.0",
      id: rpcId,
      method: "tools/call",
      params: { arguments: args, name: input.toolIdentity.tool_id },
    });
    if (Buffer.byteLength(envelope, "utf8") > MAX_STDIO_LINE_BYTES) {
      throw new Error("guard_mcp_stdio_envelope_too_large");
    }
    const response = await this.exchange(rpcId, `${envelope}\n`);
    return responseFor(input, parseRpcResponse(response, rpcId));
  }

  private exchange(id: string, line: string): Promise<unknown> {
    if (this.pending !== null) return Promise.reject(new Error("guard_mcp_stdio_concurrent_exchange"));
    if (this.exited || !this.child.stdin.writable) {
      return Promise.reject(new Error("guard_mcp_stdio_child_not_writable"));
    }
    return new Promise<unknown>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.rejectPending(new Error("guard_mcp_stdio_response_timeout"));
        if (!this.exited) this.child.kill("SIGKILL");
      }, this.timeoutMs);
      this.pending = { id, resolve, reject, timeout };
      if (this.activeContext !== null) this.activeContext.childStdinWriteCalled = true;
      this.child.stdin.write(line, "utf8", (error) => {
        if (error) this.rejectPending(new Error("guard_mcp_stdio_write_failed"));
      });
    });
  }

  private onStdout(chunk: Buffer): void {
    if (this.pending === null) return;
    this.stdoutBuffer = Buffer.concat([this.stdoutBuffer, chunk]);
    if (this.stdoutBuffer.byteLength > MAX_STDIO_LINE_BYTES) {
      this.rejectPending(new Error("guard_mcp_stdio_response_too_large"));
      if (!this.exited) this.child.kill("SIGKILL");
      return;
    }
    const newline = this.stdoutBuffer.indexOf(0x0a);
    if (newline < 0) return;
    const line = this.stdoutBuffer.subarray(0, newline).toString("utf8");
    const trailing = this.stdoutBuffer.subarray(newline + 1);
    this.stdoutBuffer = Buffer.alloc(0);
    if (trailing.some((byte) => byte !== 0x0d && byte !== 0x0a && byte !== 0x20 && byte !== 0x09)) {
      this.rejectPending(new Error("guard_mcp_stdio_unsolicited_output"));
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(line) as unknown;
    } catch {
      this.rejectPending(new Error("guard_mcp_stdio_response_json_invalid"));
      return;
    }
    const pending = this.pending;
    this.pending = null;
    clearTimeout(pending.timeout);
    pending.resolve(parsed);
  }

  private rejectPending(error: Error): void {
    const pending = this.pending;
    if (pending === null) return;
    this.pending = null;
    clearTimeout(pending.timeout);
    pending.reject(error);
  }
}

export function sealMcpStdioProxyConfiguration(
  body: GuardMcpStdioProxyConfigurationBody,
): GuardMcpStdioProxyConfiguration {
  validateConfiguration(body);
  const cloned = JSON.parse(canonicalJson(body)) as GuardMcpStdioProxyConfigurationBody;
  return { ...cloned, configuration_sha256: digestCanonical(cloned) };
}

export function verifyMcpStdioProxyConfiguration(
  configuration: GuardMcpStdioProxyConfiguration,
): void {
  assertExactKeys(configuration as unknown as Record<string, unknown>, [
    "configuration_id",
    "configuration_sha256",
    "configuration_version",
    "default_decision",
    "schema_version",
    "server_id",
    "tool_routes",
  ], "guard_mcp_stdio_configuration");
  const body: GuardMcpStdioProxyConfigurationBody = {
    schema_version: configuration.schema_version,
    configuration_id: configuration.configuration_id,
    configuration_version: configuration.configuration_version,
    default_decision: configuration.default_decision,
    server_id: configuration.server_id,
    tool_routes: configuration.tool_routes,
  };
  validateConfiguration(body);
  if (!isSha256(configuration.configuration_sha256)
    || configuration.configuration_sha256 !== digestCanonical(body)) {
    throw new Error("guard_mcp_stdio_configuration_digest_mismatch");
  }
}

export async function startAuthenticatedMcpStdioProxy(
  options: AuthenticatedMcpStdioProxyOptions,
): Promise<AuthenticatedMcpStdioProxy> {
  verifyPolicy(options.policy);
  verifyMcpStdioProxyConfiguration(options.configuration);
  validateProcessOptions(options);
  if (options.workloadExpectation.policySha256 !== options.policy.policy_sha256) {
    throw new Error("guard_mcp_stdio_expected_policy_mismatch");
  }
  if (options.workloadExpectation.configurationSha256 !== options.configuration.configuration_sha256) {
    throw new Error("guard_mcp_stdio_expected_configuration_mismatch");
  }
  verifyConfigurationAgainstPolicy(options.configuration, options.policy);
  const currentUnix = options.nowUnix?.() ?? Math.floor(Date.now() / 1000);
  const identity = verifyWorkloadIdentity(options.workloadIdentity, {
    trustedPublicKeys: options.trustedPublicKeys,
    expectation: {
      ...options.workloadExpectation,
      requiredAuthorityScopeIds: options.workloadIdentity.claims.authority_scope_ids,
    },
    nowUnix: currentUnix,
    maxLifetimeSeconds: options.maxIdentityLifetimeSeconds,
    clockSkewSeconds: options.clockSkewSeconds ?? 0,
  });
  const childLaunchDeclarationSha256 = digestCanonical({
    command: options.command,
    args: [...(options.args ?? [])],
    environment: "empty",
    shell: false,
  });
  const accessDirectory = join(options.directory, "mcp-stdio-access");
  const sdkDirectory = join(options.directory, "mcp-evidence");
  const wallTime = (): string => new Date(
    (options.nowUnix?.() ?? Math.floor(Date.now() / 1000)) * 1000,
  ).toISOString();
  const accessRecorder = new DurableMcpStdioAccessRecorder({
    directory: accessDirectory,
    createdAt: wallTime(),
    configurationSha256: options.configuration.configuration_sha256,
    policySha256: options.policy.policy_sha256,
    workloadIdentitySha256: identity.identitySha256,
    childLaunchDeclarationSha256,
    now: wallTime,
  });
  const child = spawn(options.command, [...(options.args ?? [])], {
    env: {},
    shell: false,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const spawned = waitForSpawn(child);
  const proxy = new AuthenticatedMcpStdioProxy({
    child,
    options,
    accessRecorder,
    childLaunchDeclarationSha256,
    sdkDirectory,
    accessDirectory,
    timeoutMs: options.responseTimeoutMs ?? 30_000,
  });
  await spawned;
  return proxy;
}

export function recoverInterruptedMcpStdioAccess(
  accessDirectory: string,
  now: () => string,
): McpStdioAccessBundle {
  return DurableMcpStdioAccessRecorder.recover(accessDirectory, now).finalize();
}

function validateConfiguration(body: GuardMcpStdioProxyConfigurationBody): void {
  assertExactKeys(body as unknown as Record<string, unknown>, [
    "configuration_id",
    "configuration_version",
    "default_decision",
    "schema_version",
    "server_id",
    "tool_routes",
  ], "guard_mcp_stdio_configuration_body");
  if (body.schema_version !== MCP_STDIO_PROXY_CONFIGURATION_SCHEMA_VERSION) throw new Error("guard_mcp_stdio_configuration_schema_invalid");
  if (body.default_decision !== "blocked") throw new Error("guard_mcp_stdio_configuration_must_default_blocked");
  assertStableId(body.configuration_id, "guard_mcp_stdio_configuration_id");
  assertStableId(body.configuration_version, "guard_mcp_stdio_configuration_version");
  assertStableId(body.server_id, "guard_mcp_stdio_server_id");
  if (!Array.isArray(body.tool_routes) || body.tool_routes.length === 0) throw new Error("guard_mcp_stdio_routes_missing");
  const names = new Set<string>();
  for (const route of body.tool_routes) {
    assertExactKeys(route as unknown as Record<string, unknown>, ["authority_scope_ids", "tool_identity", "tool_name"], "guard_mcp_stdio_route");
    assertStableId(route.tool_name, "guard_mcp_stdio_tool_name");
    if (route.tool_name !== route.tool_identity.tool_id || route.tool_identity.registry_id !== body.server_id) throw new Error("guard_mcp_stdio_route_identity_mismatch");
    if (names.has(route.tool_name)) throw new Error("guard_mcp_stdio_route_duplicate");
    names.add(route.tool_name);
    canonicalIds(route.authority_scope_ids, "guard_mcp_stdio_authority_scope_ids");
    validateToolIdentity(route.tool_identity);
  }
}

function verifyConfigurationAgainstPolicy(
  configuration: GuardMcpStdioProxyConfiguration,
  policy: GuardPolicy,
): void {
  if (configuration.tool_routes.length !== policy.tool_routes.length) {
    throw new Error("guard_mcp_stdio_policy_has_unconfigured_tool_routes");
  }
  for (const route of configuration.tool_routes) {
    const allowed = policy.tool_routes.find((candidate) =>
      candidate.registry_id === route.tool_identity.registry_id
      && candidate.tool_id === route.tool_identity.tool_id
      && candidate.tool_version === route.tool_identity.tool_version
      && candidate.interface_sha256 === route.tool_identity.interface_sha256);
    if (allowed === undefined) throw new Error("guard_mcp_stdio_route_not_in_policy");
    if (canonicalJson(allowed.authority_scope_ids) !== canonicalJson(route.authority_scope_ids)) {
      throw new Error("guard_mcp_stdio_route_scope_mismatch");
    }
  }
}

function validateProcessOptions(options: AuthenticatedMcpStdioProxyOptions): void {
  if (!isAbsolute(options.command)) throw new Error("guard_mcp_stdio_command_must_be_absolute");
  if ((options.args ?? []).some((item) => typeof item !== "string" || item.includes("\0"))) throw new Error("guard_mcp_stdio_argument_invalid");
  const timeout = options.responseTimeoutMs ?? 30_000;
  if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 300_000) throw new Error("guard_mcp_stdio_timeout_invalid");
}

function parseArguments(body: Uint8Array): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(body).toString("utf8")) as unknown;
  } catch {
    throw new Error("guard_mcp_stdio_arguments_json_invalid");
  }
  if (!isRecord(value)) throw new Error("guard_mcp_stdio_arguments_shape_invalid");
  return value;
}

function parseRpcResponse(value: unknown, id: string): { result: unknown; isError: boolean } {
  if (!isRecord(value) || value["jsonrpc"] !== "2.0" || value["id"] !== id) {
    throw new Error("guard_mcp_stdio_response_envelope_invalid");
  }
  const hasResult = Object.prototype.hasOwnProperty.call(value, "result");
  const hasError = Object.prototype.hasOwnProperty.call(value, "error");
  if (hasResult === hasError) throw new Error("guard_mcp_stdio_response_result_shape_invalid");
  return { result: hasError ? { error: value["error"] } : value["result"], isError: hasError };
}

function responseFor(
  input: GuardMcpInvocationInput,
  response: { result: unknown; isError: boolean },
): GuardMcpInvocationResponse {
  return {
    resolvedServerId: input.serverId,
    resolvedToolIdentity: input.toolIdentity,
    toolResultBody: Buffer.from(canonicalJson(response.result), "utf8"),
    toolResultMediaType: "application/json",
    isError: response.isError,
    stateRootAfter: null,
  };
}

function closeResult(
  bundle: McpStdioAccessBundle,
  sdkDirectory: string | null,
  accessDirectory: string,
  exitCode: number | null,
  signal: NodeJS.Signals | null,
): AuthenticatedMcpStdioProxyCloseResult {
  const counters = bundle.finalization.counters;
  return {
    sdk_bundle_directory: sdkDirectory,
    stdio_access_bundle_directory: accessDirectory,
    stdio_access_receipt_count: bundle.finalization.receipt_count,
    stdio_access_chain_head_sha256: bundle.finalization.chain_head_sha256,
    transaction_count: counters.total_transactions,
    completed_transactions: counters.completed_transactions,
    blocked_transactions: counters.blocked_transactions,
    failed_transactions: counters.failed_transactions,
    child_exit_code: exitCode,
    child_signal: signal,
    protocol_subset: MCP_STDIO_PROXY_PROTOCOL_SUBSET,
    claim_boundary: "stdio_calls_through_this_spawned_child_only_not_host_or_container_non_bypassability",
  };
}

function validateToolIdentity(identity: SdkToolIdentity): void {
  assertExactKeys(identity as unknown as Record<string, unknown>, ["interface_sha256", "registry_id", "schema_version", "tool_id", "tool_version"], "guard_mcp_stdio_tool_identity");
  if (identity.schema_version !== "gradia.guard.sdk-tool-identity.v1") throw new Error("guard_mcp_stdio_tool_identity_schema_invalid");
  assertStableId(identity.registry_id, "guard_mcp_stdio_registry_id");
  assertStableId(identity.tool_id, "guard_mcp_stdio_tool_id");
  assertStableId(identity.tool_version, "guard_mcp_stdio_tool_version");
  if (!isSha256(identity.interface_sha256)) throw new Error("guard_mcp_stdio_tool_interface_invalid");
}

function canonicalIds(values: readonly string[], label: string): void {
  if (!Array.isArray(values) || values.length === 0) throw new Error(`${label}_missing`);
  values.forEach((item) => assertStableId(item, label));
  const expected = [...new Set(values)].sort();
  if (canonicalJson(values) !== canonicalJson(expected)) throw new Error(`${label}_not_canonical`);
}

function assertExactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  if (canonicalJson(Object.keys(value).sort()) !== canonicalJson([...expected].sort())) throw new Error(`${label}_keys_invalid`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function waitForSpawn(child: ChildProcessWithoutNullStreams): Promise<void> {
  return new Promise((resolve, reject) => {
    const spawned = (): void => { cleanup(); resolve(); };
    const failed = (): void => { cleanup(); reject(new Error("guard_mcp_stdio_spawn_failed")); };
    const cleanup = (): void => {
      child.off("spawn", spawned);
      child.off("error", failed);
    };
    child.once("spawn", spawned);
    child.once("error", failed);
  });
}

function waitForExit(child: ChildProcessWithoutNullStreams): Promise<void> {
  return new Promise((resolve) => child.once("exit", () => resolve()));
}
