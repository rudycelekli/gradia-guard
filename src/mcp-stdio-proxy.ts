import type { ManagedWorkloadIdentityClient } from "./managed-workload-identity.js";
import { MCP_SESSION_VERSION, McpSessionJournal, type McpSessionProfile } from "./mcp-session-evidence.js";
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
  schema_version: typeof MCP_STDIO_PROXY_CONFIGURATION_SCHEMA_VERSION | "gradia.guard.mcp-stdio-proxy-configuration.v2";
  session?: McpSessionProfile;
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
  /** Rechecks the fixed session identity online; renewal requires a new session. */
  managedIdentity?: ManagedWorkloadIdentityClient;
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
  protocol_subset: typeof MCP_STDIO_PROXY_PROTOCOL_SUBSET | "session_2025_11_25_initialize_discovery_progress_ping_tools_call";
  session_evidence?: { path: string; receipt_count: number; chain_head_sha256: string };
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
 * A bounded newline-delimited JSON-RPC enforcement boundary.
 *
 * The child receives no request bytes until the authenticated adapter allows
 * the exact tool identity and the authorization receipt has been fsync'd.
 * Configuration v2 adds a pinned MCP session, discovery, progress and ping.
 * Configuration v1 retains the original tools/call-only transport. Neither is
 * a host sandbox: another process can spawn or write around this boundary.
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
  private sessionReady = false;
  private catalogEpoch = 0;
  private sessionJournal: McpSessionJournal | null = null;
  private sessionFailure: Error | null = null;
  private progressToken: string | null = null;

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

  /** Advisory cancellation followed by child termination. No acknowledgment or replay is inferred. */
  interrupt(): { cancellation_requested: boolean; cancellation_acknowledged: false; resumable: false } {
    const requested = this.sessionReady && this.pending !== null && this.activeContext !== null && !this.exited;
    if (requested) {
      try { this.writeNotification({ jsonrpc: "2.0", method: "notifications/cancelled",
        params: { requestId: this.pending!.id, reason: "Guard owner interrupted this session" } }); }
      catch { /* Terminate even when the cancellation receipt cannot be appended. */ }
    }
    this.failSession(new Error("guard_mcp_session_interrupted_outcome_unknown"));
    return { cancellation_requested: requested, cancellation_acknowledged: false, resumable: false };
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
    const result = closeResult(
      bundle,
      this.adapter === null ? null : this.sdkDirectory,
      this.accessDirectory,
      this.exitCode,
      this.exitSignal,
    );
    if (this.sessionJournal !== null) {
      result.protocol_subset = "session_2025_11_25_initialize_discovery_progress_ping_tools_call";
      result.session_evidence = this.sessionJournal.finish();
    }
    return result;
  }

  private async invokeSerial(
    input: AuthenticatedMcpToolRequest,
  ): Promise<AuthenticatedMcpToolResult> {
    if (this.sessionFailure !== null) throw this.sessionFailure;
    if (this.options.configuration.session !== undefined) {
      if (!this.sessionReady) throw new Error("guard_mcp_session_not_initialized");
      // Refresh the pinned catalog for each invocation; a notification may arrive
      // after the preceding response and before the next event-loop turn.
      try { await this.discover(); } catch (error) { this.failSession(error as Error); throw error; }
    }
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
      ...(this.options.managedIdentity === undefined ? {} : { managedIdentity: this.options.managedIdentity, renewManagedIdentity: false }),
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
      params: { arguments: args, name: input.toolIdentity.tool_id,
        ...(this.sessionReady ? { _meta: { progressToken: rpcId } } : {}) },
    });
    if (Buffer.byteLength(envelope, "utf8") > MAX_STDIO_LINE_BYTES) {
      throw new Error("guard_mcp_stdio_envelope_too_large");
    }
    this.progressToken = this.sessionReady ? rpcId : null;
    try {
      const response = await this.exchange(rpcId, `${envelope}\n`);
      if (this.sessionFailure !== null) throw this.sessionFailure;
      return responseFor(input, parseRpcResponse(response, rpcId));
    } finally { this.progressToken = null; }
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
      try { this.sessionJournal?.append("request", JSON.parse(line)); }
      catch (error) { this.rejectPending(error as Error); return; }
      if (this.activeContext !== null) this.activeContext.childStdinWriteCalled = true;
      this.child.stdin.write(line, "utf8", (error) => {
        if (error) this.rejectPending(new Error("guard_mcp_stdio_write_failed"));
      });
    });
  }

  private onStdout(chunk: Buffer): void {
    if (this.sessionJournal !== null) { this.onSessionStdout(chunk); return; }
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

  async initializeSession(): Promise<void> {
    const profile = this.options.configuration.session;
    if (profile === undefined) return;
    if (this.sessionJournal !== null) throw new Error("guard_mcp_session_already_initialized");
    this.sessionJournal = new McpSessionJournal(join(this.options.directory, "mcp-session"), {
      configuration_sha256: this.configuration.configuration_sha256,
      workload_identity_sha256: this.options.workloadIdentity.identity_sha256,
      child_launch_sha256: this.childLaunchDeclarationSha256, protocol_version: MCP_SESSION_VERSION,
    });
    try {
      const result = await this.control("initialize", { protocolVersion: MCP_SESSION_VERSION,
        capabilities: {}, clientInfo: { name: "gradia-guard", version: "0.1.0-beta.8" } });
      if (!isRecord(result) || result["protocolVersion"] !== MCP_SESSION_VERSION
        || !isRecord(result["serverInfo"]) || result["serverInfo"]["name"] !== profile.server_name
        || result["serverInfo"]["version"] !== profile.server_version
        || !isRecord(result["capabilities"]) || !isRecord(result["capabilities"]["tools"])) {
        throw new Error("guard_mcp_session_identity_or_version_mismatch");
      }
      this.writeNotification({ jsonrpc: "2.0", method: "notifications/initialized" });
      await this.discover();
      this.sessionReady = true;
    } catch (error) {
      this.sessionFailure = error as Error;
      this.child.kill("SIGKILL");
      throw error;
    }
  }

  private async control(method: string, params: Record<string, unknown>): Promise<unknown> {
    await this.options.managedIdentity?.check(this.options.workloadIdentity);
    verifyWorkloadIdentity(this.options.workloadIdentity, {
      trustedPublicKeys: this.options.trustedPublicKeys,
      expectation: { ...this.options.workloadExpectation,
        requiredAuthorityScopeIds: this.options.workloadIdentity.claims.authority_scope_ids },
      nowUnix: this.options.nowUnix?.() ?? Math.floor(Date.now() / 1000),
      maxLifetimeSeconds: this.options.maxIdentityLifetimeSeconds,
      clockSkewSeconds: this.options.clockSkewSeconds ?? 0,
    });
    const id = `mcp-control-${this.sequence++}-${randomBytes(8).toString("hex")}`;
    const reply = parseRpcResponse(await this.exchange(id, canonicalJson({ jsonrpc: "2.0", id, method, params }) + "\n"), id);
    if (this.sessionFailure !== null) throw this.sessionFailure;
    if (reply.isError) throw new Error("guard_mcp_session_control_refused");
    return reply.result;
  }

  private async discover(refreshesRemaining = 1): Promise<void> {
    const epoch = this.catalogEpoch;
    const tools = new Map<string, Record<string, unknown>>();
    let cursor: string | undefined;
    const seen = new Set<string>();
    for (let page = 0; page < 4; page++) {
      const result = await this.control("tools/list", cursor === undefined ? {} : { cursor });
      if (!isRecord(result) || !Array.isArray(result["tools"]) || result["tools"].length > 256) {
        throw new Error("guard_mcp_session_catalog_invalid");
      }
      for (const tool of result["tools"]) {
        if (!isRecord(tool) || typeof tool["name"] !== "string" || tools.has(tool["name"]) || !isRecord(tool["inputSchema"])) {
          throw new Error("guard_mcp_session_catalog_invalid");
        }
        tools.set(tool["name"], tool);
      }
      if (result["nextCursor"] === undefined) { cursor = undefined; break; }
      if (typeof result["nextCursor"] !== "string" || result["nextCursor"].length > 2048 || seen.has(result["nextCursor"])) {
        throw new Error("guard_mcp_session_cursor_invalid");
      }
      cursor = result["nextCursor"]; seen.add(cursor);
    }
    if (cursor !== undefined) throw new Error("guard_mcp_session_catalog_limit");
    const profile = this.configuration.session as McpSessionProfile;
    for (const route of this.configuration.tool_routes) {
      const tool = tools.get(route.tool_name);
      if (tool === undefined || digestCanonical(tool["inputSchema"]) !== profile.tool_input_schema_sha256[route.tool_name]) {
        throw new Error("guard_mcp_session_tool_schema_changed");
      }
    }
    // Additional server tools confer no authority and are never exposed by Guard.
    if (this.catalogEpoch !== epoch) {
      if (refreshesRemaining === 0) throw new Error("guard_mcp_session_catalog_changed_during_discovery");
      await this.discover(refreshesRemaining - 1);
    }
  }

  private writeNotification(envelope: Record<string, unknown>): void {
    this.sessionJournal?.append("outgoing_notification", envelope);
    this.child.stdin.write(canonicalJson(envelope) + "\n", (error) => {
      if (error) this.failSession(new Error("guard_mcp_session_notification_failed"));
    });
  }

  private failSession(error: Error): void {
    this.sessionFailure = error;
    this.rejectPending(error);
    if (!this.exited) this.child.kill("SIGKILL");
  }

  private onSessionStdout(chunk: Buffer): void {
    try {
      this.stdoutBuffer = Buffer.concat([this.stdoutBuffer, chunk]);
      if (this.stdoutBuffer.length > MAX_STDIO_LINE_BYTES) throw new Error("guard_mcp_session_response_too_large");
      for (;;) {
        const end = this.stdoutBuffer.indexOf(0x0a);
        if (end < 0) break;
        const line = this.stdoutBuffer.subarray(0, end).toString("utf8");
        this.stdoutBuffer = this.stdoutBuffer.subarray(end + 1);
        const message: unknown = JSON.parse(line);
        if (!isRecord(message) || message["jsonrpc"] !== "2.0") throw new Error("guard_mcp_session_envelope_invalid");
        this.sessionJournal?.append("incoming", message);
        if (typeof message["method"] === "string") {
          if (Object.keys(message).some(key => !["jsonrpc", "method", "id", "params"].includes(key))
            || (message["params"] !== undefined && !isRecord(message["params"]))) throw new Error("guard_mcp_session_envelope_invalid");
          if (message["id"] !== undefined) {
            if (message["method"] !== "ping" || typeof message["id"] !== "string" && typeof message["id"] !== "number") {
              throw new Error("guard_mcp_session_server_request_not_supported");
            }
            this.writeNotification({ jsonrpc: "2.0", id: message["id"], result: {} });
          } else if (message["method"] === "notifications/tools/list_changed") {
            this.catalogEpoch++;
          } else if (message["method"] === "notifications/progress") {
            const params = message["params"];
            if (!isRecord(params) || this.progressToken === null || params["progressToken"] !== this.progressToken
              || typeof params["progress"] !== "number" || !Number.isFinite(params["progress"]) || params["progress"] < 0
              || (params["total"] !== undefined && (typeof params["total"] !== "number"
                || !Number.isFinite(params["total"]) || params["total"] < params["progress"]))) {
              throw new Error("guard_mcp_session_progress_invalid");
            }
          } else throw new Error("guard_mcp_session_notification_not_supported");
          continue;
        }
        const pending = this.pending;
        if (pending === null || message["id"] !== pending.id) throw new Error("guard_mcp_session_response_id_invalid");
        parseRpcResponse(message, pending.id);
        this.pending = null; clearTimeout(pending.timeout); pending.resolve(message);
      }
    } catch (error) { this.failSession(error as Error); }
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
    ...(configuration.session === undefined ? [] : ["session"]),
  ], "guard_mcp_stdio_configuration");
  const body: GuardMcpStdioProxyConfigurationBody = {
    schema_version: configuration.schema_version,
    configuration_id: configuration.configuration_id,
    configuration_version: configuration.configuration_version,
    default_decision: configuration.default_decision,
    server_id: configuration.server_id,
    tool_routes: configuration.tool_routes,
    ...(configuration.session === undefined ? {} : { session: configuration.session }),
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
  await options.managedIdentity?.check(options.workloadIdentity);
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
  try { await proxy.initializeSession(); }
  catch (error) { await proxy.close(); throw error; }
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
    ...(body.session === undefined ? [] : ["session"]),
  ], "guard_mcp_stdio_configuration_body");
  if (body.schema_version !== MCP_STDIO_PROXY_CONFIGURATION_SCHEMA_VERSION
    && body.schema_version !== "gradia.guard.mcp-stdio-proxy-configuration.v2") throw new Error("guard_mcp_stdio_configuration_schema_invalid");
  if ((body.schema_version === "gradia.guard.mcp-stdio-proxy-configuration.v2") !== (body.session !== undefined)) {
    throw new Error("guard_mcp_stdio_session_profile_required");
  }
  if (body.session !== undefined) {
    assertExactKeys(body.session as unknown as Record<string, unknown>,
      ["protocol_version", "server_name", "server_version", "tool_input_schema_sha256"], "guard_mcp_session_profile");
    if (body.session.protocol_version !== MCP_SESSION_VERSION || !isRecord(body.session.tool_input_schema_sha256)) {
      throw new Error("guard_mcp_session_profile_invalid");
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,199}$/.test(body.session.server_name)) throw new Error("guard_mcp_server_name_invalid");
    assertStableId(body.session.server_version, "guard_mcp_server_version");
    if (Object.keys(body.session.tool_input_schema_sha256).sort().join() !== body.tool_routes.map(r => r.tool_name).sort().join()
      || Object.values(body.session.tool_input_schema_sha256).some(v => !isSha256(v))) {
      throw new Error("guard_mcp_session_schema_pins_invalid");
    }
  }
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
