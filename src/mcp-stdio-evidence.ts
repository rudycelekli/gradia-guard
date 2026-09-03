import { randomBytes } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { canonicalJson, digestCanonical, isSha256 } from "./canonical.js";
import { assertStableId } from "./security.js";

export const MCP_STDIO_ACCESS_HEADER_SCHEMA_VERSION =
  "gradia.guard.mcp-stdio-access-header.v1" as const;
export const MCP_STDIO_ACCESS_RECEIPT_SCHEMA_VERSION =
  "gradia.guard.mcp-stdio-access-receipt.v1" as const;
export const MCP_STDIO_ACCESS_FINALIZATION_SCHEMA_VERSION =
  "gradia.guard.mcp-stdio-access-finalization.v1" as const;
export const MCP_STDIO_ACCESS_GENESIS_SHA256 = "0".repeat(64);

export type McpStdioAuthorizationDecision = "allowed" | "blocked";
export type McpStdioTerminalDisposition =
  | "blocked"
  | "completed"
  | "tool_failure"
  | "protocol_failure"
  | "identity_mismatch"
  | "interrupted_unknown";

export interface McpStdioAccessHeaderBody {
  schema_version: typeof MCP_STDIO_ACCESS_HEADER_SCHEMA_VERSION;
  session_id: string;
  created_at: string;
  capture_boundary: "authenticated_mcp_stdio_dispatcher";
  bypass_possible: true;
  bypass_declaration:
    "direct_child_processes_other_stdio_paths_and_parent_crashes_before_authorization_fsync_are_not_observed_or_blocked";
  payload_retention: "digest_only";
  protocol_subset:
    "stateless_newline_delimited_json_rpc_tools_call_only_no_initialize_initialized_discovery_notifications_streaming_or_multi_round";
  resolved_identity_attestation: "configuration_bound_not_child_attested";
  crash_recovery_supported: true;
  configuration_sha256: string;
  policy_sha256: string;
  workload_identity_sha256: string;
  child_launch_declaration_sha256: string;
  child_launch_binding:
    "declared_absolute_path_arguments_empty_environment_and_shell_false_not_executable_bytes_or_child_identity";
}

export interface McpStdioAccessHeader extends McpStdioAccessHeaderBody {
  header_sha256: string;
}

export interface McpStdioAuthorizationReceiptBody {
  schema_version: typeof MCP_STDIO_ACCESS_RECEIPT_SCHEMA_VERSION;
  session_id: string;
  header_sha256: string;
  sequence: number;
  receipt_kind: "authorization";
  request_id: string;
  logical_operation_id: string;
  attempt_number: number;
  observed_at: string;
  previous_receipt_sha256: string;
  route_sha256: string;
  request_sha256: string;
  request_byte_length: number;
  authorization_decision: McpStdioAuthorizationDecision;
  child_stdin_write_called: false;
  reason_code: "adapter_allowed" | "adapter_blocked";
  recovery_synthesized: false;
}

export interface McpStdioTerminalReceiptBody {
  schema_version: typeof MCP_STDIO_ACCESS_RECEIPT_SCHEMA_VERSION;
  session_id: string;
  header_sha256: string;
  sequence: number;
  receipt_kind: "terminal";
  request_id: string;
  logical_operation_id: string;
  attempt_number: number;
  observed_at: string;
  previous_receipt_sha256: string;
  route_sha256: string;
  request_sha256: string;
  request_byte_length: number;
  authorization_receipt_sha256: string;
  terminal_disposition: McpStdioTerminalDisposition;
  child_stdin_write_called: boolean | null;
  sdk_occurrence_sha256: string | null;
  reason_code:
    | "adapter_blocked"
    | "adapter_completed"
    | "adapter_tool_failure"
    | "adapter_protocol_failure"
    | "adapter_identity_mismatch"
    | "recovered_after_interruption";
  recovery_synthesized: boolean;
}

export type McpStdioAccessReceiptBody =
  | McpStdioAuthorizationReceiptBody
  | McpStdioTerminalReceiptBody;
export type McpStdioAccessReceipt = McpStdioAccessReceiptBody & {
  receipt_sha256: string;
};

export interface McpStdioAccessCounters {
  total_transactions: number;
  allowed_transactions: number;
  blocked_transactions: number;
  completed_transactions: number;
  failed_transactions: number;
  interrupted_unknown_transactions: number;
}

export interface McpStdioAccessFinalizationBody {
  schema_version: typeof MCP_STDIO_ACCESS_FINALIZATION_SCHEMA_VERSION;
  session_id: string;
  header_sha256: string;
  finalized_at: string;
  receipt_count: number;
  chain_head_sha256: string;
  counters: McpStdioAccessCounters;
  terminal_status: "completed" | "recovered_interruption";
  recovery_performed: boolean;
}

export interface McpStdioAccessFinalization extends McpStdioAccessFinalizationBody {
  finalization_sha256: string;
}

export interface McpStdioAccessBundle {
  header: McpStdioAccessHeader;
  receipts: readonly McpStdioAccessReceipt[];
  finalization: McpStdioAccessFinalization;
}

export interface McpStdioAccessVerification {
  ok: boolean;
  blockers: readonly string[];
  session_id: string | null;
  receipt_count: number;
  chain_head_sha256: string | null;
  counters: McpStdioAccessCounters | null;
  claim_boundary:
    "stdio_calls_through_this_dispatcher_only_not_host_or_container_non_bypassability";
}

export interface McpStdioTransactionInput {
  requestId: string;
  logicalOperationId: string;
  attemptNumber: number;
  routeSha256: string;
  requestSha256: string;
  requestByteLength: number;
}

export interface McpStdioAccessRecorderOptions {
  directory: string;
  sessionId?: string;
  createdAt: string;
  configurationSha256: string;
  policySha256: string;
  workloadIdentitySha256: string;
  childLaunchDeclarationSha256: string;
  now: () => string;
}

interface OpenTransaction extends McpStdioTransactionInput {
  authorizationReceiptSha256: string;
  authorizationDecision: McpStdioAuthorizationDecision;
}

type McpStdioReceiptAppendInput =
  | Omit<McpStdioAuthorizationReceiptBody, "schema_version" | "session_id" | "header_sha256" | "sequence" | "observed_at" | "previous_receipt_sha256">
  | Omit<McpStdioTerminalReceiptBody, "schema_version" | "session_id" | "header_sha256" | "sequence" | "observed_at" | "previous_receipt_sha256">;

/**
 * Digest-only, fsync-backed evidence for one declared MCP stdio dispatcher.
 * An allowed authorization is persisted before the dispatcher may write bytes.
 */
export class DurableMcpStdioAccessRecorder {
  readonly directory: string;
  readonly headerPath: string;
  readonly receiptsPath: string;
  readonly bundlePath: string;
  readonly header: McpStdioAccessHeader;
  private readonly now: () => string;
  private receiptList: McpStdioAccessReceipt[];
  private open: Map<string, OpenTransaction>;
  private recoveredFromInterruption: boolean;
  private finalized = false;

  constructor(options: McpStdioAccessRecorderOptions) {
    if (existsSync(options.directory)) throw new Error("mcp_stdio_access_directory_exists");
    for (const [field, value] of [
      ["configuration", options.configurationSha256],
      ["policy", options.policySha256],
      ["workload_identity", options.workloadIdentitySha256],
      ["child_launch_declaration", options.childLaunchDeclarationSha256],
    ] as const) {
      if (!isSha256(value)) throw new Error(`mcp_stdio_access_${field}_digest_invalid`);
    }
    const sessionId = options.sessionId ?? `mcp-stdio-${randomBytes(16).toString("hex")}`;
    assertStableId(sessionId, "mcp_stdio_access_session_id");
    requireTimestamp(options.createdAt, "mcp_stdio_access_created_at_invalid");
    const body: McpStdioAccessHeaderBody = {
      schema_version: MCP_STDIO_ACCESS_HEADER_SCHEMA_VERSION,
      session_id: sessionId,
      created_at: options.createdAt,
      capture_boundary: "authenticated_mcp_stdio_dispatcher",
      bypass_possible: true,
      bypass_declaration:
        "direct_child_processes_other_stdio_paths_and_parent_crashes_before_authorization_fsync_are_not_observed_or_blocked",
      payload_retention: "digest_only",
      protocol_subset:
        "stateless_newline_delimited_json_rpc_tools_call_only_no_initialize_initialized_discovery_notifications_streaming_or_multi_round",
      resolved_identity_attestation: "configuration_bound_not_child_attested",
      crash_recovery_supported: true,
      configuration_sha256: options.configurationSha256,
      policy_sha256: options.policySha256,
      workload_identity_sha256: options.workloadIdentitySha256,
      child_launch_declaration_sha256: options.childLaunchDeclarationSha256,
      child_launch_binding:
        "declared_absolute_path_arguments_empty_environment_and_shell_false_not_executable_bytes_or_child_identity",
    };
    this.header = { ...body, header_sha256: digestCanonical(body) };
    this.directory = options.directory;
    this.headerPath = join(options.directory, "header.json");
    this.receiptsPath = join(options.directory, "receipts.ndjson");
    this.bundlePath = join(options.directory, "bundle.json");
    this.now = options.now;
    this.receiptList = [];
    this.open = new Map();
    this.recoveredFromInterruption = false;
    mkdirSync(options.directory, { recursive: true, mode: 0o700 });
    writeDurableCanonical(this.headerPath, this.header);
    writeDurableNewFile(this.receiptsPath, "");
  }

  private static fromRecovered(
    directory: string,
    header: McpStdioAccessHeader,
    receipts: McpStdioAccessReceipt[],
    now: () => string,
  ): DurableMcpStdioAccessRecorder {
    const recorder = Object.create(
      DurableMcpStdioAccessRecorder.prototype,
    ) as DurableMcpStdioAccessRecorder;
    Object.defineProperties(recorder, {
      directory: { value: directory, enumerable: true },
      headerPath: { value: join(directory, "header.json"), enumerable: true },
      receiptsPath: { value: join(directory, "receipts.ndjson"), enumerable: true },
      bundlePath: { value: join(directory, "bundle.json"), enumerable: true },
      header: { value: header, enumerable: true },
      now: { value: now },
      receiptList: { value: receipts, writable: true },
      open: { value: openTransactions(receipts), writable: true },
      recoveredFromInterruption: { value: true, writable: true },
      finalized: { value: false, writable: true },
    });
    return recorder;
  }

  static recover(directory: string, now: () => string): DurableMcpStdioAccessRecorder {
    if (existsSync(join(directory, "bundle.json"))) {
      throw new Error("mcp_stdio_access_already_finalized");
    }
    const prefix = readPrefix(directory);
    if (prefix.blockers.length > 0 || prefix.header === null) {
      throw new Error(`mcp_stdio_access_recovery_invalid:${prefix.blockers.join(",")}`);
    }
    return DurableMcpStdioAccessRecorder.fromRecovered(
      directory,
      prefix.header,
      [...prefix.receipts],
      now,
    );
  }

  get receipts(): readonly McpStdioAccessReceipt[] {
    return Object.freeze([...this.receiptList]);
  }

  authorize(
    input: McpStdioTransactionInput,
    decision: McpStdioAuthorizationDecision,
  ): McpStdioAccessReceipt {
    if (this.finalized) throw new Error("mcp_stdio_access_post_finalization_write");
    if (this.recoveredFromInterruption) throw new Error("mcp_stdio_access_recovered_session_write");
    validateTransaction(input);
    if (this.open.has(input.requestId) || this.receiptList.some((item) => item.request_id === input.requestId)) {
      throw new Error("mcp_stdio_access_request_id_reused");
    }
    const receipt = this.appendReceipt({
      receipt_kind: "authorization",
      ...transactionFields(input),
      authorization_decision: decision,
      child_stdin_write_called: false,
      reason_code: decision === "allowed" ? "adapter_allowed" : "adapter_blocked",
      recovery_synthesized: false,
    });
    this.open.set(input.requestId, {
      ...input,
      authorizationReceiptSha256: receipt.receipt_sha256,
      authorizationDecision: decision,
    });
    return receipt;
  }

  terminal(
    requestId: string,
    disposition: Exclude<McpStdioTerminalDisposition, "interrupted_unknown">,
    sdkOccurrenceSha256: string,
    childStdinWriteCalled: boolean,
  ): McpStdioAccessReceipt {
    if (this.finalized) throw new Error("mcp_stdio_access_post_finalization_write");
    if (this.recoveredFromInterruption) throw new Error("mcp_stdio_access_recovered_session_write");
    if (!isSha256(sdkOccurrenceSha256)) throw new Error("mcp_stdio_access_sdk_occurrence_invalid");
    const active = this.requireOpen(requestId);
    if ((active.authorizationDecision === "blocked") !== (disposition === "blocked")) {
      throw new Error("mcp_stdio_access_authorization_terminal_mismatch");
    }
    if (active.authorizationDecision === "blocked" && childStdinWriteCalled) {
      throw new Error("mcp_stdio_access_blocked_dispatch_claim");
    }
    const receipt = this.appendTerminal(
      active,
      disposition,
      sdkOccurrenceSha256,
      childStdinWriteCalled,
      false,
    );
    this.open.delete(requestId);
    return receipt;
  }

  finalize(): McpStdioAccessBundle {
    if (this.finalized) throw new Error("mcp_stdio_access_already_finalized");
    if (!this.recoveredFromInterruption && this.open.size > 0) {
      throw new Error("mcp_stdio_access_open_transactions_prevent_finalization");
    }
    if (this.recoveredFromInterruption) {
      for (const active of [...this.open.values()].sort((a, b) => a.requestId.localeCompare(b.requestId))) {
        this.appendTerminal(active, "interrupted_unknown", null, null, true);
        this.open.delete(active.requestId);
      }
    }
    const finalizedAt = this.now();
    requireTimestamp(finalizedAt, "mcp_stdio_access_finalized_at_invalid");
    const body: McpStdioAccessFinalizationBody = {
      schema_version: MCP_STDIO_ACCESS_FINALIZATION_SCHEMA_VERSION,
      session_id: this.header.session_id,
      header_sha256: this.header.header_sha256,
      finalized_at: finalizedAt,
      receipt_count: this.receiptList.length,
      chain_head_sha256:
        this.receiptList.at(-1)?.receipt_sha256 ?? MCP_STDIO_ACCESS_GENESIS_SHA256,
      counters: countersFor(this.receiptList),
      terminal_status: this.recoveredFromInterruption ? "recovered_interruption" : "completed",
      recovery_performed: this.recoveredFromInterruption,
    };
    const finalization: McpStdioAccessFinalization = {
      ...body,
      finalization_sha256: digestCanonical(body),
    };
    const bundle: McpStdioAccessBundle = {
      header: this.header,
      receipts: [...this.receiptList],
      finalization,
    };
    const checked = verifyMcpStdioAccessBundle(bundle);
    if (!checked.ok) {
      throw new Error(`mcp_stdio_access_bundle_unverified:${checked.blockers.join(",")}`);
    }
    writeDurableCanonicalExclusive(this.bundlePath, bundle, "mcp_stdio_access_bundle_exists");
    this.finalized = true;
    return bundle;
  }

  private appendTerminal(
    active: OpenTransaction,
    disposition: McpStdioTerminalDisposition,
    sdkOccurrenceSha256: string | null,
    childStdinWriteCalled: boolean | null,
    recovered: boolean,
  ): McpStdioAccessReceipt {
    const reason = disposition === "interrupted_unknown"
      ? "recovered_after_interruption"
      : disposition === "blocked"
        ? "adapter_blocked"
        : disposition === "completed"
          ? "adapter_completed"
          : disposition === "tool_failure"
            ? "adapter_tool_failure"
            : disposition === "protocol_failure"
              ? "adapter_protocol_failure"
              : "adapter_identity_mismatch";
    return this.appendReceipt({
      receipt_kind: "terminal",
      ...transactionFields(active),
      authorization_receipt_sha256: active.authorizationReceiptSha256,
      terminal_disposition: disposition,
      child_stdin_write_called: childStdinWriteCalled,
      sdk_occurrence_sha256: sdkOccurrenceSha256,
      reason_code: reason,
      recovery_synthesized: recovered,
    });
  }

  private appendReceipt(
    input: McpStdioReceiptAppendInput,
  ): McpStdioAccessReceipt {
    const observedAt = this.now();
    requireTimestamp(observedAt, "mcp_stdio_access_observed_at_invalid");
    const body = {
      schema_version: MCP_STDIO_ACCESS_RECEIPT_SCHEMA_VERSION,
      session_id: this.header.session_id,
      header_sha256: this.header.header_sha256,
      sequence: this.receiptList.length,
      observed_at: observedAt,
      previous_receipt_sha256:
        this.receiptList.at(-1)?.receipt_sha256 ?? MCP_STDIO_ACCESS_GENESIS_SHA256,
      ...input,
    } as McpStdioAccessReceiptBody;
    const receipt = { ...body, receipt_sha256: digestCanonical(body) } as McpStdioAccessReceipt;
    const candidate = [...this.receiptList, receipt];
    const blockers = prefixBlockers(this.header, candidate, false);
    if (blockers.length > 0) {
      throw new Error(`mcp_stdio_access_receipt_invalid:${blockers.join(",")}`);
    }
    appendDurableLine(this.receiptsPath, canonicalJson(receipt));
    this.receiptList = candidate;
    return receipt;
  }

  private requireOpen(requestId: string): OpenTransaction {
    assertStableId(requestId, "mcp_stdio_access_request_id");
    const active = this.open.get(requestId);
    if (!active) throw new Error("mcp_stdio_access_transaction_not_open");
    return active;
  }
}

export function verifyMcpStdioAccessBundle(value: unknown): McpStdioAccessVerification {
  const blockers = new Set<string>();
  if (!isRecord(value)) return verification(["mcp_stdio_access_bundle_shape_invalid"]);
  exactKeys(value, ["finalization", "header", "receipts"], "mcp_stdio_access_bundle", blockers);
  let header: McpStdioAccessHeader | null = null;
  let receipts: McpStdioAccessReceipt[] = [];
  if (isRecord(value["header"])) {
    try {
      header = parseHeader(value["header"]);
    } catch {
      blockers.add("mcp_stdio_access_header_schema_invalid");
    }
  } else blockers.add("mcp_stdio_access_header_shape_invalid");
  if (Array.isArray(value["receipts"])) {
    try {
      receipts = value["receipts"].map(parseReceipt);
    } catch {
      blockers.add("mcp_stdio_access_receipts_schema_invalid");
    }
  } else blockers.add("mcp_stdio_access_receipts_shape_invalid");
  if (header !== null) prefixBlockers(header, receipts, true).forEach((item) => blockers.add(item));
  const rawFinalization = value["finalization"];
  let counters: McpStdioAccessCounters | null = null;
  if (!isRecord(rawFinalization)) blockers.add("mcp_stdio_access_finalization_shape_invalid");
  else if (header !== null) {
    try {
      const finalization = parseFinalization(rawFinalization);
      counters = countersFor(receipts);
      const head = receipts.at(-1)?.receipt_sha256 ?? MCP_STDIO_ACCESS_GENESIS_SHA256;
      if (finalization.session_id !== header.session_id) blockers.add("mcp_stdio_access_finalization_session_mismatch");
      if (finalization.header_sha256 !== header.header_sha256) blockers.add("mcp_stdio_access_finalization_header_mismatch");
      if (finalization.receipt_count !== receipts.length) blockers.add("mcp_stdio_access_finalization_count_mismatch");
      if (finalization.chain_head_sha256 !== head) blockers.add("mcp_stdio_access_finalization_head_mismatch");
      if (finalization.finalized_at < (receipts.at(-1)?.observed_at ?? header.created_at)) blockers.add("mcp_stdio_access_finalization_precedes_receipts");
      if (canonicalJson(finalization.counters) !== canonicalJson(counters)) blockers.add("mcp_stdio_access_finalization_counters_mismatch");
      if (finalization.finalization_sha256 !== digestCanonical(withoutKey(finalization as unknown as Record<string, unknown>, "finalization_sha256"))) blockers.add("mcp_stdio_access_finalization_digest_mismatch");
      const synthesized = receipts.some((item) => item.receipt_kind === "terminal" && item.recovery_synthesized);
      if (synthesized && !finalization.recovery_performed) blockers.add("mcp_stdio_access_recovery_flag_mismatch");
      if ((finalization.terminal_status === "recovered_interruption") !== finalization.recovery_performed) blockers.add("mcp_stdio_access_terminal_status_mismatch");
    } catch {
      blockers.add("mcp_stdio_access_finalization_schema_invalid");
    }
  }
  const result = [...blockers].sort();
  return {
    ok: result.length === 0,
    blockers: Object.freeze(result),
    session_id: header?.session_id ?? null,
    receipt_count: receipts.length,
    chain_head_sha256: receipts.at(-1)?.receipt_sha256 ?? (header === null ? null : MCP_STDIO_ACCESS_GENESIS_SHA256),
    counters,
    claim_boundary: "stdio_calls_through_this_dispatcher_only_not_host_or_container_non_bypassability",
  };
}

export function verifyMcpStdioAccessBundleDirectory(directory: string): McpStdioAccessVerification {
  try {
    const text = readFileSync(join(directory, "bundle.json"), "utf8");
    const parsed = JSON.parse(text) as unknown;
    const checked = verifyMcpStdioAccessBundle(parsed);
    if (`${canonicalJson(parsed)}\n` !== text) {
      return { ...checked, ok: false, blockers: [...checked.blockers, "mcp_stdio_access_bundle_file_noncanonical"].sort() };
    }
    return checked;
  } catch {
    return verification(["mcp_stdio_access_bundle_unreadable"]);
  }
}

interface PrefixReadResult {
  blockers: readonly string[];
  header: McpStdioAccessHeader | null;
  receipts: readonly McpStdioAccessReceipt[];
}

function readPrefix(directory: string): PrefixReadResult {
  const blockers = new Set<string>();
  let header: McpStdioAccessHeader | null = null;
  let receipts: McpStdioAccessReceipt[] = [];
  try {
    const text = readFileSync(join(directory, "header.json"), "utf8");
    const value = JSON.parse(text) as unknown;
    header = parseHeader(value);
    if (`${canonicalJson(value)}\n` !== text) blockers.add("mcp_stdio_access_header_file_noncanonical");
  } catch {
    blockers.add("mcp_stdio_access_header_unreadable");
  }
  try {
    const text = readFileSync(join(directory, "receipts.ndjson"), "utf8");
    if (text.length > 0 && !text.endsWith("\n")) blockers.add("mcp_stdio_access_journal_truncated");
    receipts = text.split("\n").filter(Boolean).map((line, index) => {
      try {
        const value = JSON.parse(line) as unknown;
        if (canonicalJson(value) !== line) blockers.add(`mcp_stdio_access_journal_noncanonical:${index}`);
        return parseReceipt(value);
      } catch {
        blockers.add(`mcp_stdio_access_journal_json_invalid:${index}`);
        return null;
      }
    }).filter((item): item is McpStdioAccessReceipt => item !== null);
  } catch {
    blockers.add("mcp_stdio_access_journal_unreadable");
  }
  if (header !== null) prefixBlockers(header, receipts, false).forEach((item) => blockers.add(item));
  return { blockers: [...blockers].sort(), header, receipts };
}

function prefixBlockers(
  header: McpStdioAccessHeader,
  receipts: readonly McpStdioAccessReceipt[],
  requireClosed: boolean,
): string[] {
  const blockers = new Set<string>();
  if (header.header_sha256 !== digestCanonical(withoutKey(header as unknown as Record<string, unknown>, "header_sha256"))) blockers.add("mcp_stdio_access_header_digest_mismatch");
  let head = MCP_STDIO_ACCESS_GENESIS_SHA256;
  let lastTime = header.created_at;
  const open = new Map<string, McpStdioAuthorizationReceiptBody & { receipt_sha256: string }>();
  const seen = new Set<string>();
  receipts.forEach((receipt, index) => {
    if (receipt.session_id !== header.session_id) blockers.add(`mcp_stdio_access_receipt_session_mismatch:${index}`);
    if (receipt.header_sha256 !== header.header_sha256) blockers.add(`mcp_stdio_access_receipt_header_mismatch:${index}`);
    if (receipt.sequence !== index) blockers.add(`mcp_stdio_access_receipt_sequence_gap:${index}`);
    if (receipt.previous_receipt_sha256 !== head) blockers.add(`mcp_stdio_access_receipt_predecessor_mismatch:${index}`);
    if (receipt.receipt_sha256 !== digestCanonical(withoutKey(receipt as unknown as Record<string, unknown>, "receipt_sha256"))) blockers.add(`mcp_stdio_access_receipt_digest_mismatch:${index}`);
    if (receipt.observed_at < lastTime) blockers.add(`mcp_stdio_access_timestamp_regressed:${index}`);
    if (receipt.receipt_kind === "authorization") {
      if (seen.has(receipt.request_id)) blockers.add(`mcp_stdio_access_request_id_reused:${index}`);
      seen.add(receipt.request_id);
      open.set(receipt.request_id, receipt);
    } else {
      const auth = open.get(receipt.request_id);
      if (!auth || receipt.authorization_receipt_sha256 !== auth.receipt_sha256) blockers.add(`mcp_stdio_access_authorization_binding_missing:${index}`);
      else {
        const same = auth.logical_operation_id === receipt.logical_operation_id
          && auth.attempt_number === receipt.attempt_number
          && auth.route_sha256 === receipt.route_sha256
          && auth.request_sha256 === receipt.request_sha256
          && auth.request_byte_length === receipt.request_byte_length;
        if (!same) blockers.add(`mcp_stdio_access_transaction_binding_mismatch:${index}`);
        if (auth.authorization_decision === "allowed" && receipt.terminal_disposition === "blocked") blockers.add(`mcp_stdio_access_authorization_terminal_mismatch:${index}`);
        if (auth.authorization_decision === "blocked" && !["blocked", "interrupted_unknown"].includes(receipt.terminal_disposition)) blockers.add(`mcp_stdio_access_authorization_terminal_mismatch:${index}`);
        if (auth.authorization_decision === "blocked" && receipt.child_stdin_write_called === true) blockers.add(`mcp_stdio_access_blocked_write_claim:${index}`);
        if (["completed", "identity_mismatch"].includes(receipt.terminal_disposition) && receipt.child_stdin_write_called !== true) blockers.add(`mcp_stdio_access_completed_without_write_call:${index}`);
        open.delete(receipt.request_id);
      }
      if (receipt.terminal_disposition === "interrupted_unknown") {
        if (!receipt.recovery_synthesized || receipt.sdk_occurrence_sha256 !== null || receipt.child_stdin_write_called !== null) blockers.add(`mcp_stdio_access_recovery_shape_invalid:${index}`);
      } else if (receipt.recovery_synthesized || !isSha256(receipt.sdk_occurrence_sha256) || receipt.child_stdin_write_called === null) blockers.add(`mcp_stdio_access_sdk_binding_invalid:${index}`);
    }
    head = receipt.receipt_sha256;
    lastTime = receipt.observed_at;
  });
  if (requireClosed && open.size > 0) blockers.add("mcp_stdio_access_open_transactions");
  return [...blockers].sort();
}

function openTransactions(receipts: readonly McpStdioAccessReceipt[]): Map<string, OpenTransaction> {
  const result = new Map<string, OpenTransaction>();
  for (const receipt of receipts) {
    if (receipt.receipt_kind === "authorization") {
      result.set(receipt.request_id, {
        requestId: receipt.request_id,
        logicalOperationId: receipt.logical_operation_id,
        attemptNumber: receipt.attempt_number,
        routeSha256: receipt.route_sha256,
        requestSha256: receipt.request_sha256,
        requestByteLength: receipt.request_byte_length,
        authorizationReceiptSha256: receipt.receipt_sha256,
        authorizationDecision: receipt.authorization_decision,
      });
    } else result.delete(receipt.request_id);
  }
  return result;
}

function parseHeader(value: unknown): McpStdioAccessHeader {
  const record = requireRecord(value);
  const blockers = new Set<string>();
  exactKeys(record, ["bypass_declaration", "bypass_possible", "capture_boundary", "child_launch_binding", "child_launch_declaration_sha256", "configuration_sha256", "crash_recovery_supported", "created_at", "header_sha256", "payload_retention", "policy_sha256", "protocol_subset", "resolved_identity_attestation", "schema_version", "session_id", "workload_identity_sha256"], "mcp_stdio_access_header", blockers);
  if (blockers.size > 0) throw new Error("mcp_stdio_access_header_fields_invalid");
  if (record["schema_version"] !== MCP_STDIO_ACCESS_HEADER_SCHEMA_VERSION
    || record["capture_boundary"] !== "authenticated_mcp_stdio_dispatcher"
    || record["bypass_possible"] !== true
    || record["bypass_declaration"] !== "direct_child_processes_other_stdio_paths_and_parent_crashes_before_authorization_fsync_are_not_observed_or_blocked"
    || record["payload_retention"] !== "digest_only"
    || record["protocol_subset"] !== "stateless_newline_delimited_json_rpc_tools_call_only_no_initialize_initialized_discovery_notifications_streaming_or_multi_round"
    || record["resolved_identity_attestation"] !== "configuration_bound_not_child_attested"
    || record["child_launch_binding"] !== "declared_absolute_path_arguments_empty_environment_and_shell_false_not_executable_bytes_or_child_identity"
    || record["crash_recovery_supported"] !== true) throw new Error("mcp_stdio_access_header_contract_invalid");
  assertStableId(String(record["session_id"]), "mcp_stdio_access_session_id");
  requireTimestamp(record["created_at"], "mcp_stdio_access_created_at_invalid");
  for (const field of ["child_launch_declaration_sha256", "configuration_sha256", "header_sha256", "policy_sha256", "workload_identity_sha256"] as const) if (!isSha256(record[field])) throw new Error("mcp_stdio_access_header_digest_invalid");
  return record as unknown as McpStdioAccessHeader;
}

function parseReceipt(value: unknown): McpStdioAccessReceipt {
  const record = requireRecord(value);
  const common = ["attempt_number", "header_sha256", "logical_operation_id", "observed_at", "previous_receipt_sha256", "receipt_kind", "receipt_sha256", "request_byte_length", "request_id", "request_sha256", "route_sha256", "schema_version", "sequence", "session_id"];
  const kind = record["receipt_kind"];
  const expected = kind === "authorization"
    ? [...common, "authorization_decision", "child_stdin_write_called", "reason_code", "recovery_synthesized"]
    : [...common, "authorization_receipt_sha256", "child_stdin_write_called", "reason_code", "recovery_synthesized", "sdk_occurrence_sha256", "terminal_disposition"];
  const fieldBlockers = new Set<string>();
  exactKeys(record, expected, "mcp_stdio_access_receipt", fieldBlockers);
  if (fieldBlockers.size > 0) throw new Error("mcp_stdio_access_receipt_fields_invalid");
  if (record["schema_version"] !== MCP_STDIO_ACCESS_RECEIPT_SCHEMA_VERSION) throw new Error("mcp_stdio_access_receipt_schema_invalid");
  assertStableId(String(record["request_id"]), "mcp_stdio_access_request_id");
  assertStableId(String(record["logical_operation_id"]), "mcp_stdio_access_logical_operation_id");
  requireTimestamp(record["observed_at"], "mcp_stdio_access_observed_at_invalid");
  if (!Number.isSafeInteger(record["sequence"]) || Number(record["sequence"]) < 0) throw new Error("mcp_stdio_access_sequence_invalid");
  if (!Number.isSafeInteger(record["attempt_number"]) || Number(record["attempt_number"]) < 1) throw new Error("mcp_stdio_access_attempt_invalid");
  if (!Number.isSafeInteger(record["request_byte_length"]) || Number(record["request_byte_length"]) < 0) throw new Error("mcp_stdio_access_request_length_invalid");
  for (const field of ["header_sha256", "previous_receipt_sha256", "receipt_sha256", "request_sha256", "route_sha256"] as const) if (!isSha256(record[field])) throw new Error("mcp_stdio_access_receipt_digest_invalid");
  if (kind === "authorization") {
    if (!["allowed", "blocked"].includes(String(record["authorization_decision"])) || record["child_stdin_write_called"] !== false || record["recovery_synthesized"] !== false) throw new Error("mcp_stdio_access_authorization_shape_invalid");
    const expectedReason = record["authorization_decision"] === "allowed" ? "adapter_allowed" : "adapter_blocked";
    if (record["reason_code"] !== expectedReason) throw new Error("mcp_stdio_access_authorization_reason_invalid");
  } else if (kind === "terminal") {
    if (!isSha256(record["authorization_receipt_sha256"])) throw new Error("mcp_stdio_access_authorization_digest_invalid");
    if (!["blocked", "completed", "tool_failure", "protocol_failure", "identity_mismatch", "interrupted_unknown"].includes(String(record["terminal_disposition"]))) throw new Error("mcp_stdio_access_terminal_disposition_invalid");
    if (record["child_stdin_write_called"] !== null && typeof record["child_stdin_write_called"] !== "boolean") throw new Error("mcp_stdio_access_terminal_shape_invalid");
    if (typeof record["recovery_synthesized"] !== "boolean") throw new Error("mcp_stdio_access_terminal_shape_invalid");
    if (record["sdk_occurrence_sha256"] !== null && !isSha256(record["sdk_occurrence_sha256"])) throw new Error("mcp_stdio_access_sdk_occurrence_invalid");
    const disposition = String(record["terminal_disposition"]);
    const expectedReason = disposition === "interrupted_unknown"
      ? "recovered_after_interruption"
      : disposition === "blocked"
        ? "adapter_blocked"
        : disposition === "completed"
          ? "adapter_completed"
          : disposition === "tool_failure"
            ? "adapter_tool_failure"
            : disposition === "protocol_failure"
              ? "adapter_protocol_failure"
              : "adapter_identity_mismatch";
    if (record["reason_code"] !== expectedReason) throw new Error("mcp_stdio_access_terminal_reason_invalid");
  } else throw new Error("mcp_stdio_access_receipt_kind_invalid");
  return record as unknown as McpStdioAccessReceipt;
}

function parseFinalization(value: Record<string, unknown>): McpStdioAccessFinalization {
  const blockers = new Set<string>();
  exactKeys(value, ["chain_head_sha256", "counters", "finalization_sha256", "finalized_at", "header_sha256", "receipt_count", "recovery_performed", "schema_version", "session_id", "terminal_status"], "mcp_stdio_access_finalization", blockers);
  if (blockers.size > 0 || value["schema_version"] !== MCP_STDIO_ACCESS_FINALIZATION_SCHEMA_VERSION) throw new Error("mcp_stdio_access_finalization_schema_invalid");
  requireTimestamp(value["finalized_at"], "mcp_stdio_access_finalized_at_invalid");
  assertStableId(String(value["session_id"]), "mcp_stdio_access_session_id");
  if (!isSha256(value["chain_head_sha256"]) || !isSha256(value["header_sha256"]) || !isSha256(value["finalization_sha256"])) throw new Error("mcp_stdio_access_finalization_digest_invalid");
  if (!Number.isSafeInteger(value["receipt_count"]) || Number(value["receipt_count"]) < 0) throw new Error("mcp_stdio_access_finalization_count_invalid");
  if (!["completed", "recovered_interruption"].includes(String(value["terminal_status"])) || typeof value["recovery_performed"] !== "boolean") throw new Error("mcp_stdio_access_finalization_status_invalid");
  const counters = requireRecord(value["counters"]);
  const countBlockers = new Set<string>();
  exactKeys(counters, ["allowed_transactions", "blocked_transactions", "completed_transactions", "failed_transactions", "interrupted_unknown_transactions", "total_transactions"], "mcp_stdio_access_counters", countBlockers);
  if (countBlockers.size > 0 || Object.values(counters).some((item) => !Number.isSafeInteger(item) || Number(item) < 0)) throw new Error("mcp_stdio_access_counters_invalid");
  return value as unknown as McpStdioAccessFinalization;
}

function countersFor(receipts: readonly McpStdioAccessReceipt[]): McpStdioAccessCounters {
  const authorizations = receipts.filter((item): item is McpStdioAccessReceipt & McpStdioAuthorizationReceiptBody => item.receipt_kind === "authorization");
  const terminals = receipts.filter((item): item is McpStdioAccessReceipt & McpStdioTerminalReceiptBody => item.receipt_kind === "terminal");
  return {
    total_transactions: authorizations.length,
    allowed_transactions: authorizations.filter((item) => item.authorization_decision === "allowed").length,
    blocked_transactions: authorizations.filter((item) => item.authorization_decision === "blocked").length,
    completed_transactions: terminals.filter((item) => item.terminal_disposition === "completed").length,
    failed_transactions: terminals.filter((item) => ["tool_failure", "protocol_failure", "identity_mismatch"].includes(item.terminal_disposition)).length,
    interrupted_unknown_transactions: terminals.filter((item) => item.terminal_disposition === "interrupted_unknown").length,
  };
}

function validateTransaction(input: McpStdioTransactionInput): void {
  assertStableId(input.requestId, "mcp_stdio_access_request_id");
  assertStableId(input.logicalOperationId, "mcp_stdio_access_logical_operation_id");
  if (!Number.isSafeInteger(input.attemptNumber) || input.attemptNumber < 1) throw new Error("mcp_stdio_access_attempt_invalid");
  if (!isSha256(input.routeSha256) || !isSha256(input.requestSha256)) throw new Error("mcp_stdio_access_transaction_digest_invalid");
  if (!Number.isSafeInteger(input.requestByteLength) || input.requestByteLength < 0) throw new Error("mcp_stdio_access_request_length_invalid");
}

function transactionFields(input: McpStdioTransactionInput) {
  return {
    request_id: input.requestId,
    logical_operation_id: input.logicalOperationId,
    attempt_number: input.attemptNumber,
    route_sha256: input.routeSha256,
    request_sha256: input.requestSha256,
    request_byte_length: input.requestByteLength,
  };
}

function verification(blockers: readonly string[]): McpStdioAccessVerification {
  return { ok: false, blockers: Object.freeze([...blockers]), session_id: null, receipt_count: 0, chain_head_sha256: null, counters: null, claim_boundary: "stdio_calls_through_this_dispatcher_only_not_host_or_container_non_bypassability" };
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string, blockers: Set<string>): void {
  if (canonicalJson(Object.keys(value).sort()) !== canonicalJson([...expected].sort())) blockers.add(`${label}_fields_invalid`);
}

function requireRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("mcp_stdio_access_record_invalid");
  return value as Record<string, unknown>;
}

function requireTimestamp(value: unknown, error: string): asserts value is string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) || Number.isNaN(Date.parse(value))) throw new Error(error);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function withoutKey(value: Record<string, unknown>, key: string): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([field]) => field !== key));
}

function writeDurableCanonical(path: string, value: unknown): void {
  const temporary = `${path}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  writeDurableNewFile(temporary, `${canonicalJson(value)}\n`);
  renameSync(temporary, path);
  fsyncDirectory(dirname(path));
}

function writeDurableCanonicalExclusive(path: string, value: unknown, existsError: string): void {
  const temporary = `${path}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  writeDurableNewFile(temporary, `${canonicalJson(value)}\n`);
  try {
    linkSync(temporary, path);
    fsyncDirectory(dirname(path));
  } catch (error) {
    if (error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === "EEXIST") throw new Error(existsError);
    throw error;
  } finally {
    if (existsSync(temporary)) unlinkSync(temporary);
  }
}

function writeDurableNewFile(path: string, text: string): void {
  const descriptor = openSync(path, "wx", 0o600);
  try {
    writeMcpStdioBufferFully(descriptor, Buffer.from(text, "utf8"));
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function appendDurableLine(path: string, line: string): void {
  const descriptor = openSync(path, "a", 0o600);
  try {
    writeMcpStdioBufferFully(descriptor, Buffer.from(`${line}\n`, "utf8"));
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

type McpStdioSyncWriter = (
  descriptor: number,
  buffer: Uint8Array,
  offset: number,
  length: number,
) => number;

/** @internal Exported only so the partial-write invariant has a deterministic test. */
export function writeMcpStdioBufferFully(
  descriptor: number,
  buffer: Uint8Array,
  writer: McpStdioSyncWriter = writeSync,
): void {
  let offset = 0;
  while (offset < buffer.byteLength) {
    const written = writer(descriptor, buffer, offset, buffer.byteLength - offset);
    if (!Number.isSafeInteger(written) || written <= 0 || written > buffer.byteLength - offset) {
      throw new Error("mcp_stdio_access_partial_write_failed");
    }
    offset += written;
  }
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, "r");
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}
