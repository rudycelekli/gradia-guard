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
import { canonicalJson, digestCanonical, isSha256, sha256 } from "./canonical.js";
import { assertStableId } from "./security.js";

export const MCP_HTTP_ACCESS_HEADER_SCHEMA_VERSION_V1 =
  "gradia.guard.mcp-http-access-header.v1" as const;
export const MCP_HTTP_ACCESS_HEADER_SCHEMA_VERSION =
  "gradia.guard.mcp-http-access-header.v2" as const;
export const MCP_HTTP_ACCESS_RECEIPT_SCHEMA_VERSION =
  "gradia.guard.mcp-http-access-receipt.v1" as const;
export const MCP_HTTP_ACCESS_FINALIZATION_SCHEMA_VERSION_V1 =
  "gradia.guard.mcp-http-access-finalization.v1" as const;
export const MCP_HTTP_ACCESS_FINALIZATION_SCHEMA_VERSION =
  "gradia.guard.mcp-http-access-finalization.v2" as const;
export const MCP_HTTP_ACCESS_GENESIS_SHA256 = "0".repeat(64);

export type McpHttpRequestKind =
  | "server_discovery"
  | "tool_list"
  | "tool_call"
  | "unknown";

export type McpHttpAccessDisposition = "completed" | "failed" | "refused";

export type McpHttpAccessReasonCode =
  | "adapter_identity_mismatch"
  | "adapter_policy_refused"
  | "adapter_protocol_failed"
  | "adapter_tool_failure"
  | "authorization_refused"
  | "body_refused"
  | "http_request_refused"
  | "origin_not_allowed"
  | "protocol_refused"
  | "proxy_internal_failure"
  | "rpc_method_refused"
  | "server_discovery_completed"
  | "target_refused"
  | "tool_call_completed"
  | "tool_list_completed"
  | "tool_route_not_allowed";

export type McpHttpSdkDisposition =
  | "blocked"
  | "completed"
  | "identity_mismatch"
  | "protocol_failure"
  | "tool_failure";

export interface McpHttpAccessHeaderBody {
  schema_version: typeof MCP_HTTP_ACCESS_HEADER_SCHEMA_VERSION;
  session_id: string;
  created_at: string;
  capture_boundary: "loopback_mcp_http_request_listener";
  bypass_possible: true;
  bypass_declaration:
    "requests_outside_this_proxy_socket_parser_rejections_and_process_crashes_before_receipt_are_not_observed";
  payload_retention: "digest_only";
  authorization_value_retained: false;
  crash_recovery_supported: true;
  configuration_sha256: string;
  policy_sha256: string;
  workload_identity_sha256: string;
  workload_identity_verified_at_start: true;
}

export interface McpHttpAccessHeaderV1Body {
  schema_version: typeof MCP_HTTP_ACCESS_HEADER_SCHEMA_VERSION_V1;
  session_id: string;
  created_at: string;
  capture_boundary: "loopback_mcp_http_request_listener";
  bypass_possible: true;
  bypass_declaration:
    "requests_outside_this_proxy_socket_parser_rejections_and_process_crashes_before_receipt_are_not_observed";
  payload_retention: "digest_only";
  authorization_value_retained: false;
  crash_recovery_supported: false;
  configuration_sha256: string;
  policy_sha256: string;
  workload_identity_sha256: string;
  workload_identity_verified_at_start: true;
}

export type McpHttpAccessHeaderV1 = McpHttpAccessHeaderV1Body & { header_sha256: string };
export type McpHttpAccessHeaderV2 = McpHttpAccessHeaderBody & { header_sha256: string };
export type McpHttpAccessHeader = McpHttpAccessHeaderV1 | McpHttpAccessHeaderV2;

export interface McpHttpRequestEvidence {
  http_method_kind: "post" | "other";
  http_method_sha256: string;
  http_method_byte_length: number;
  target_sha256: string;
  target_byte_length: number;
  header_shape_sha256: string;
  header_count: number;
  header_name_byte_length: number;
  header_value_byte_length: number;
  authorization_header_present: boolean;
  origin_header_present: boolean;
  body_observed: boolean;
  body_sha256: string | null;
  body_byte_length: number | null;
}

export interface McpHttpAccessOutcome {
  request_kind: McpHttpRequestKind;
  disposition: McpHttpAccessDisposition;
  reason_code: McpHttpAccessReasonCode;
  http_status: number;
  route_target_sha256: string | null;
  upstream_invoked: boolean | null;
  sdk_disposition: McpHttpSdkDisposition | null;
  sdk_occurrence_sha256: string | null;
}

export interface McpHttpAccessReceiptBody {
  schema_version: typeof MCP_HTTP_ACCESS_RECEIPT_SCHEMA_VERSION;
  session_id: string;
  header_sha256: string;
  sequence: number;
  request_id: string;
  observed_at: string;
  previous_receipt_sha256: string;
  request: McpHttpRequestEvidence;
  outcome: McpHttpAccessOutcome;
}

export interface McpHttpAccessReceipt extends McpHttpAccessReceiptBody {
  receipt_sha256: string;
}

export interface McpHttpAccessCounters {
  total_requests: number;
  completed_metadata_requests: number;
  accepted_tool_requests: number;
  blocked_tool_requests: number;
  unauthorized_http_requests: number;
  malformed_http_requests: number;
  failed_tool_requests: number;
}

export interface McpHttpAccessFinalizationBody {
  schema_version: typeof MCP_HTTP_ACCESS_FINALIZATION_SCHEMA_VERSION;
  session_id: string;
  header_sha256: string;
  finalized_at: string;
  receipt_count: number;
  chain_head_sha256: string;
  counters: McpHttpAccessCounters;
  terminal_status: "completed" | "recovered_interruption";
  recovery_performed: boolean;
}

export interface McpHttpAccessFinalizationV1Body {
  schema_version: typeof MCP_HTTP_ACCESS_FINALIZATION_SCHEMA_VERSION_V1;
  session_id: string;
  header_sha256: string;
  finalized_at: string;
  receipt_count: number;
  chain_head_sha256: string;
  counters: McpHttpAccessCounters;
}

export type McpHttpAccessFinalizationV1 = McpHttpAccessFinalizationV1Body & {
  finalization_sha256: string;
};
export type McpHttpAccessFinalizationV2 = McpHttpAccessFinalizationBody & {
  finalization_sha256: string;
};
export type McpHttpAccessFinalization =
  | McpHttpAccessFinalizationV1
  | McpHttpAccessFinalizationV2;

export interface McpHttpAccessBundle {
  header: McpHttpAccessHeader;
  receipts: readonly McpHttpAccessReceipt[];
  finalization: McpHttpAccessFinalization;
}

export interface McpHttpAccessVerification {
  ok: boolean;
  blockers: readonly string[];
  session_id: string | null;
  receipt_count: number;
  chain_head_sha256: string | null;
  counters: McpHttpAccessCounters | null;
}

export interface McpHttpAccessRecorderOptions {
  directory: string;
  sessionId?: string;
  createdAt: string;
  configurationSha256: string;
  policySha256: string;
  workloadIdentitySha256: string;
  now: () => string;
}

export interface McpHttpAccessAppendInput {
  requestId: string;
  request: McpHttpRequestEvidence;
  outcome: McpHttpAccessOutcome;
}

export class McpHttpAccessRecorder {
  readonly directory: string;
  readonly headerPath: string;
  readonly receiptsPath: string;
  readonly bundlePath: string;
  readonly header: McpHttpAccessHeaderV2;
  private readonly now: () => string;
  private receiptList: McpHttpAccessReceipt[] = [];
  private finalized = false;
  private recoveredFromInterruption = false;

  constructor(options: McpHttpAccessRecorderOptions) {
    if (existsSync(options.directory)) throw new Error("mcp_http_access_directory_exists");
    for (const [field, value] of [
      ["configuration", options.configurationSha256],
      ["policy", options.policySha256],
      ["workload_identity", options.workloadIdentitySha256],
    ] as const) {
      if (!isSha256(value)) throw new Error(`mcp_http_access_${field}_digest_invalid`);
    }
    const sessionId = options.sessionId ?? `mcp-http-${randomBytes(16).toString("hex")}`;
    assertStableId(sessionId, "mcp_http_access_session_id");
    requireTimestamp(options.createdAt, "mcp_http_access_created_at_invalid");
    const headerBody: McpHttpAccessHeaderBody = {
      schema_version: MCP_HTTP_ACCESS_HEADER_SCHEMA_VERSION,
      session_id: sessionId,
      created_at: options.createdAt,
      capture_boundary: "loopback_mcp_http_request_listener",
      bypass_possible: true,
      bypass_declaration:
        "requests_outside_this_proxy_socket_parser_rejections_and_process_crashes_before_receipt_are_not_observed",
      payload_retention: "digest_only",
      authorization_value_retained: false,
      crash_recovery_supported: true,
      configuration_sha256: options.configurationSha256,
      policy_sha256: options.policySha256,
      workload_identity_sha256: options.workloadIdentitySha256,
      workload_identity_verified_at_start: true,
    };
    this.header = { ...headerBody, header_sha256: digestCanonical(headerBody) };
    const blockers = headerBlockers(this.header);
    if (blockers.length > 0) throw new Error(`mcp_http_access_header_invalid:${blockers.join(",")}`);
    mkdirSync(options.directory, { recursive: true, mode: 0o700 });
    this.directory = options.directory;
    this.headerPath = join(options.directory, "header.json");
    this.receiptsPath = join(options.directory, "receipts.ndjson");
    this.bundlePath = join(options.directory, "bundle.json");
    this.now = options.now;
    writeDurableCanonical(this.headerPath, this.header);
    writeDurableNewFile(this.receiptsPath, "");
  }

  private static fromRecovered(
    directory: string,
    header: McpHttpAccessHeaderV2,
    receipts: McpHttpAccessReceipt[],
    now: () => string,
  ): McpHttpAccessRecorder {
    const recorder = Object.create(McpHttpAccessRecorder.prototype) as McpHttpAccessRecorder;
    Object.defineProperties(recorder, {
      directory: { value: directory, enumerable: true },
      headerPath: { value: join(directory, "header.json"), enumerable: true },
      receiptsPath: { value: join(directory, "receipts.ndjson"), enumerable: true },
      bundlePath: { value: join(directory, "bundle.json"), enumerable: true },
      header: { value: header, enumerable: true },
      now: { value: now, writable: false },
      receiptList: { value: receipts, writable: true },
      finalized: { value: false, writable: true },
      recoveredFromInterruption: { value: true, writable: true },
    });
    return recorder;
  }

  /**
   * Recover one valid durable prefix and close it only as an interrupted
   * session. Recovery never resumes request capture and does not establish the
   * cause of interruption or reconstruct requests that were not appended.
   */
  static recover(directory: string, now: () => string): McpHttpAccessRecorder {
    if (existsSync(join(directory, "bundle.json"))) {
      throw new Error("mcp_http_access_already_finalized");
    }
    const prefix = readMcpHttpAccessPrefixDirectory(directory);
    if (prefix.blockers.length > 0 || prefix.header === null) {
      throw new Error(`mcp_http_access_recovery_invalid:${prefix.blockers.join(",")}`);
    }
    if (
      prefix.header.schema_version !== MCP_HTTP_ACCESS_HEADER_SCHEMA_VERSION
      || prefix.header.crash_recovery_supported !== true
    ) {
      throw new Error("mcp_http_access_recovery_not_supported_by_header");
    }
    return McpHttpAccessRecorder.fromRecovered(
      directory,
      prefix.header,
      [...prefix.receipts],
      now,
    );
  }

  get receipts(): readonly McpHttpAccessReceipt[] {
    return Object.freeze([...this.receiptList]);
  }

  append(input: McpHttpAccessAppendInput): McpHttpAccessReceipt {
    if (this.finalized) throw new Error("mcp_http_access_post_finalization_write");
    if (this.recoveredFromInterruption) {
      throw new Error("mcp_http_access_recovered_session_write");
    }
    assertStableId(input.requestId, "mcp_http_access_request_id");
    const observedAt = this.now();
    requireTimestamp(observedAt, "mcp_http_access_observed_at_invalid");
    const receiptBody: McpHttpAccessReceiptBody = {
      schema_version: MCP_HTTP_ACCESS_RECEIPT_SCHEMA_VERSION,
      session_id: this.header.session_id,
      header_sha256: this.header.header_sha256,
      sequence: this.receiptList.length,
      request_id: input.requestId,
      observed_at: observedAt,
      previous_receipt_sha256:
        this.receiptList.at(-1)?.receipt_sha256 ?? MCP_HTTP_ACCESS_GENESIS_SHA256,
      request: clone(input.request),
      outcome: clone(input.outcome),
    };
    const receipt: McpHttpAccessReceipt = {
      ...receiptBody,
      receipt_sha256: digestCanonical(receiptBody),
    };
    const blockers = receiptChainBlockers(this.header, [...this.receiptList, receipt]);
    if (blockers.length > 0) throw new Error(`mcp_http_access_receipt_invalid:${blockers.join(",")}`);
    appendDurableLine(this.receiptsPath, canonicalJson(receipt));
    this.receiptList.push(receipt);
    return receipt;
  }

  finalize(): McpHttpAccessBundle {
    if (this.finalized) throw new Error("mcp_http_access_already_finalized");
    const finalizedAt = this.now();
    requireTimestamp(finalizedAt, "mcp_http_access_finalized_at_invalid");
    const finalizationBody: McpHttpAccessFinalizationBody = {
      schema_version: MCP_HTTP_ACCESS_FINALIZATION_SCHEMA_VERSION,
      session_id: this.header.session_id,
      header_sha256: this.header.header_sha256,
      finalized_at: finalizedAt,
      receipt_count: this.receiptList.length,
      chain_head_sha256:
        this.receiptList.at(-1)?.receipt_sha256 ?? MCP_HTTP_ACCESS_GENESIS_SHA256,
      counters: countersFor(this.receiptList),
      terminal_status: this.recoveredFromInterruption
        ? "recovered_interruption"
        : "completed",
      recovery_performed: this.recoveredFromInterruption,
    };
    const finalization: McpHttpAccessFinalization = {
      ...finalizationBody,
      finalization_sha256: digestCanonical(finalizationBody),
    };
    const bundle: McpHttpAccessBundle = {
      header: this.header,
      receipts: [...this.receiptList],
      finalization,
    };
    const verification = verifyMcpHttpAccessBundle(bundle);
    if (!verification.ok) {
      throw new Error(`mcp_http_access_bundle_unverified:${verification.blockers.join(",")}`);
    }
    writeDurableCanonicalExclusive(
      this.bundlePath,
      bundle,
      "mcp_http_access_bundle_exists",
    );
    this.finalized = true;
    return bundle;
  }
}

export function mcpHttpRequestEvidence(input: {
  method: string | undefined;
  target: string | undefined;
  rawHeaders: readonly string[];
  body: Uint8Array | null;
}): McpHttpRequestEvidence {
  const method = input.method ?? "";
  const target = input.target ?? "";
  const headerShape: { name: string; value_byte_length: number }[] = [];
  let headerNameBytes = 0;
  let headerValueBytes = 0;
  for (let index = 0; index < input.rawHeaders.length; index += 2) {
    const name = (input.rawHeaders[index] ?? "").toLowerCase();
    const value = input.rawHeaders[index + 1] ?? "";
    const nameLength = Buffer.byteLength(name, "utf8");
    const valueLength = Buffer.byteLength(value, "utf8");
    headerNameBytes += nameLength;
    headerValueBytes += valueLength;
    headerShape.push({ name, value_byte_length: valueLength });
  }
  return {
    http_method_kind: method === "POST" ? "post" : "other",
    http_method_sha256: sha256(Buffer.from(method, "utf8")),
    http_method_byte_length: Buffer.byteLength(method, "utf8"),
    target_sha256: sha256(Buffer.from(target, "utf8")),
    target_byte_length: Buffer.byteLength(target, "utf8"),
    header_shape_sha256: digestCanonical(headerShape),
    header_count: headerShape.length,
    header_name_byte_length: headerNameBytes,
    header_value_byte_length: headerValueBytes,
    authorization_header_present: headerShape.some((item) => item.name === "authorization"),
    origin_header_present: headerShape.some((item) => item.name === "origin"),
    body_observed: input.body !== null,
    body_sha256: input.body === null ? null : sha256(input.body),
    body_byte_length: input.body === null ? null : input.body.byteLength,
  };
}

export function mcpHttpRouteTargetSha256(serverId: string, toolName: string | null): string {
  return digestCanonical({ server_id: serverId, tool_name: toolName });
}

export function verifyMcpHttpAccessBundle(value: unknown): McpHttpAccessVerification {
  const blockers: string[] = [];
  if (!isRecord(value)) return verification(["mcp_http_access_bundle_shape_invalid"], null, [], null);
  exactKeys(value, ["finalization", "header", "receipts"], "mcp_http_access_bundle", blockers);
  const header = isRecord(value["header"])
    ? (value["header"] as unknown as McpHttpAccessHeader)
    : null;
  const receipts = Array.isArray(value["receipts"])
    ? (value["receipts"] as unknown as McpHttpAccessReceipt[])
    : [];
  const finalization = isRecord(value["finalization"])
    ? (value["finalization"] as unknown as McpHttpAccessFinalization)
    : null;
  try {
    if (header === null) blockers.push("mcp_http_access_header_shape_invalid");
    else blockers.push(...headerBlockers(header));
  } catch {
    blockers.push("mcp_http_access_header_unreadable");
  }
  if (!Array.isArray(value["receipts"])) blockers.push("mcp_http_access_receipts_shape_invalid");
  try {
    if (header !== null) blockers.push(...receiptChainBlockers(header, receipts));
  } catch {
    blockers.push("mcp_http_access_receipt_chain_unreadable");
  }
  try {
    if (finalization === null) blockers.push("mcp_http_access_finalization_shape_invalid");
    else blockers.push(...finalizationBlockers(header, receipts, finalization));
  } catch {
    blockers.push("mcp_http_access_finalization_unreadable");
  }
  return verification(blockers, header, receipts, finalization);
}

export function verifyMcpHttpAccessBundleDirectory(directory: string): McpHttpAccessVerification {
  const prefix = readMcpHttpAccessPrefixDirectory(directory);
  const blockers = [...prefix.blockers];
  let bundle: unknown = null;
  try {
    bundle = JSON.parse(readFileSync(join(directory, "bundle.json"), "utf8")) as unknown;
  } catch {
    blockers.push("mcp_http_access_bundle_unreadable");
  }
  const verified = verifyMcpHttpAccessBundle(bundle);
  blockers.push(...verified.blockers);
  if (isRecord(bundle)) {
    if (canonicalJson(bundle["header"]) !== canonicalJson(prefix.header)) {
      blockers.push("mcp_http_access_header_file_mismatch");
    }
    if (canonicalJson(bundle["receipts"]) !== canonicalJson(prefix.receipts)) {
      blockers.push("mcp_http_access_journal_bundle_mismatch");
    }
  }
  return {
    ...verified,
    ok: blockers.length === 0,
    blockers: Object.freeze([...new Set(blockers)].sort()),
  };
}

function headerBlockers(header: McpHttpAccessHeader): string[] {
  const blockers: string[] = [];
  if (!isRecord(header)) return ["mcp_http_access_header_shape_invalid"];
  exactKeys(header as unknown as Record<string, unknown>, [
    "authorization_value_retained",
    "bypass_declaration",
    "bypass_possible",
    "capture_boundary",
    "configuration_sha256",
    "crash_recovery_supported",
    "created_at",
    "header_sha256",
    "payload_retention",
    "policy_sha256",
    "schema_version",
    "session_id",
    "workload_identity_sha256",
    "workload_identity_verified_at_start",
  ], "mcp_http_access_header", blockers);
  if (
    header.schema_version !== MCP_HTTP_ACCESS_HEADER_SCHEMA_VERSION
    && header.schema_version !== MCP_HTTP_ACCESS_HEADER_SCHEMA_VERSION_V1
  ) blockers.push("mcp_http_access_header_schema_invalid");
  try { assertStableId(header.session_id, "mcp_http_access_session_id"); } catch { blockers.push("mcp_http_access_session_id_invalid"); }
  if (!timestampValid(header.created_at)) blockers.push("mcp_http_access_created_at_invalid");
  if (header.capture_boundary !== "loopback_mcp_http_request_listener") blockers.push("mcp_http_access_boundary_invalid");
  if (header.bypass_possible !== true || header.bypass_declaration !== "requests_outside_this_proxy_socket_parser_rejections_and_process_crashes_before_receipt_are_not_observed") blockers.push("mcp_http_access_bypass_declaration_invalid");
  if (header.payload_retention !== "digest_only" || header.authorization_value_retained !== false) blockers.push("mcp_http_access_secret_retention_invalid");
  if (
    (header.schema_version === MCP_HTTP_ACCESS_HEADER_SCHEMA_VERSION
      && header.crash_recovery_supported !== true)
    || (header.schema_version === MCP_HTTP_ACCESS_HEADER_SCHEMA_VERSION_V1
      && header.crash_recovery_supported !== false)
  ) blockers.push("mcp_http_access_crash_claim_invalid");
  if (header.workload_identity_verified_at_start !== true) blockers.push("mcp_http_access_identity_verification_missing");
  for (const [label, digest] of [
    ["configuration", header.configuration_sha256],
    ["policy", header.policy_sha256],
    ["workload_identity", header.workload_identity_sha256],
    ["header", header.header_sha256],
  ] as const) if (!isSha256(digest)) blockers.push(`mcp_http_access_${label}_digest_invalid`);
  const body = withoutKey(header as unknown as Record<string, unknown>, "header_sha256");
  if (isSha256(header.header_sha256) && digestCanonical(body) !== header.header_sha256) blockers.push("mcp_http_access_header_digest_mismatch");
  return blockers;
}

function receiptChainBlockers(header: McpHttpAccessHeader, receipts: readonly McpHttpAccessReceipt[]): string[] {
  const blockers: string[] = [];
  let head = MCP_HTTP_ACCESS_GENESIS_SHA256;
  let previousObservedAt: string | null = null;
  const requestIds = new Set<string>();
  receipts.forEach((receipt, index) => {
    if (!isRecord(receipt)) { blockers.push(`mcp_http_access_receipt_shape_invalid:${index}`); return; }
    exactKeys(receipt as unknown as Record<string, unknown>, [
      "header_sha256", "observed_at", "outcome", "previous_receipt_sha256",
      "receipt_sha256", "request", "request_id", "schema_version", "sequence", "session_id",
    ], `mcp_http_access_receipt:${index}`, blockers);
    if (receipt.schema_version !== MCP_HTTP_ACCESS_RECEIPT_SCHEMA_VERSION) blockers.push(`mcp_http_access_receipt_schema_invalid:${index}`);
    if (receipt.session_id !== header.session_id) blockers.push(`mcp_http_access_receipt_session_mismatch:${index}`);
    if (receipt.header_sha256 !== header.header_sha256) blockers.push(`mcp_http_access_receipt_header_mismatch:${index}`);
    if (receipt.sequence !== index) blockers.push(`mcp_http_access_receipt_sequence_gap:${index}`);
    try { assertStableId(receipt.request_id, "mcp_http_access_request_id"); } catch { blockers.push(`mcp_http_access_request_id_invalid:${index}`); }
    if (requestIds.has(receipt.request_id)) blockers.push(`mcp_http_access_request_id_duplicate:${index}`);
    requestIds.add(receipt.request_id);
    if (!timestampValid(receipt.observed_at)) blockers.push(`mcp_http_access_observed_at_invalid:${index}`);
    if (previousObservedAt !== null && receipt.observed_at < previousObservedAt) blockers.push(`mcp_http_access_timestamp_regressed:${index}`);
    previousObservedAt = receipt.observed_at;
    if (receipt.previous_receipt_sha256 !== head) blockers.push(`mcp_http_access_previous_hash_mismatch:${index}`);
    blockers.push(...requestBlockers(receipt.request, index));
    blockers.push(...outcomeBlockers(receipt.outcome, index));
    const body = withoutKey(receipt as unknown as Record<string, unknown>, "receipt_sha256");
    if (!isSha256(receipt.receipt_sha256)) blockers.push(`mcp_http_access_receipt_digest_invalid:${index}`);
    else {
      if (digestCanonical(body) !== receipt.receipt_sha256) blockers.push(`mcp_http_access_receipt_digest_mismatch:${index}`);
      head = receipt.receipt_sha256;
    }
  });
  return blockers;
}

function requestBlockers(request: McpHttpRequestEvidence, index: number): string[] {
  const blockers: string[] = [];
  if (!isRecord(request)) return [`mcp_http_access_request_shape_invalid:${index}`];
  exactKeys(request as unknown as Record<string, unknown>, [
    "authorization_header_present", "body_byte_length", "body_observed", "body_sha256",
    "header_count", "header_name_byte_length", "header_shape_sha256", "header_value_byte_length",
    "http_method_byte_length", "http_method_kind", "http_method_sha256", "origin_header_present",
    "target_byte_length", "target_sha256",
  ], `mcp_http_access_request:${index}`, blockers);
  if (request.http_method_kind !== "post" && request.http_method_kind !== "other") blockers.push(`mcp_http_access_method_kind_invalid:${index}`);
  for (const [label, value] of [
    ["http_method", request.http_method_sha256],
    ["target", request.target_sha256],
    ["header_shape", request.header_shape_sha256],
  ] as const) if (!isSha256(value)) blockers.push(`mcp_http_access_${label}_digest_invalid:${index}`);
  for (const [label, value] of [
    ["http_method", request.http_method_byte_length], ["target", request.target_byte_length],
    ["header_count", request.header_count], ["header_name", request.header_name_byte_length],
    ["header_value", request.header_value_byte_length],
  ] as const) if (!Number.isSafeInteger(value) || value < 0) blockers.push(`mcp_http_access_${label}_length_invalid:${index}`);
  if (typeof request.authorization_header_present !== "boolean" || typeof request.origin_header_present !== "boolean" || typeof request.body_observed !== "boolean") blockers.push(`mcp_http_access_request_boolean_invalid:${index}`);
  if (request.body_observed) {
    if (!isSha256(request.body_sha256) || !Number.isSafeInteger(request.body_byte_length) || (request.body_byte_length ?? -1) < 0) blockers.push(`mcp_http_access_body_reference_invalid:${index}`);
  } else if (request.body_sha256 !== null || request.body_byte_length !== null) blockers.push(`mcp_http_access_unobserved_body_reference_present:${index}`);
  return blockers;
}

function outcomeBlockers(outcome: McpHttpAccessOutcome, index: number): string[] {
  const blockers: string[] = [];
  if (!isRecord(outcome)) return [`mcp_http_access_outcome_shape_invalid:${index}`];
  exactKeys(outcome as unknown as Record<string, unknown>, [
    "disposition", "http_status", "reason_code", "request_kind", "route_target_sha256",
    "sdk_disposition", "sdk_occurrence_sha256", "upstream_invoked",
  ], `mcp_http_access_outcome:${index}`, blockers);
  const requestKinds: readonly McpHttpRequestKind[] = ["server_discovery", "tool_list", "tool_call", "unknown"];
  const dispositions: readonly McpHttpAccessDisposition[] = ["completed", "failed", "refused"];
  const reasons: readonly McpHttpAccessReasonCode[] = [
    "adapter_identity_mismatch", "adapter_policy_refused", "adapter_protocol_failed",
    "adapter_tool_failure", "authorization_refused", "body_refused", "http_request_refused",
    "origin_not_allowed", "protocol_refused", "proxy_internal_failure", "rpc_method_refused",
    "server_discovery_completed", "target_refused", "tool_call_completed",
    "tool_list_completed", "tool_route_not_allowed",
  ];
  const sdkDispositions: readonly McpHttpSdkDisposition[] = ["blocked", "completed", "identity_mismatch", "protocol_failure", "tool_failure"];
  if (!requestKinds.includes(outcome.request_kind)) blockers.push(`mcp_http_access_request_kind_invalid:${index}`);
  if (!dispositions.includes(outcome.disposition)) blockers.push(`mcp_http_access_disposition_invalid:${index}`);
  if (!reasons.includes(outcome.reason_code)) blockers.push(`mcp_http_access_reason_invalid:${index}`);
  if (!Number.isSafeInteger(outcome.http_status) || outcome.http_status < 100 || outcome.http_status > 599) blockers.push(`mcp_http_access_status_invalid:${index}`);
  if (outcome.route_target_sha256 !== null && !isSha256(outcome.route_target_sha256)) blockers.push(`mcp_http_access_route_digest_invalid:${index}`);
  if (outcome.upstream_invoked !== null && typeof outcome.upstream_invoked !== "boolean") blockers.push(`mcp_http_access_upstream_state_invalid:${index}`);
  if (outcome.sdk_disposition !== null && !sdkDispositions.includes(outcome.sdk_disposition)) blockers.push(`mcp_http_access_sdk_disposition_invalid:${index}`);
  if (outcome.sdk_occurrence_sha256 !== null && !isSha256(outcome.sdk_occurrence_sha256)) blockers.push(`mcp_http_access_sdk_occurrence_invalid:${index}`);
  if ((outcome.sdk_disposition === null) !== (outcome.sdk_occurrence_sha256 === null)) blockers.push(`mcp_http_access_sdk_binding_incomplete:${index}`);
  if (outcome.sdk_disposition !== null && outcome.request_kind !== "tool_call") blockers.push(`mcp_http_access_sdk_binding_non_tool:${index}`);
  if (outcome.upstream_invoked === false && outcome.sdk_disposition !== null && outcome.sdk_disposition !== "blocked") blockers.push(`mcp_http_access_upstream_sdk_mismatch:${index}`);
  if (outcome.disposition === "completed" && outcome.http_status !== 200) blockers.push(`mcp_http_access_completed_status_invalid:${index}`);
  if (outcome.reason_code === "authorization_refused" && outcome.http_status !== 401) blockers.push(`mcp_http_access_authorization_status_invalid:${index}`);
  if (outcome.reason_code === "origin_not_allowed" && outcome.http_status !== 403) blockers.push(`mcp_http_access_origin_status_invalid:${index}`);
  return blockers;
}

function finalizationBlockers(
  header: McpHttpAccessHeader | null,
  receipts: readonly McpHttpAccessReceipt[],
  finalization: McpHttpAccessFinalization,
): string[] {
  const blockers: string[] = [];
  const isV2 = finalization.schema_version === MCP_HTTP_ACCESS_FINALIZATION_SCHEMA_VERSION;
  exactKeys(finalization as unknown as Record<string, unknown>, [
    "chain_head_sha256", "counters", "finalization_sha256", "finalized_at",
    "header_sha256", "receipt_count", "schema_version", "session_id",
    ...(isV2 ? ["recovery_performed", "terminal_status"] : []),
  ], "mcp_http_access_finalization", blockers);
  if (
    finalization.schema_version !== MCP_HTTP_ACCESS_FINALIZATION_SCHEMA_VERSION
    && finalization.schema_version !== MCP_HTTP_ACCESS_FINALIZATION_SCHEMA_VERSION_V1
  ) blockers.push("mcp_http_access_finalization_schema_invalid");
  if (!timestampValid(finalization.finalized_at)) blockers.push("mcp_http_access_finalized_at_invalid");
  if (header !== null) {
    if (finalization.session_id !== header.session_id) blockers.push("mcp_http_access_finalization_session_mismatch");
    if (finalization.header_sha256 !== header.header_sha256) blockers.push("mcp_http_access_finalization_header_mismatch");
    if (finalization.finalized_at < header.created_at) blockers.push("mcp_http_access_finalized_before_creation");
    const expectedFinalizationSchema = header.schema_version === MCP_HTTP_ACCESS_HEADER_SCHEMA_VERSION
      ? MCP_HTTP_ACCESS_FINALIZATION_SCHEMA_VERSION
      : MCP_HTTP_ACCESS_FINALIZATION_SCHEMA_VERSION_V1;
    if (finalization.schema_version !== expectedFinalizationSchema) {
      blockers.push("mcp_http_access_finalization_header_schema_mismatch");
    }
  }
  const lastObservedAt = receipts.at(-1)?.observed_at;
  if (lastObservedAt !== undefined && finalization.finalized_at < lastObservedAt) {
    blockers.push("mcp_http_access_finalized_before_last_receipt");
  }
  if (isV2) {
    const v2 = finalization as McpHttpAccessFinalizationV2;
    if (v2.terminal_status !== "completed" && v2.terminal_status !== "recovered_interruption") {
      blockers.push("mcp_http_access_terminal_status_invalid");
    }
    if (typeof v2.recovery_performed !== "boolean") {
      blockers.push("mcp_http_access_recovery_state_invalid");
    } else if (
      v2.recovery_performed !== (v2.terminal_status === "recovered_interruption")
    ) {
      blockers.push("mcp_http_access_recovery_terminal_mismatch");
    }
  }
  if (finalization.receipt_count !== receipts.length) blockers.push("mcp_http_access_finalization_count_mismatch");
  const expectedHead = receipts.at(-1)?.receipt_sha256 ?? MCP_HTTP_ACCESS_GENESIS_SHA256;
  if (finalization.chain_head_sha256 !== expectedHead) blockers.push("mcp_http_access_finalization_head_mismatch");
  const counterBlockers: string[] = [];
  if (!isRecord(finalization.counters)) counterBlockers.push("mcp_http_access_counters_shape_invalid");
  else {
    exactKeys(finalization.counters as unknown as Record<string, unknown>, [
      "accepted_tool_requests", "blocked_tool_requests", "completed_metadata_requests",
      "failed_tool_requests", "malformed_http_requests", "total_requests",
      "unauthorized_http_requests",
    ], "mcp_http_access_counters", counterBlockers);
    for (const [field, value] of Object.entries(finalization.counters)) {
      if (!Number.isSafeInteger(value) || (value as number) < 0) {
        counterBlockers.push(`mcp_http_access_counter_invalid:${field}`);
      }
    }
    try {
      const expectedCounters = countersFor(receipts);
      if (canonicalJson(finalization.counters) !== canonicalJson(expectedCounters)) {
        blockers.push("mcp_http_access_finalization_counters_mismatch");
      }
    } catch {
      blockers.push("mcp_http_access_counters_unrecomputable");
    }
  }
  blockers.push(...counterBlockers);
  const body = withoutKey(finalization as unknown as Record<string, unknown>, "finalization_sha256");
  if (!isSha256(finalization.finalization_sha256)) blockers.push("mcp_http_access_finalization_digest_invalid");
  else if (digestCanonical(body) !== finalization.finalization_sha256) blockers.push("mcp_http_access_finalization_digest_mismatch");
  return blockers;
}

function countersFor(receipts: readonly McpHttpAccessReceipt[]): McpHttpAccessCounters {
  const counters: McpHttpAccessCounters = {
    total_requests: receipts.length,
    completed_metadata_requests: 0,
    accepted_tool_requests: 0,
    blocked_tool_requests: 0,
    unauthorized_http_requests: 0,
    malformed_http_requests: 0,
    failed_tool_requests: 0,
  };
  for (const receipt of receipts) {
    const { outcome } = receipt;
    if (outcome.disposition === "completed" && (outcome.request_kind === "server_discovery" || outcome.request_kind === "tool_list")) counters.completed_metadata_requests += 1;
    if (outcome.request_kind === "tool_call" && outcome.disposition === "completed") counters.accepted_tool_requests += 1;
    if (outcome.request_kind === "tool_call" && outcome.disposition === "refused") counters.blocked_tool_requests += 1;
    if (outcome.request_kind === "tool_call" && outcome.disposition === "failed") counters.failed_tool_requests += 1;
    if (outcome.reason_code === "origin_not_allowed" || outcome.reason_code === "authorization_refused") counters.unauthorized_http_requests += 1;
    if (["body_refused", "http_request_refused", "protocol_refused", "proxy_internal_failure", "rpc_method_refused", "target_refused"].includes(outcome.reason_code)) counters.malformed_http_requests += 1;
  }
  return counters;
}

function verification(
  blockers: readonly string[],
  header: McpHttpAccessHeader | null,
  receipts: readonly McpHttpAccessReceipt[],
  finalization: McpHttpAccessFinalization | null,
): McpHttpAccessVerification {
  const unique = [...new Set(blockers)].sort();
  return {
    ok: unique.length === 0,
    blockers: Object.freeze(unique),
    session_id: header?.session_id ?? null,
    receipt_count: receipts.length,
    chain_head_sha256: finalization?.chain_head_sha256 ?? null,
    counters: finalization?.counters ?? null,
  };
}

function readMcpHttpAccessPrefixDirectory(directory: string): {
  blockers: readonly string[];
  header: McpHttpAccessHeader | null;
  receipts: readonly McpHttpAccessReceipt[];
} {
  const blockers: string[] = [];
  let header: McpHttpAccessHeader | null = null;
  let receipts: McpHttpAccessReceipt[] = [];
  try {
    const text = readFileSync(join(directory, "header.json"), "utf8");
    const parsed = JSON.parse(text) as unknown;
    if (!isRecord(parsed)) blockers.push("mcp_http_access_header_shape_invalid");
    else {
      header = parsed as unknown as McpHttpAccessHeader;
      if (`${canonicalJson(parsed)}\n` !== text) {
        blockers.push("mcp_http_access_header_file_noncanonical");
      }
      blockers.push(...headerBlockers(header));
    }
  } catch {
    blockers.push("mcp_http_access_header_unreadable");
  }
  try {
    const journal = readFileSync(join(directory, "receipts.ndjson"), "utf8");
    if (journal.length > 0 && !journal.endsWith("\n")) {
      blockers.push("mcp_http_access_journal_truncated");
    }
    receipts = journal
      .split("\n")
      .filter((line) => line.length > 0)
      .map((line, index) => {
        try {
          const parsed = JSON.parse(line) as unknown;
          if (canonicalJson(parsed) !== line) {
            blockers.push(`mcp_http_access_journal_noncanonical:${index}`);
          }
          return parsed as McpHttpAccessReceipt;
        } catch {
          blockers.push(`mcp_http_access_journal_json_invalid:${index}`);
          return null;
        }
      })
      .filter((item): item is McpHttpAccessReceipt => item !== null);
  } catch {
    blockers.push("mcp_http_access_journal_unreadable");
  }
  if (header !== null) {
    try {
      blockers.push(...receiptChainBlockers(header, receipts));
    } catch {
      blockers.push("mcp_http_access_receipt_chain_unreadable");
    }
  }
  return {
    blockers: Object.freeze([...new Set(blockers)].sort()),
    header,
    receipts: Object.freeze(receipts),
  };
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string, blockers: string[]): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (canonicalJson(actual) !== canonicalJson(wanted)) blockers.push(`${label}_fields_invalid`);
}

function withoutKey(value: Record<string, unknown>, key: string): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([field]) => field !== key));
}

function timestampValid(value: unknown): value is string {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) && !Number.isNaN(Date.parse(value));
}

function requireTimestamp(value: string, error: string): void {
  if (!timestampValid(value)) throw new Error(error);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function clone<T>(value: T): T {
  return JSON.parse(canonicalJson(value)) as T;
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
    if (
      error instanceof Error
      && "code" in error
      && (error as NodeJS.ErrnoException).code === "EEXIST"
    ) {
      throw new Error(existsError);
    }
    throw error;
  } finally {
    if (existsSync(temporary)) unlinkSync(temporary);
  }
}

function writeDurableNewFile(path: string, text: string): void {
  const descriptor = openSync(path, "wx", 0o600);
  try {
    writeSync(descriptor, text, undefined, "utf8");
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function appendDurableLine(path: string, line: string): void {
  const descriptor = openSync(path, "a", 0o600);
  try {
    writeSync(descriptor, `${line}\n`, undefined, "utf8");
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
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
