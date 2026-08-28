import { canonicalJson, digestCanonical, isSha256 } from "./canonical.js";
import { assertStableId } from "./security.js";

export const RUNTIME_HEADER_SCHEMA_VERSION = "gradia.guard.runtime-header.v1" as const;
export const RUNTIME_RECEIPT_SCHEMA_VERSION = "gradia.guard.runtime-receipt.v1" as const;
export const RUNTIME_FINALIZATION_SCHEMA_VERSION =
  "gradia.guard.runtime-finalization.v1" as const;
export const RUNTIME_ANCHOR_STATEMENT_SCHEMA_VERSION =
  "gradia.guard.runtime-anchor-statement.v1" as const;
export const RUNTIME_ANCHOR_RECEIPT_SCHEMA_VERSION =
  "gradia.guard.runtime-anchor-receipt.v1" as const;
export const RUNTIME_GENESIS_SHA256 =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" as const;

export type RuntimeTerminalStatus = "completed" | "failed" | "crashed" | "cancelled";

export interface RuntimeDigestOnlyContent {
  schema_version: "gradia.guard.digest-only-content.v1";
  media_type: string;
  byte_length: number;
  plaintext_sha256: string;
}

export interface RuntimeEvidenceHeader {
  schema_version: typeof RUNTIME_HEADER_SCHEMA_VERSION;
  runtime_version: string;
  session_id: string;
  created_at: string;
  capture_boundary: "declared_runtime_recorder";
  bypass_possible: true;
  bypass_declaration: "operations_outside_this_recorder_are_not_observed_or_enforced";
  isolation_attestation: "not_attested";
  runtime_identity_sha256: string;
  policy_sha256: string;
  credential_policy_sha256: string;
  declared_credential_scope_ids: readonly string[];
  header_sha256: string;
}

export interface RuntimeFileEvidenceBody {
  kind: "file";
  operation: "read" | "write" | "create" | "delete" | "rename" | "stat";
  path_identity_sha256: string;
  target_path_identity_sha256: string | null;
  outcome: "success" | "failed" | "blocked";
  before: RuntimeDigestOnlyContent | null;
  after: RuntimeDigestOnlyContent | null;
  bytes_observed: number;
  reason_codes: readonly string[];
}

export interface RuntimeProcessEvidenceBody {
  kind: "process";
  operation: "spawn" | "terminal" | "signal";
  process_identity_sha256: string;
  parent_process_identity_sha256: string | null;
  command_identity_sha256: string;
  outcome: "running" | "completed" | "failed" | "signaled" | "blocked";
  exit_code: number | null;
  signal: string | null;
  reason_codes: readonly string[];
}

export interface RuntimeNetworkEvidenceBody {
  kind: "network";
  operation: "connect" | "send" | "receive" | "close";
  direction: "outbound" | "inbound";
  protocol: "tcp" | "tls" | "http" | "https" | "grpc" | "other";
  endpoint_identity_sha256: string;
  outcome: "success" | "failed" | "blocked";
  payload: RuntimeDigestOnlyContent | null;
  bytes_observed: number;
  reason_codes: readonly string[];
}

export interface RuntimeCredentialScopeEvidenceBody {
  kind: "credential_scope";
  credential_policy_sha256: string;
  requested_scope_ids: readonly string[];
  resolved_scope_ids: readonly string[];
  credential_slot_identity_sha256s: readonly string[];
  decision: "allowed" | "blocked";
  delivery_mechanism: "root_only_file" | "broker_handle" | null;
  reason_codes: readonly string[];
}

export interface RuntimeSideEffectEvidenceBody {
  kind: "side_effect";
  effect_kind:
    | "database_mutation"
    | "message_dispatch"
    | "external_tool"
    | "change_control"
    | "other";
  source_receipt_sha256: string;
  target_identity_sha256: string;
  request_identity_sha256: string;
  response_identity_sha256: string | null;
  state_root_before_sha256: string | null;
  state_root_after_sha256: string | null;
  outcome: "success" | "failed" | "blocked";
  reversible: boolean;
  reason_codes: readonly string[];
}

export interface RuntimeTerminalEvidenceBody {
  kind: "terminal";
  terminal_status: RuntimeTerminalStatus;
  reason_codes: readonly string[];
  preterminal_receipt_count: number;
  preterminal_chain_head_sha256: string;
  crash_recovery: boolean;
}

export type RuntimeEvidenceBody =
  | RuntimeFileEvidenceBody
  | RuntimeProcessEvidenceBody
  | RuntimeNetworkEvidenceBody
  | RuntimeCredentialScopeEvidenceBody
  | RuntimeSideEffectEvidenceBody
  | RuntimeTerminalEvidenceBody;

export interface RuntimeEvidenceReceipt {
  schema_version: typeof RUNTIME_RECEIPT_SCHEMA_VERSION;
  session_id: string;
  header_sha256: string;
  sequence: number;
  logical_time: number;
  observed_at: string;
  occurrence_id: string;
  previous_receipt_sha256: string;
  body: RuntimeEvidenceBody;
  receipt_sha256: string;
}

export interface RuntimeFinalization {
  schema_version: typeof RUNTIME_FINALIZATION_SCHEMA_VERSION;
  session_id: string;
  header_sha256: string;
  finalized_at: string;
  receipt_count: number;
  chain_head_sha256: string;
  terminal_receipt_sha256: string;
  terminal_status: RuntimeTerminalStatus;
  finalization_sha256: string;
}

export interface RuntimeAnchorStatement {
  schema_version: typeof RUNTIME_ANCHOR_STATEMENT_SCHEMA_VERSION;
  session_id: string;
  header_sha256: string;
  finalization_sha256: string;
  receipt_count: number;
  chain_head_sha256: string;
  statement_sha256: string;
}

export interface RuntimeAnchorReceipt {
  schema_version: typeof RUNTIME_ANCHOR_RECEIPT_SCHEMA_VERSION;
  store_id: string;
  anchor_sequence: number;
  anchored_at: string;
  previous_anchor_sha256: string;
  statement: RuntimeAnchorStatement;
  anchor_sha256: string;
}

export interface RuntimeEvidenceBundle {
  header: RuntimeEvidenceHeader;
  receipts: readonly RuntimeEvidenceReceipt[];
  finalization: RuntimeFinalization;
  anchor_receipt: RuntimeAnchorReceipt;
}

export interface RuntimeEvidenceVerification {
  ok: boolean;
  blockers: readonly string[];
  session_id: string | null;
  receipt_count: number;
  chain_head_sha256: string | null;
  terminal_status: RuntimeTerminalStatus | null;
  finalization_sha256: string | null;
  anchor_sha256: string | null;
  bundle_sha256: string | null;
  claim_boundary: "declared_runtime_observation_not_container_or_kubernetes_enforcement";
}

export interface RuntimeEvidencePrefixVerification {
  ok: boolean;
  blockers: readonly string[];
  header: RuntimeEvidenceHeader | null;
  receipts: readonly RuntimeEvidenceReceipt[];
  chain_head_sha256: string | null;
  terminal_status: RuntimeTerminalStatus | null;
}

export function runtimeHeaderSha256(header: RuntimeEvidenceHeader): string {
  return digestCanonical(withoutKey(header, "header_sha256"));
}

export function runtimeReceiptSha256(receipt: RuntimeEvidenceReceipt): string {
  return digestCanonical(withoutKey(receipt, "receipt_sha256"));
}

export function runtimeFinalizationSha256(finalization: RuntimeFinalization): string {
  return digestCanonical(withoutKey(finalization, "finalization_sha256"));
}

export function runtimeAnchorStatementSha256(statement: RuntimeAnchorStatement): string {
  return digestCanonical(withoutKey(statement, "statement_sha256"));
}

export function runtimeAnchorReceiptSha256(receipt: RuntimeAnchorReceipt): string {
  return digestCanonical(withoutKey(receipt, "anchor_sha256"));
}

/** Verify the exact portable G3 ABI admitted by the managed Guard API. */
export function verifyRuntimeEvidenceBundle(value: unknown): RuntimeEvidenceVerification {
  let bundle: RuntimeEvidenceBundle;
  try {
    bundle = parseRuntimeEvidenceBundle(value);
  } catch {
    return verification(["runtime_evidence_bundle_schema_invalid"], null, 0, null, null, null, null, null);
  }
  const header = bundle.header;
  const prefix = verifyParsedRuntimeEvidencePrefix(header, bundle.receipts, true);
  const blockers = new Set(prefix.blockers);
  const head = prefix.chain_head_sha256 ?? RUNTIME_GENESIS_SHA256;
  const terminalStatus = prefix.terminal_status;

  const finalization = bundle.finalization;
  if (finalization.session_id !== header.session_id) blockers.add("runtime_finalization_session_mismatch");
  if (finalization.header_sha256 !== header.header_sha256) blockers.add("runtime_finalization_header_mismatch");
  if (finalization.receipt_count !== bundle.receipts.length) {
    blockers.add("runtime_finalization_truncation_count_mismatch");
  }
  if (finalization.chain_head_sha256 !== head) {
    blockers.add("runtime_finalization_truncation_head_mismatch");
  }
  const terminal = bundle.receipts.at(-1);
  if (terminal?.body.kind !== "terminal") {
    blockers.add("runtime_finalization_terminal_receipt_missing");
  } else {
    if (finalization.terminal_receipt_sha256 !== terminal.receipt_sha256) {
      blockers.add("runtime_finalization_terminal_receipt_mismatch");
    }
    if (finalization.terminal_status !== terminal.body.terminal_status) {
      blockers.add("runtime_finalization_terminal_status_mismatch");
    }
    if (finalization.finalized_at < terminal.observed_at) {
      blockers.add("runtime_finalization_precedes_terminal");
    }
  }
  if (finalization.finalization_sha256 !== runtimeFinalizationSha256(finalization)) {
    blockers.add("runtime_finalization_digest_mismatch");
  }
  const expectedStatement = expectedRuntimeAnchorStatement(finalization);
  const anchor = bundle.anchor_receipt;
  if (canonicalJson(anchor.statement) !== canonicalJson(expectedStatement)) {
    blockers.add("runtime_anchor_statement_binding_mismatch");
  }
  if (anchor.anchor_sha256 !== runtimeAnchorReceiptSha256(anchor)) {
    blockers.add("runtime_anchor_receipt_digest_mismatch");
  }
  if (anchor.anchored_at < finalization.finalized_at) blockers.add("runtime_anchor_precedes_finalization");
  if (
    anchor.anchor_sequence !== 0 ||
    anchor.previous_anchor_sha256 !== RUNTIME_GENESIS_SHA256 ||
    anchor.statement.statement_sha256 !== runtimeAnchorStatementSha256(anchor.statement) ||
    anchor.anchor_sha256 !== runtimeAnchorReceiptSha256(anchor)
  ) {
    blockers.add("runtime_anchor_unverified");
  }
  return verification(
    [...blockers].sort(),
    header.session_id,
    bundle.receipts.length,
    isSha256(head) ? head : null,
    terminalStatus,
    finalization.finalization_sha256,
    anchor.anchor_sha256,
    digestCanonical(bundle),
  );
}

/** Verify a durable recorder prefix before appending or recovering it. */
export function verifyRuntimeEvidencePrefix(
  headerValue: unknown,
  receiptValues: unknown,
  requireTerminal = false,
): RuntimeEvidencePrefixVerification {
  try {
    const header = parseHeader(headerValue);
    if (!Array.isArray(receiptValues)) throw new Error("runtime_receipts_invalid");
    const receipts = receiptValues.map(parseReceipt);
    return verifyParsedRuntimeEvidencePrefix(header, receipts, requireTerminal);
  } catch {
    return {
      ok: false,
      blockers: ["runtime_evidence_prefix_schema_invalid"],
      header: null,
      receipts: [],
      chain_head_sha256: null,
      terminal_status: null,
    };
  }
}

function verifyParsedRuntimeEvidencePrefix(
  header: RuntimeEvidenceHeader,
  receipts: readonly RuntimeEvidenceReceipt[],
  requireTerminal: boolean,
): RuntimeEvidencePrefixVerification {
  const blockers = new Set<string>();
  if (header.header_sha256 !== runtimeHeaderSha256(header)) {
    blockers.add("runtime_header_digest_mismatch");
  }
  let head: string = RUNTIME_GENESIS_SHA256;
  let lastTimestamp = header.created_at;
  let lastLogicalTime = -1;
  let terminalStatus: RuntimeTerminalStatus | null = null;
  const receiptDigests = new Set<string>();
  const occurrenceIds = new Set<string>();
  receipts.forEach((receipt, index) => {
    if (receipt.session_id !== header.session_id) blockers.add(`runtime_receipt_session_mismatch:${index}`);
    if (receipt.header_sha256 !== header.header_sha256) blockers.add(`runtime_receipt_header_mismatch:${index}`);
    if (receipt.sequence !== index) blockers.add(`runtime_receipt_sequence_gap:${index}`);
    if (receipt.previous_receipt_sha256 !== head) blockers.add(`runtime_receipt_predecessor_missing_or_mismatch:${index}`);
    if (receipt.receipt_sha256 !== runtimeReceiptSha256(receipt)) blockers.add(`runtime_receipt_digest_mismatch:${index}`);
    if (receipt.observed_at < lastTimestamp) blockers.add(`runtime_receipt_timestamp_regressed:${index}`);
    if (receipt.logical_time < lastLogicalTime) blockers.add(`runtime_receipt_logical_time_regressed:${index}`);
    if (occurrenceIds.has(receipt.occurrence_id)) blockers.add(`runtime_occurrence_id_reused:${index}`);
    occurrenceIds.add(receipt.occurrence_id);
    if (terminalStatus !== null) blockers.add(`runtime_post_terminal_write:${index}`);
    if (receipt.body.kind === "credential_scope") {
      if (receipt.body.credential_policy_sha256 !== header.credential_policy_sha256) blockers.add(`runtime_credential_policy_mismatch:${index}`);
      const requested = new Set(receipt.body.requested_scope_ids);
      const declared = new Set(header.declared_credential_scope_ids);
      if (receipt.body.resolved_scope_ids.some((scope) => !requested.has(scope) || !declared.has(scope))) blockers.add(`runtime_false_credential_scope:${index}`);
    }
    if (receipt.body.kind === "side_effect" && !receiptDigests.has(receipt.body.source_receipt_sha256)) blockers.add(`runtime_side_effect_source_predecessor_missing:${index}`);
    if (receipt.body.kind === "terminal") {
      terminalStatus = receipt.body.terminal_status;
      if (receipt.body.preterminal_receipt_count !== index) blockers.add(`runtime_terminal_predecessor_count_mismatch:${index}`);
      if (receipt.body.preterminal_chain_head_sha256 !== head) blockers.add(`runtime_terminal_predecessor_head_mismatch:${index}`);
      if (index !== receipts.length - 1) blockers.add(`runtime_terminal_not_last:${index}`);
    }
    receiptDigests.add(receipt.receipt_sha256);
    head = receipt.receipt_sha256;
    lastTimestamp = receipt.observed_at;
    lastLogicalTime = receipt.logical_time;
  });
  if (requireTerminal && terminalStatus === null) blockers.add("runtime_terminal_receipt_missing");
  return {
    ok: blockers.size === 0,
    blockers: [...blockers].sort(),
    header,
    receipts,
    chain_head_sha256: isSha256(head) ? head : null,
    terminal_status: terminalStatus,
  };
}

function parseRuntimeEvidenceBundle(value: unknown): RuntimeEvidenceBundle {
  const bundle = requireRecord(value, "runtime_bundle");
  exactKeys(bundle, ["anchor_receipt", "finalization", "header", "receipts"]);
  const header = parseHeader(bundle["header"]);
  if (!Array.isArray(bundle["receipts"])) throw new Error("runtime_receipts_invalid");
  const receipts = bundle["receipts"].map(parseReceipt);
  const finalization = parseFinalization(bundle["finalization"]);
  const anchor = parseAnchorReceipt(bundle["anchor_receipt"]);
  return { header, receipts, finalization, anchor_receipt: anchor };
}

function parseHeader(value: unknown): RuntimeEvidenceHeader {
  const header = requireRecord(value, "runtime_header");
  exactKeys(header, [
    "bypass_declaration", "bypass_possible", "capture_boundary", "created_at",
    "credential_policy_sha256", "declared_credential_scope_ids", "header_sha256",
    "isolation_attestation", "policy_sha256", "runtime_identity_sha256",
    "runtime_version", "schema_version", "session_id",
  ]);
  if (header["schema_version"] !== RUNTIME_HEADER_SCHEMA_VERSION) throw new Error("runtime_header_schema_invalid");
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(requireString(header["runtime_version"]))) {
    throw new Error("runtime_version_invalid");
  }
  assertStableId(requireString(header["session_id"]), "runtime_session_id");
  requireTimestamp(header["created_at"]);
  if (
    header["capture_boundary"] !== "declared_runtime_recorder" ||
    header["bypass_possible"] !== true ||
    header["bypass_declaration"] !== "operations_outside_this_recorder_are_not_observed_or_enforced" ||
    header["isolation_attestation"] !== "not_attested"
  ) throw new Error("runtime_header_boundary_invalid");
  for (const key of ["runtime_identity_sha256", "policy_sha256", "credential_policy_sha256", "header_sha256"]) {
    requireDigest(header[key]);
  }
  requireCanonicalIds(header["declared_credential_scope_ids"]);
  return header as unknown as RuntimeEvidenceHeader;
}

function parseReceipt(value: unknown): RuntimeEvidenceReceipt {
  const receipt = requireRecord(value, "runtime_receipt");
  exactKeys(receipt, [
    "body", "header_sha256", "logical_time", "observed_at", "occurrence_id",
    "previous_receipt_sha256", "receipt_sha256", "schema_version", "sequence", "session_id",
  ]);
  if (receipt["schema_version"] !== RUNTIME_RECEIPT_SCHEMA_VERSION) throw new Error("runtime_receipt_schema_invalid");
  assertStableId(requireString(receipt["session_id"]), "runtime_receipt_session_id");
  assertStableId(requireString(receipt["occurrence_id"]), "runtime_occurrence_id");
  requireDigest(receipt["header_sha256"]);
  requireDigest(receipt["previous_receipt_sha256"]);
  requireDigest(receipt["receipt_sha256"]);
  requireInteger(receipt["sequence"]);
  requireInteger(receipt["logical_time"]);
  requireTimestamp(receipt["observed_at"]);
  const body = parseBody(receipt["body"]);
  return { ...(receipt as unknown as Omit<RuntimeEvidenceReceipt, "body">), body };
}

function parseBody(value: unknown): RuntimeEvidenceBody {
  const body = requireRecord(value, "runtime_body");
  switch (body["kind"]) {
    case "file": return parseFileBody(body);
    case "process": return parseProcessBody(body);
    case "network": return parseNetworkBody(body);
    case "credential_scope": return parseCredentialBody(body);
    case "side_effect": return parseSideEffectBody(body);
    case "terminal": return parseTerminalBody(body);
    default: throw new Error("runtime_body_kind_invalid");
  }
}

function parseFileBody(body: Record<string, unknown>): RuntimeFileEvidenceBody {
  exactKeys(body, ["after", "before", "bytes_observed", "kind", "operation", "outcome", "path_identity_sha256", "reason_codes", "target_path_identity_sha256"]);
  requireOne(body["operation"], ["read", "write", "create", "delete", "rename", "stat"]);
  requireOne(body["outcome"], ["success", "failed", "blocked"]);
  requireDigest(body["path_identity_sha256"]);
  requireNullableDigest(body["target_path_identity_sha256"]);
  const before = parseNullableContent(body["before"]);
  const after = parseNullableContent(body["after"]);
  const bytes = requireInteger(body["bytes_observed"]);
  requireCanonicalIds(body["reason_codes"]);
  if ((body["operation"] === "rename") !== (body["target_path_identity_sha256"] !== null)) throw new Error("runtime_file_rename_target_shape_invalid");
  if (body["outcome"] === "blocked" && (bytes !== 0 || canonicalJson(after) !== canonicalJson(before))) throw new Error("runtime_blocked_file_effect_recorded");
  if (["read", "stat"].includes(String(body["operation"])) && canonicalJson(after) !== canonicalJson(before)) throw new Error("runtime_read_only_file_mutation_recorded");
  return { ...(body as unknown as RuntimeFileEvidenceBody), before, after };
}

function parseProcessBody(body: Record<string, unknown>): RuntimeProcessEvidenceBody {
  exactKeys(body, ["command_identity_sha256", "exit_code", "kind", "operation", "outcome", "parent_process_identity_sha256", "process_identity_sha256", "reason_codes", "signal"]);
  requireOne(body["operation"], ["spawn", "terminal", "signal"]);
  requireOne(body["outcome"], ["running", "completed", "failed", "signaled", "blocked"]);
  requireDigest(body["process_identity_sha256"]);
  requireDigest(body["command_identity_sha256"]);
  requireNullableDigest(body["parent_process_identity_sha256"]);
  requireCanonicalIds(body["reason_codes"]);
  const exitCode = body["exit_code"] === null ? null : requireSignedInteger(body["exit_code"]);
  const signal = body["signal"];
  if (signal !== null && (typeof signal !== "string" || !/^SIG[A-Z0-9]+$/.test(signal))) throw new Error("runtime_process_signal_invalid");
  if (["running", "blocked"].includes(String(body["outcome"])) && (exitCode !== null || signal !== null)) throw new Error("runtime_nonterminal_process_has_terminal_status");
  if (body["outcome"] === "completed" && (exitCode !== 0 || signal !== null)) throw new Error("runtime_completed_process_status_invalid");
  if (body["outcome"] === "failed" && (exitCode === null || exitCode === 0 || signal !== null)) throw new Error("runtime_failed_process_status_invalid");
  if (body["outcome"] === "signaled" && (signal === null || exitCode !== null)) throw new Error("runtime_signaled_process_status_invalid");
  if (body["operation"] === "spawn" && !["running", "blocked"].includes(String(body["outcome"]))) throw new Error("runtime_process_spawn_outcome_invalid");
  if (body["operation"] === "terminal" && ["running", "blocked"].includes(String(body["outcome"]))) throw new Error("runtime_process_terminal_outcome_invalid");
  return body as unknown as RuntimeProcessEvidenceBody;
}

function parseNetworkBody(body: Record<string, unknown>): RuntimeNetworkEvidenceBody {
  exactKeys(body, ["bytes_observed", "direction", "endpoint_identity_sha256", "kind", "operation", "outcome", "payload", "protocol", "reason_codes"]);
  requireOne(body["operation"], ["connect", "send", "receive", "close"]);
  requireOne(body["direction"], ["outbound", "inbound"]);
  requireOne(body["protocol"], ["tcp", "tls", "http", "https", "grpc", "other"]);
  requireOne(body["outcome"], ["success", "failed", "blocked"]);
  requireDigest(body["endpoint_identity_sha256"]);
  requireCanonicalIds(body["reason_codes"]);
  const payload = parseNullableContent(body["payload"]);
  const bytes = requireInteger(body["bytes_observed"]);
  if (["connect", "close"].includes(String(body["operation"])) && (payload !== null || bytes !== 0)) throw new Error("runtime_network_lifecycle_payload_invalid");
  if (payload !== null && bytes !== payload.byte_length) throw new Error("runtime_network_payload_length_mismatch");
  if (payload === null && ["send", "receive"].includes(String(body["operation"])) && bytes !== 0) throw new Error("runtime_network_payload_identity_missing");
  return { ...(body as unknown as RuntimeNetworkEvidenceBody), payload };
}

function parseCredentialBody(body: Record<string, unknown>): RuntimeCredentialScopeEvidenceBody {
  exactKeys(body, ["credential_policy_sha256", "credential_slot_identity_sha256s", "decision", "delivery_mechanism", "kind", "reason_codes", "requested_scope_ids", "resolved_scope_ids"]);
  requireDigest(body["credential_policy_sha256"]);
  requireCanonicalIds(body["requested_scope_ids"]);
  requireCanonicalIds(body["resolved_scope_ids"]);
  requireCanonicalDigests(body["credential_slot_identity_sha256s"]);
  requireCanonicalIds(body["reason_codes"]);
  requireOne(body["decision"], ["allowed", "blocked"]);
  if (body["delivery_mechanism"] !== null) requireOne(body["delivery_mechanism"], ["root_only_file", "broker_handle"]);
  const requested = body["requested_scope_ids"] as unknown[];
  const resolved = body["resolved_scope_ids"] as unknown[];
  const slots = body["credential_slot_identity_sha256s"] as unknown[];
  if (body["decision"] === "allowed" && (requested.length === 0 || resolved.length === 0 || slots.length === 0 || body["delivery_mechanism"] === null)) throw new Error("runtime_allowed_credential_scope_shape_invalid");
  if (body["decision"] === "blocked" && (resolved.length > 0 || slots.length > 0 || body["delivery_mechanism"] !== null)) throw new Error("runtime_blocked_credential_scope_delivery_recorded");
  return body as unknown as RuntimeCredentialScopeEvidenceBody;
}

function parseSideEffectBody(body: Record<string, unknown>): RuntimeSideEffectEvidenceBody {
  exactKeys(body, ["effect_kind", "kind", "outcome", "reason_codes", "request_identity_sha256", "response_identity_sha256", "reversible", "source_receipt_sha256", "state_root_after_sha256", "state_root_before_sha256", "target_identity_sha256"]);
  requireOne(body["effect_kind"], ["database_mutation", "message_dispatch", "external_tool", "change_control", "other"]);
  requireOne(body["outcome"], ["success", "failed", "blocked"]);
  for (const key of ["source_receipt_sha256", "target_identity_sha256", "request_identity_sha256"]) requireDigest(body[key]);
  for (const key of ["response_identity_sha256", "state_root_before_sha256", "state_root_after_sha256"]) requireNullableDigest(body[key]);
  if (typeof body["reversible"] !== "boolean") throw new Error("runtime_side_effect_reversible_invalid");
  requireCanonicalIds(body["reason_codes"]);
  if (body["outcome"] === "blocked" && (body["response_identity_sha256"] !== null || body["state_root_after_sha256"] !== body["state_root_before_sha256"])) throw new Error("runtime_blocked_side_effect_recorded");
  return body as unknown as RuntimeSideEffectEvidenceBody;
}

function parseTerminalBody(body: Record<string, unknown>): RuntimeTerminalEvidenceBody {
  exactKeys(body, ["crash_recovery", "kind", "preterminal_chain_head_sha256", "preterminal_receipt_count", "reason_codes", "terminal_status"]);
  requireOne(body["terminal_status"], ["completed", "failed", "crashed", "cancelled"]);
  requireCanonicalIds(body["reason_codes"]);
  requireInteger(body["preterminal_receipt_count"]);
  requireDigest(body["preterminal_chain_head_sha256"]);
  if (typeof body["crash_recovery"] !== "boolean") throw new Error("runtime_terminal_crash_recovery_invalid");
  if (body["crash_recovery"] === true && body["terminal_status"] !== "crashed") throw new Error("runtime_terminal_false_crash_recovery");
  return body as unknown as RuntimeTerminalEvidenceBody;
}

function parseFinalization(value: unknown): RuntimeFinalization {
  const item = requireRecord(value, "runtime_finalization");
  exactKeys(item, ["chain_head_sha256", "finalization_sha256", "finalized_at", "header_sha256", "receipt_count", "schema_version", "session_id", "terminal_receipt_sha256", "terminal_status"]);
  if (item["schema_version"] !== RUNTIME_FINALIZATION_SCHEMA_VERSION) throw new Error("runtime_finalization_schema_invalid");
  assertStableId(requireString(item["session_id"]), "runtime_finalization_session_id");
  requireTimestamp(item["finalized_at"]);
  requireInteger(item["receipt_count"], 1);
  for (const key of ["chain_head_sha256", "finalization_sha256", "header_sha256", "terminal_receipt_sha256"]) requireDigest(item[key]);
  requireOne(item["terminal_status"], ["completed", "failed", "crashed", "cancelled"]);
  return item as unknown as RuntimeFinalization;
}

function parseAnchorStatement(value: unknown): RuntimeAnchorStatement {
  const item = requireRecord(value, "runtime_anchor_statement");
  exactKeys(item, ["chain_head_sha256", "finalization_sha256", "header_sha256", "receipt_count", "schema_version", "session_id", "statement_sha256"]);
  if (item["schema_version"] !== RUNTIME_ANCHOR_STATEMENT_SCHEMA_VERSION) throw new Error("runtime_anchor_statement_schema_invalid");
  assertStableId(requireString(item["session_id"]), "runtime_anchor_session_id");
  requireInteger(item["receipt_count"], 1);
  for (const key of ["chain_head_sha256", "finalization_sha256", "header_sha256", "statement_sha256"]) requireDigest(item[key]);
  return item as unknown as RuntimeAnchorStatement;
}

function parseAnchorReceipt(value: unknown): RuntimeAnchorReceipt {
  const item = requireRecord(value, "runtime_anchor_receipt");
  exactKeys(item, ["anchor_sequence", "anchor_sha256", "anchored_at", "previous_anchor_sha256", "schema_version", "statement", "store_id"]);
  if (item["schema_version"] !== RUNTIME_ANCHOR_RECEIPT_SCHEMA_VERSION) throw new Error("runtime_anchor_receipt_schema_invalid");
  assertStableId(requireString(item["store_id"]), "runtime_anchor_store_id");
  requireInteger(item["anchor_sequence"]);
  requireTimestamp(item["anchored_at"]);
  requireDigest(item["previous_anchor_sha256"]);
  requireDigest(item["anchor_sha256"]);
  const statement = parseAnchorStatement(item["statement"]);
  return { ...(item as unknown as Omit<RuntimeAnchorReceipt, "statement">), statement };
}

function parseNullableContent(value: unknown): RuntimeDigestOnlyContent | null {
  if (value === null) return null;
  const item = requireRecord(value, "runtime_content");
  exactKeys(item, ["byte_length", "media_type", "plaintext_sha256", "schema_version"]);
  if (item["schema_version"] !== "gradia.guard.digest-only-content.v1") throw new Error("runtime_content_schema_invalid");
  const media = requireString(item["media_type"]);
  if (media.length < 1 || media.length > 200 || [...media].some((char) => char.charCodeAt(0) < 0x20 || char.charCodeAt(0) > 0x7e)) throw new Error("runtime_content_media_type_invalid");
  requireInteger(item["byte_length"]);
  requireDigest(item["plaintext_sha256"]);
  return item as unknown as RuntimeDigestOnlyContent;
}

function expectedRuntimeAnchorStatement(finalization: RuntimeFinalization): RuntimeAnchorStatement {
  const body = {
    schema_version: RUNTIME_ANCHOR_STATEMENT_SCHEMA_VERSION,
    session_id: finalization.session_id,
    header_sha256: finalization.header_sha256,
    finalization_sha256: finalization.finalization_sha256,
    receipt_count: finalization.receipt_count,
    chain_head_sha256: finalization.chain_head_sha256,
  };
  return { ...body, statement_sha256: digestCanonical(body) };
}

function verification(
  blockers: readonly string[], sessionId: string | null, receiptCount: number,
  chainHead: string | null, terminalStatus: RuntimeTerminalStatus | null,
  finalizationSha256: string | null, anchorSha256: string | null,
  bundleSha256: string | null,
): RuntimeEvidenceVerification {
  return {
    ok: blockers.length === 0,
    blockers: [...new Set(blockers)].sort(),
    session_id: sessionId,
    receipt_count: receiptCount,
    chain_head_sha256: chainHead,
    terminal_status: terminalStatus,
    finalization_sha256: finalizationSha256,
    anchor_sha256: anchorSha256,
    bundle_sha256: bundleSha256,
    claim_boundary: "declared_runtime_observation_not_container_or_kubernetes_enforcement",
  };
}

function withoutKey<T extends object, K extends keyof T>(value: T, key: K): Omit<T, K> {
  const copy = { ...value };
  delete copy[key];
  return copy;
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label}_shape_invalid`);
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): void {
  if (canonicalJson(Object.keys(value).sort()) !== canonicalJson([...expected].sort())) throw new Error("runtime_fields_invalid");
}

function requireString(value: unknown): string {
  if (typeof value !== "string") throw new Error("runtime_string_invalid");
  return value;
}

function requireTimestamp(value: unknown): string {
  const timestamp = requireString(value);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(timestamp)) throw new Error("runtime_timestamp_invalid");
  return timestamp;
}

function requireDigest(value: unknown): string {
  if (typeof value !== "string" || !isSha256(value)) throw new Error("runtime_digest_invalid");
  return value;
}

function requireNullableDigest(value: unknown): void {
  if (value !== null) requireDigest(value);
}

function requireInteger(value: unknown, minimum = 0): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) throw new Error("runtime_integer_invalid");
  return value as number;
}

function requireSignedInteger(value: unknown): number {
  if (!Number.isSafeInteger(value)) throw new Error("runtime_integer_invalid");
  return value as number;
}

function requireOne(value: unknown, options: readonly string[]): string {
  if (typeof value !== "string" || !options.includes(value)) throw new Error("runtime_enum_invalid");
  return value;
}

function requireCanonicalIds(value: unknown): readonly string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) throw new Error("runtime_ids_invalid");
  const items = value as string[];
  items.forEach((item) => assertStableId(item, "runtime_id"));
  if (items.some((item, index) => index > 0 && String(items[index - 1]) >= item)) throw new Error("runtime_ids_not_canonical");
  return items;
}

function requireCanonicalDigests(value: unknown): readonly string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || !isSha256(item))) throw new Error("runtime_digests_invalid");
  const items = value as string[];
  if (items.some((item, index) => index > 0 && String(items[index - 1]) >= item)) throw new Error("runtime_digests_not_canonical");
  return items;
}
