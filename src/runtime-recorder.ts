import { randomBytes } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  writeSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { canonicalJson, digestCanonical } from "./canonical.js";
import {
  RUNTIME_ANCHOR_RECEIPT_SCHEMA_VERSION,
  RUNTIME_ANCHOR_STATEMENT_SCHEMA_VERSION,
  RUNTIME_FINALIZATION_SCHEMA_VERSION,
  RUNTIME_GENESIS_SHA256,
  RUNTIME_HEADER_SCHEMA_VERSION,
  RUNTIME_RECEIPT_SCHEMA_VERSION,
  runtimeAnchorReceiptSha256,
  runtimeAnchorStatementSha256,
  runtimeFinalizationSha256,
  runtimeReceiptSha256,
  verifyRuntimeEvidenceBundle,
  verifyRuntimeEvidencePrefix,
  type RuntimeAnchorReceipt,
  type RuntimeAnchorStatement,
  type RuntimeEvidenceBody,
  type RuntimeEvidenceBundle,
  type RuntimeEvidenceHeader,
  type RuntimeEvidenceReceipt,
  type RuntimeFinalization,
  type RuntimeTerminalEvidenceBody,
  type RuntimeTerminalStatus,
} from "./runtime-evidence.js";
import { assertStableId } from "./security.js";

export interface RuntimeEvidenceRecorderOptions {
  directory: string;
  runtimeVersion: string;
  sessionId: string;
  createdAt: string;
  runtimeIdentitySha256: string;
  policySha256: string;
  credentialPolicySha256: string;
  declaredCredentialScopeIds: readonly string[];
  anchorStoreId?: string;
}

export interface RuntimeReceiptAppendOptions {
  logicalTime: number;
  observedAt: string;
  occurrenceId: string;
}

export interface RuntimeTerminalizeOptions extends RuntimeReceiptAppendOptions {
  terminalStatus: RuntimeTerminalStatus;
  reasonCodes: readonly string[];
  crashRecovery: boolean;
}

/**
 * A local fsync-backed producer for the portable G3 ABI.
 *
 * The journal proves that these bytes form a durable, recoverable declared
 * recorder prefix. It deliberately does not claim that the process owns root,
 * that calls around it were prevented, or that the host persisted the bytes.
 */
export class DurableRuntimeEvidenceRecorder {
  readonly directory: string;
  readonly headerPath: string;
  readonly receiptsPath: string;
  readonly bundlePath: string;
  readonly header: RuntimeEvidenceHeader;
  private readonly anchorStoreId: string;
  private receiptList: RuntimeEvidenceReceipt[];
  private terminalStatus: RuntimeTerminalStatus | null;
  private finalized: boolean;

  constructor(options: RuntimeEvidenceRecorderOptions) {
    if (existsSync(options.directory)) throw new Error("runtime_recorder_directory_exists");
    assertStableId(options.anchorStoreId ?? "local-portable-anchor.v1", "runtime_anchor_store_id");
    const headerBody = {
      schema_version: RUNTIME_HEADER_SCHEMA_VERSION,
      runtime_version: options.runtimeVersion,
      session_id: options.sessionId,
      created_at: options.createdAt,
      capture_boundary: "declared_runtime_recorder" as const,
      bypass_possible: true as const,
      bypass_declaration:
        "operations_outside_this_recorder_are_not_observed_or_enforced" as const,
      isolation_attestation: "not_attested" as const,
      runtime_identity_sha256: options.runtimeIdentitySha256,
      policy_sha256: options.policySha256,
      credential_policy_sha256: options.credentialPolicySha256,
      declared_credential_scope_ids: [...options.declaredCredentialScopeIds],
    };
    const header: RuntimeEvidenceHeader = {
      ...headerBody,
      header_sha256: digestCanonical(headerBody),
    };
    const initial = verifyRuntimeEvidencePrefix(header, [], false);
    if (!initial.ok) throw new Error(`runtime_recorder_header_invalid:${initial.blockers.join(",")}`);
    mkdirSync(options.directory, { recursive: false, mode: 0o700 });
    this.directory = options.directory;
    this.headerPath = join(options.directory, "header.json");
    this.receiptsPath = join(options.directory, "receipts.ndjson");
    this.bundlePath = join(options.directory, "bundle.json");
    this.header = header;
    this.anchorStoreId = options.anchorStoreId ?? "local-portable-anchor.v1";
    this.receiptList = [];
    this.terminalStatus = null;
    this.finalized = false;
    writeDurableCanonical(this.headerPath, header);
    writeDurableNewFile(this.receiptsPath, "");
  }

  private static fromRecovered(
    directory: string,
    header: RuntimeEvidenceHeader,
    receipts: RuntimeEvidenceReceipt[],
    anchorStoreId: string,
  ): DurableRuntimeEvidenceRecorder {
    const recorder = Object.create(DurableRuntimeEvidenceRecorder.prototype) as DurableRuntimeEvidenceRecorder;
    const terminal = receipts.at(-1);
    const recoveredTerminalStatus = terminal?.body.kind === "terminal"
      ? terminal.body.terminal_status
      : null;
    Object.defineProperties(recorder, {
      directory: { value: directory, enumerable: true },
      headerPath: { value: join(directory, "header.json"), enumerable: true },
      receiptsPath: { value: join(directory, "receipts.ndjson"), enumerable: true },
      bundlePath: { value: join(directory, "bundle.json"), enumerable: true },
      header: { value: header, enumerable: true },
      anchorStoreId: { value: anchorStoreId, writable: false },
      receiptList: { value: receipts, writable: true },
      terminalStatus: {
        value: recoveredTerminalStatus,
        writable: true,
      },
      finalized: { value: false, writable: true },
    });
    return recorder;
  }

  static recover(directory: string, anchorStoreId = "local-portable-anchor.v1"): DurableRuntimeEvidenceRecorder {
    if (existsSync(join(directory, "bundle.json"))) throw new Error("runtime_recorder_already_finalized");
    assertStableId(anchorStoreId, "runtime_anchor_store_id");
    let header: unknown;
    let receipts: unknown[];
    try {
      header = JSON.parse(readFileSync(join(directory, "header.json"), "utf8")) as unknown;
      const text = readFileSync(join(directory, "receipts.ndjson"), "utf8");
      if (text.length > 0 && !text.endsWith("\n")) throw new Error("runtime_receipt_journal_truncated");
      receipts = text.split("\n").filter(Boolean).map((line) => JSON.parse(line) as unknown);
    } catch (error) {
      if (error instanceof Error && error.message === "runtime_receipt_journal_truncated") throw error;
      throw new Error("runtime_recorder_recovery_unreadable");
    }
    const verification = verifyRuntimeEvidencePrefix(header, receipts, false);
    if (!verification.ok || verification.header === null) {
      throw new Error(`runtime_recorder_recovery_invalid:${verification.blockers.join(",")}`);
    }
    return DurableRuntimeEvidenceRecorder.fromRecovered(
      directory,
      verification.header,
      [...verification.receipts],
      anchorStoreId,
    );
  }

  get receipts(): readonly RuntimeEvidenceReceipt[] {
    return Object.freeze([...this.receiptList]);
  }

  append(body: Exclude<RuntimeEvidenceBody, RuntimeTerminalEvidenceBody>, options: RuntimeReceiptAppendOptions): RuntimeEvidenceReceipt {
    if (this.finalized) throw new Error("runtime_post_finalization_write");
    if (this.terminalStatus !== null) throw new Error("runtime_post_terminal_write");
    const receipt = this.buildReceipt(body, options);
    this.admitAndPersist(receipt, false);
    return receipt;
  }

  terminalize(options: RuntimeTerminalizeOptions): RuntimeEvidenceReceipt {
    if (this.finalized) throw new Error("runtime_post_finalization_write");
    if (this.terminalStatus !== null) throw new Error("runtime_terminal_already_recorded");
    const body: RuntimeTerminalEvidenceBody = {
      kind: "terminal",
      terminal_status: options.terminalStatus,
      reason_codes: [...options.reasonCodes],
      preterminal_receipt_count: this.receiptList.length,
      preterminal_chain_head_sha256:
        this.receiptList.at(-1)?.receipt_sha256 ?? RUNTIME_GENESIS_SHA256,
      crash_recovery: options.crashRecovery,
    };
    const receipt = this.buildReceipt(body, options);
    this.admitAndPersist(receipt, true);
    this.terminalStatus = options.terminalStatus;
    return receipt;
  }

  finalize(finalizedAt: string): RuntimeEvidenceBundle {
    if (this.finalized) throw new Error("runtime_already_finalized");
    const terminal = this.receiptList.at(-1);
    if (terminal?.body.kind !== "terminal" || this.terminalStatus === null) {
      throw new Error("runtime_terminal_receipt_missing");
    }
    const finalizationBody = {
      schema_version: RUNTIME_FINALIZATION_SCHEMA_VERSION,
      session_id: this.header.session_id,
      header_sha256: this.header.header_sha256,
      finalized_at: finalizedAt,
      receipt_count: this.receiptList.length,
      chain_head_sha256: terminal.receipt_sha256,
      terminal_receipt_sha256: terminal.receipt_sha256,
      terminal_status: this.terminalStatus,
    };
    const finalization: RuntimeFinalization = {
      ...finalizationBody,
      finalization_sha256: digestCanonical(finalizationBody),
    };
    if (finalization.finalization_sha256 !== runtimeFinalizationSha256(finalization)) {
      throw new Error("runtime_finalization_digest_mismatch");
    }
    const statementBody = {
      schema_version: RUNTIME_ANCHOR_STATEMENT_SCHEMA_VERSION,
      session_id: this.header.session_id,
      header_sha256: this.header.header_sha256,
      finalization_sha256: finalization.finalization_sha256,
      receipt_count: this.receiptList.length,
      chain_head_sha256: terminal.receipt_sha256,
    };
    const statement: RuntimeAnchorStatement = {
      ...statementBody,
      statement_sha256: digestCanonical(statementBody),
    };
    if (statement.statement_sha256 !== runtimeAnchorStatementSha256(statement)) {
      throw new Error("runtime_anchor_statement_digest_mismatch");
    }
    const anchorBody = {
      schema_version: RUNTIME_ANCHOR_RECEIPT_SCHEMA_VERSION,
      store_id: this.anchorStoreId,
      anchor_sequence: 0,
      anchored_at: finalizedAt,
      previous_anchor_sha256: RUNTIME_GENESIS_SHA256,
      statement,
    };
    const anchor: RuntimeAnchorReceipt = {
      ...anchorBody,
      anchor_sha256: digestCanonical(anchorBody),
    };
    if (anchor.anchor_sha256 !== runtimeAnchorReceiptSha256(anchor)) {
      throw new Error("runtime_anchor_receipt_digest_mismatch");
    }
    const bundle: RuntimeEvidenceBundle = {
      header: this.header,
      receipts: [...this.receiptList],
      finalization,
      anchor_receipt: anchor,
    };
    const verification = verifyRuntimeEvidenceBundle(bundle);
    if (!verification.ok) throw new Error(`runtime_bundle_unverified:${verification.blockers.join(",")}`);
    writeDurableCanonical(this.bundlePath, bundle);
    this.finalized = true;
    return bundle;
  }

  private buildReceipt(
    body: RuntimeEvidenceBody,
    options: RuntimeReceiptAppendOptions,
  ): RuntimeEvidenceReceipt {
    assertStableId(options.occurrenceId, "runtime_occurrence_id");
    const receiptBody = {
      schema_version: RUNTIME_RECEIPT_SCHEMA_VERSION,
      session_id: this.header.session_id,
      header_sha256: this.header.header_sha256,
      sequence: this.receiptList.length,
      logical_time: options.logicalTime,
      observed_at: options.observedAt,
      occurrence_id: options.occurrenceId,
      previous_receipt_sha256:
        this.receiptList.at(-1)?.receipt_sha256 ?? RUNTIME_GENESIS_SHA256,
      body,
    };
    const receipt: RuntimeEvidenceReceipt = {
      ...receiptBody,
      receipt_sha256: digestCanonical(receiptBody),
    };
    if (receipt.receipt_sha256 !== runtimeReceiptSha256(receipt)) {
      throw new Error("runtime_receipt_digest_mismatch");
    }
    return receipt;
  }

  private admitAndPersist(receipt: RuntimeEvidenceReceipt, requireTerminal: boolean): void {
    const candidate = [...this.receiptList, receipt];
    const verification = verifyRuntimeEvidencePrefix(this.header, candidate, requireTerminal);
    if (!verification.ok) throw new Error(`runtime_receipt_refused:${verification.blockers.join(",")}`);
    appendDurableLine(this.receiptsPath, canonicalJson(receipt));
    this.receiptList = candidate;
  }
}

export function loadRuntimeEvidenceBundle(path: string): RuntimeEvidenceBundle {
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, "utf8")) as unknown;
  } catch {
    throw new Error("runtime_bundle_unreadable");
  }
  const verification = verifyRuntimeEvidenceBundle(value);
  if (!verification.ok) throw new Error(`runtime_bundle_unverified:${verification.blockers.join(",")}`);
  return value as RuntimeEvidenceBundle;
}

function writeDurableCanonical(path: string, value: unknown): void {
  const temporary = `${path}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  writeDurableNewFile(temporary, `${canonicalJson(value)}\n`);
  renameSync(temporary, path);
  fsyncDirectory(dirname(path));
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

function fsyncDirectory(directory: string): void {
  const descriptor = openSync(directory, "r");
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}
