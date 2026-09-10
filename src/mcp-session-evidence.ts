import { closeSync, constants, fstatSync, fsyncSync, mkdirSync, openSync, readFileSync, writeSync } from "node:fs";
import { dirname, join } from "node:path";
import { canonicalJson, digestCanonical } from "./canonical.js";

export const MCP_SESSION_VERSION = "2025-11-25" as const;
export interface McpSessionProfile {
  protocol_version: typeof MCP_SESSION_VERSION;
  server_name: string;
  server_version: string;
  tool_input_schema_sha256: Readonly<Record<string, string>>;
}

/** Payload-free control/notification journal. No resumable transport or replay. */
export class McpSessionJournal {
  readonly path: string;
  private head = "0".repeat(64);
  private count = 0;
  private closed = false;
  constructor(directory: string, binding: Record<string, unknown>) {
    mkdirSync(directory, { mode: 0o700 });
    this.path = join(directory, "session.ndjson");
    const fd = openSync(this.path, "wx", 0o600);
    fsyncSync(fd);
    closeSync(fd);
    for (const path of [directory, dirname(directory)]) {
      const directoryFd = openSync(path, "r");
      try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
    }
    this.append("opened", binding);
  }
  append(kind: string, body: unknown): void {
    if (this.closed || this.count >= 4096) throw new Error("mcp_session_journal_closed_or_full");
    const row = { schema: "gradia.guard.mcp-session-receipt.v1", index: this.count,
      previous_sha256: this.head, kind, body_sha256: digestCanonical(body) };
    const receipt = { ...row, sha256: digestCanonical(row) };
    const bytes = Buffer.from(canonicalJson(receipt) + "\n");
    const fd = openSync(this.path, constants.O_APPEND | constants.O_WRONLY | constants.O_NOFOLLOW);
    try {
      let written = 0;
      while (written < bytes.length) {
        const size = writeSync(fd, bytes, written, bytes.length - written);
        if (size <= 0) throw new Error("mcp_session_journal_write_failed");
        written += size;
      }
      fsyncSync(fd);
    } finally { closeSync(fd); }
    this.head = receipt.sha256;
    this.count++;
  }
  finish(): { path: string; receipt_count: number; chain_head_sha256: string } {
    this.append("closed", { transport_resumable: false });
    this.closed = true;
    return verifyMcpSessionJournal(this.path);
  }
}

export function verifyMcpSessionJournal(path: string): {
  path: string; receipt_count: number; chain_head_sha256: string;
} {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  let bytes: string;
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > 4_000_000) throw new Error("mcp_session_journal_invalid");
    bytes = readFileSync(fd, "utf8");
  } finally { closeSync(fd); }
  if (bytes.length > 4_000_000 || !bytes.endsWith("\n")) throw new Error("mcp_session_journal_invalid");
  const lines = bytes.slice(0, -1).split("\n");
  if (lines.length > 4096) throw new Error("mcp_session_journal_invalid");
  let head = "0".repeat(64);
  for (const [index, line] of lines.entries()) {
    const row = JSON.parse(line) as Record<string, unknown>;
    const { sha256, ...body } = row;
    if (canonicalJson(row) !== line || Object.keys(row).sort().join() !==
      "body_sha256,index,kind,previous_sha256,schema,sha256" || row["index"] !== index
      || row["schema"] !== "gradia.guard.mcp-session-receipt.v1"
      || row["previous_sha256"] !== head || sha256 !== digestCanonical(body)
      || typeof row["body_sha256"] !== "string" || !/^[0-9a-f]{64}$/.test(row["body_sha256"])
      || !["opened", "request", "incoming", "outgoing_notification", "closed"].includes(row["kind"] as string)
      || (index > 0 && row["kind"] === "opened") || (index === 0 && row["kind"] !== "opened")
      || (index < lines.length - 1 && row["kind"] === "closed")) {
      throw new Error("mcp_session_journal_invalid");
    }
    head = sha256 as string;
  }
  if (lines.length < 2 || JSON.parse(lines.at(-1) as string)["kind"] !== "closed") {
    throw new Error("mcp_session_journal_incomplete_no_replay");
  }
  return { path, receipt_count: lines.length, chain_head_sha256: head };
}
