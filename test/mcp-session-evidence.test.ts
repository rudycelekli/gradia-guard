import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { McpSessionJournal, verifyMcpSessionJournal } from "../src/mcp-session-evidence.js";

test("session metadata journal refuses interrupted prefixes and post-finalization mutation", () => {
  const root = mkdtempSync(join(tmpdir(), "guard-session-journal-"));
  try {
    const journal = new McpSessionJournal(join(root, "session"), { privateInput: "not retained" });
    journal.append("request", { secretArgument: "not retained" });
    assert.throws(() => verifyMcpSessionJournal(journal.path), /incomplete_no_replay/);
    const closed = journal.finish();
    assert.equal(closed.receipt_count, 3);
    const original = readFileSync(journal.path, "utf8");
    assert.equal(original.includes("not retained"), false);
    writeFileSync(journal.path, original.replace('"index":1', '"index":2'));
    assert.throws(() => verifyMcpSessionJournal(journal.path), /invalid/);
    writeFileSync(journal.path, original.slice(0, -10));
    assert.throws(() => verifyMcpSessionJournal(journal.path), /invalid/);
  } finally { rmSync(root, { recursive: true }); }
});
