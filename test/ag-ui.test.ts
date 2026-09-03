import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import {
  canonicalJson,
  createProofBoundAguiProposal,
  digestCanonical,
  parseProofBoundAguiSse,
  parseProofBoundAguiSseStream,
  proofBoundAguiRequestedActionSha256,
  sha256,
  verifyProofBoundAguiActionReceipt,
  verifyProofBoundAguiEvent,
  verifyProofBoundAguiProposal,
} from "../src/index.js";

interface ReferenceFixture {
  schema_version: string;
  proposal: Record<string, unknown>;
  proposal_sha256: string;
  event_id: string;
  event: Record<string, unknown>;
  event_sha256: string;
  sse_sha256: string;
  action_receipt: Record<string, unknown>;
}

function fixture(): ReferenceFixture {
  return JSON.parse(
    readFileSync(join(process.cwd(), "test", "fixtures", "proof-bound-ag-ui-reference.json"), "utf8"),
  ) as ReferenceFixture;
}

function fixtureSse(reference: ReferenceFixture): string {
  return `id: ${reference.event_id}\ndata: ${canonicalJson(reference.event)}\n\n`;
}

test("Python and TypeScript share one proof-bound AG-UI golden vector", () => {
  const reference = fixture();
  assert.equal(reference.schema_version, "proof-bound-ag-ui-cross-language-reference.v1");

  const proposal = verifyProofBoundAguiProposal(reference.proposal, "run-golden-1");
  assert.equal(proposal.proposalSha256, reference.proposal_sha256);
  assert.equal(
    proposal.requestedActionSha256,
    proofBoundAguiRequestedActionSha256("steer", {
      episodeId: "episode-golden-1",
      eventId: "priority.changed",
    }),
  );
  assert.deepEqual(
    createProofBoundAguiProposal({
      proposalId: "proposal-golden-1",
      kind: "steer",
      runId: "run-golden-1",
      payload: { episodeId: "episode-golden-1", eventId: "priority.changed" },
    }),
    reference.proposal,
  );

  assert.equal(digestCanonical(verifyProofBoundAguiEvent(reference.event)), reference.event_sha256);
  const sse = fixtureSse(reference);
  assert.equal(sha256(sse), reference.sse_sha256);
  assert.deepEqual(parseProofBoundAguiSse(sse), [
    { id: reference.event_id, event: reference.event },
  ]);
  assert.deepEqual(
    verifyProofBoundAguiActionReceipt(reference.action_receipt, {
      runId: "run-golden-1",
      proposal: reference.proposal as unknown as ReturnType<typeof createProofBoundAguiProposal>,
      decision: "approved",
    }),
    reference.action_receipt,
  );
});

test("action receipts bind the exact proposal, human decision, and bounded local effect", () => {
  const reference = fixture();
  const forged = structuredClone(reference.action_receipt);
  forged["rationale"] = "Changed after the decision.";
  assert.throws(
    () =>
      verifyProofBoundAguiActionReceipt(forged, {
        runId: "run-golden-1",
        proposal: reference.proposal as unknown as ReturnType<typeof createProofBoundAguiProposal>,
      }),
    /ag_ui_action_receipt_digest_mismatch/,
  );
  const overclaim = structuredClone(reference.action_receipt);
  overclaim["externalEffectProved"] = true;
  assert.throws(
    () =>
      verifyProofBoundAguiActionReceipt(overclaim, {
        runId: "run-golden-1",
        proposal: reference.proposal as unknown as ReturnType<typeof createProofBoundAguiProposal>,
      }),
    /ag_ui_action_receipt_external_effect_overclaim/,
  );
});

test("proposal action identity cannot be changed beneath a valid transport digest", () => {
  const reference = fixture();
  const mutated = structuredClone(reference.proposal);
  const value = mutated["value"] as Record<string, unknown>;
  const payload = value["payload"] as Record<string, unknown>;
  payload["eventId"] = "priority.forged";
  value["contentSha256"] = digestCanonical({
    kind: value["kind"],
    payload,
    requested_action_sha256: value["requestedActionSha256"],
    run_id: value["runId"],
    thread_id: value["threadId"],
  });
  assert.throws(
    () => verifyProofBoundAguiProposal(mutated, "run-golden-1"),
    /ag_ui_proposal_action_digest_mismatch/,
  );
});

test("authority, root, reasoning, unknown fields, and duplicate event ids fail closed", () => {
  const reference = fixture();
  const proposal = structuredClone(reference.proposal);
  ((proposal["value"] as Record<string, unknown>)["payload"] as Record<string, unknown>)[
    "authorizationToken"
  ] = "forged";
  assert.throws(
    () => verifyProofBoundAguiProposal(proposal, "run-golden-1"),
    /ag_ui_proposal_forbidden_authority_field/,
  );

  const rootBearing = structuredClone(reference.event);
  (rootBearing["metadata"] as Record<string, unknown>)["worldRoot"] = "f".repeat(64);
  assert.throws(() => verifyProofBoundAguiEvent(rootBearing), /ag_ui_metadata_keys_invalid/);

  assert.throws(
    () => verifyProofBoundAguiEvent({ type: "REASONING_START" }),
    /ag_ui_reasoning_event_forbidden/,
  );
  assert.throws(
    () => verifyProofBoundAguiEvent({ ...reference.event, authority: "browser" }),
    /ag_ui_event_keys_invalid/,
  );

  const sse = fixtureSse(reference);
  assert.throws(() => parseProofBoundAguiSse(`${sse}${sse}`), /ag_ui_event_id_duplicate/);
});

test("fragmented live SSE is verified before the client receives each event", async () => {
  const reference = fixture();
  const sse = fixtureSse(reference);
  async function* chunks(): AsyncGenerator<Uint8Array> {
    const bytes = new TextEncoder().encode(sse);
    yield bytes.slice(0, 7);
    yield bytes.slice(7, 29);
    yield bytes.slice(29);
  }
  const seen = [];
  for await (const item of parseProofBoundAguiSseStream(chunks())) seen.push(item);
  assert.deepEqual(seen, [{ id: reference.event_id, event: reference.event }]);

  async function* duplicate(): AsyncGenerator<string> {
    yield sse;
    yield sse;
  }
  await assert.rejects(
    async () => {
      for await (const _item of parseProofBoundAguiSseStream(duplicate())) {
        // Consume until the duplicate is encountered.
      }
    },
    /ag_ui_event_id_duplicate/,
  );
});

test("the live verifier refuses an unbounded event before parsing its payload", async () => {
  async function* oversized(): AsyncGenerator<string> {
    yield `id: oversized\ndata: ${"x".repeat(1_048_576)}\n\n`;
  }
  await assert.rejects(
    async () => {
      for await (const _item of parseProofBoundAguiSseStream(oversized())) {
        // The frame is refused before it can be yielded.
      }
    },
    /ag_ui_sse_frame_too_large/,
  );
});
