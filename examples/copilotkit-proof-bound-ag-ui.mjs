/**
 * Minimal server-side bridge for a CopilotKit/AG-UI client.
 *
 * CopilotKit may render these verified events and collect a human decision.
 * It never receives Gradia credentials in browser code, never dispatches a
 * Universe tool directly, and never mints an approval, world root, or receipt.
 */
import {
  createProofBoundAguiProposal,
  parseProofBoundAguiSseStream,
  verifyProofBoundAguiActionReceipt,
} from "@gradia/guard";

function authorization(token) {
  if (typeof token !== "string" || token.length < 1) throw new Error("gradia_token_required");
  return { Authorization: `Bearer ${token}` };
}

export async function* verifiedUniverseEvents({ apiBaseUrl, token, runId, lastEventId }) {
  const headers = {
    ...authorization(token),
    Accept: "text/event-stream",
    ...(lastEventId === undefined ? {} : { "Last-Event-ID": lastEventId }),
  };
  const response = await fetch(
    `${apiBaseUrl}/v1/runs/${encodeURIComponent(runId)}/interop/ag-ui/stream?projection=agent`,
    { headers },
  );
  if (!response.ok || response.body === null) {
    throw new Error(`gradia_ag_ui_stream_refused:${response.status}`);
  }
  for await (const event of parseProofBoundAguiSseStream(response.body)) yield event;
}

export async function decideFrozenSteeringProposal({
  apiBaseUrl,
  token,
  runId,
  episodeId,
  eventId,
  proposalId,
  decision,
  rationale,
  idempotencyKey,
}) {
  const proposal = createProofBoundAguiProposal({
    proposalId,
    kind: "steer",
    runId,
    payload: { episodeId, eventId },
  });
  const response = await fetch(
    `${apiBaseUrl}/v1/runs/${encodeURIComponent(runId)}/interop/ag-ui/actions`,
    {
      method: "POST",
      headers: {
        ...authorization(token),
        "Content-Type": "application/json",
        "Idempotency-Key": idempotencyKey,
      },
      body: JSON.stringify({ proposal, decision, rationale }),
    },
  );
  if (!response.ok) throw new Error(`gradia_ag_ui_action_refused:${response.status}`);
  const receipt = await response.json();
  return verifyProofBoundAguiActionReceipt(receipt, { runId, proposal, decision });
}
