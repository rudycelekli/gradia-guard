import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { digestCanonical } from "../src/canonical.js";
import { GatewayIdentityMismatchError, GatewayRecorder } from "../src/gateway.js";
import {
  completeProviderAttempt,
  failProviderTransport,
  prepareProviderAttempt,
  type NativeGatewayProvider,
} from "../src/provider-adapters.js";
import { verifyGatewayBundle } from "../src/gateway-verify.js";

const encoder = new TextEncoder();

function directory(label: string): string {
  return join(mkdtempSync(join(tmpdir(), "gradia-provider-adapter-")), label);
}

function policy(provider: NativeGatewayProvider, model: string) {
  return {
    decision: "allowed" as const,
    censorKind: null,
    reasonCodes: ["policy_allowed"],
    policySha256: digestCanonical({ provider, model, rule: "fixture" }),
  };
}

function prepare(
  recorder: GatewayRecorder,
  provider: NativeGatewayProvider,
  model: string,
  body: Record<string, unknown>,
) {
  const prepared = prepareProviderAttempt(recorder, {
    provider,
    requestBody: encoder.encode(JSON.stringify(body)),
    requestMediaType: "application/json",
    requestedModelFromRoute: provider === "gemini" ? model : null,
    logicalRequestId: `${provider}-request-1`,
    attemptNumber: 1,
    retryOfOccurrenceSha256: null,
    policy: policy(provider, model),
  });
  prepared.attempt.markDispatched();
  return prepared;
}

test("native provider adapters map four wire shapes into one exact G1 ABI", () => {
  const fixtures: Array<{
    provider: NativeGatewayProvider;
    model: string;
    request: Record<string, unknown>;
    response: Record<string, unknown>;
    expectedInput: number;
    expectedOutput: number;
    expectedCacheRead: number | null;
  }> = [
    {
      provider: "openai",
      model: "gpt-5.6-2026-08-01",
      request: { model: "gpt-5.6-2026-08-01", input: "hello" },
      response: {
        id: "resp_1",
        model: "gpt-5.6-2026-08-01",
        usage: { input_tokens: 11, output_tokens: 7, total_tokens: 18, input_tokens_details: { cached_tokens: 3 } },
      },
      expectedInput: 11,
      expectedOutput: 7,
      expectedCacheRead: 3,
    },
    {
      provider: "xai",
      model: "grok-4.6",
      request: { model: "grok-4.6", input: "hello" },
      response: { id: "resp_2", model: "grok-4.6", usage: { input_tokens: 13, output_tokens: 5, total_tokens: 18 } },
      expectedInput: 13,
      expectedOutput: 5,
      expectedCacheRead: null,
    },
    {
      provider: "anthropic",
      model: "claude-opus-5-20260801",
      request: { model: "claude-opus-5-20260801", messages: [] },
      response: {
        id: "msg_1",
        model: "claude-opus-5-20260801",
        usage: { input_tokens: 17, output_tokens: 9, cache_read_input_tokens: 4, cache_creation_input_tokens: 2 },
      },
      expectedInput: 17,
      expectedOutput: 9,
      expectedCacheRead: 4,
    },
    {
      provider: "gemini",
      model: "gemini-3.1-pro-preview",
      request: { contents: [{ role: "user", parts: [{ text: "hello" }] }] },
      response: {
        responseId: "gem_1",
        modelVersion: "gemini-3.1-pro-preview",
        usageMetadata: { promptTokenCount: 19, candidatesTokenCount: 6, thoughtsTokenCount: 8, totalTokenCount: 33, cachedContentTokenCount: 2 },
      },
      expectedInput: 19,
      expectedOutput: 14,
      expectedCacheRead: 2,
    },
  ];

  for (const fixture of fixtures) {
    const recorder = new GatewayRecorder({ directory: directory(fixture.provider) });
    const prepared = prepare(recorder, fixture.provider, fixture.model, fixture.request);
    const frame = completeProviderAttempt(prepared, {
      responseBody: encoder.encode(JSON.stringify(fixture.response)),
      responseMediaType: "application/json",
      httpStatus: 200,
    });
    assert.equal(frame.outcome, "success");
    assert.equal(frame.resolved_model, fixture.model);
    assert.equal(frame.usage?.input_tokens, fixture.expectedInput);
    assert.equal(frame.usage?.output_tokens, fixture.expectedOutput);
    assert.equal(frame.usage?.cache_read_input_tokens, fixture.expectedCacheRead);
    recorder.finalize();
    assert.deepEqual(verifyGatewayBundle(recorder.directory).blockers, []);
    const raw = readFileSync(join(recorder.directory, "frames.ndjson"), "utf8");
    assert.doesNotMatch(raw, /hello/);
  }
});

test("malformed success is recorded as protocol failure, not model output", () => {
  const recorder = new GatewayRecorder({ directory: directory("protocol") });
  const prepared = prepare(recorder, "openai", "gpt-5.6-2026-08-01", {
    model: "gpt-5.6-2026-08-01",
  });
  const frame = completeProviderAttempt(prepared, {
    responseBody: encoder.encode(JSON.stringify({ model: "gpt-5.6-2026-08-01" })),
    responseMediaType: "application/json",
    httpStatus: 200,
  });
  assert.equal(frame.outcome, "protocol_failure");
  assert.equal(frame.failure_code, "provider_response_contract_invalid");
  recorder.finalize();
  assert.equal(verifyGatewayBundle(recorder.directory).ok, true);
});

test("provider, transport, and identity failures remain distinct", () => {
  const providerRecorder = new GatewayRecorder({ directory: directory("provider") });
  const providerAttempt = prepare(providerRecorder, "anthropic", "claude-opus-5-20260801", {
    model: "claude-opus-5-20260801",
  });
  assert.equal(
    completeProviderAttempt(providerAttempt, {
      responseBody: encoder.encode(JSON.stringify({ type: "error" })),
      responseMediaType: "application/json",
      httpStatus: 529,
    }).outcome,
    "provider_failure",
  );
  providerRecorder.finalize();

  const transportRecorder = new GatewayRecorder({ directory: directory("transport") });
  const transportAttempt = prepare(transportRecorder, "xai", "grok-4.6", { model: "grok-4.6" });
  assert.equal(failProviderTransport(transportAttempt, "read_timeout").outcome, "transport_failure");
  transportRecorder.finalize();

  const identityRecorder = new GatewayRecorder({ directory: directory("identity") });
  const identityAttempt = prepare(identityRecorder, "openai", "gpt-5.6-2026-08-01", {
    model: "gpt-5.6-2026-08-01",
  });
  assert.throws(
    () =>
      completeProviderAttempt(identityAttempt, {
        responseBody: encoder.encode(
          JSON.stringify({ model: "gpt-5.5-2026-06-01", usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 } }),
        ),
        responseMediaType: "application/json",
        httpStatus: 200,
      }),
    GatewayIdentityMismatchError,
  );
  identityRecorder.finalize();
  assert.equal(verifyGatewayBundle(identityRecorder.directory).ok, false);
});

test("Gemini takes model identity only from the route and all others bind the body", () => {
  const gemini = new GatewayRecorder({ directory: directory("gemini-route") });
  assert.throws(
    () =>
      prepareProviderAttempt(gemini, {
        provider: "gemini",
        requestBody: encoder.encode(JSON.stringify({ model: "gemini-3.1-pro-preview" })),
        requestMediaType: "application/json",
        requestedModelFromRoute: "gemini-3.1-pro-preview",
        logicalRequestId: "gemini-request",
        attemptNumber: 1,
        retryOfOccurrenceSha256: null,
        policy: policy("gemini", "gemini-3.1-pro-preview"),
      }),
    /gemini_request_model_must_come_from_route/,
  );

  const openai = new GatewayRecorder({ directory: directory("openai-route") });
  assert.throws(
    () =>
      prepareProviderAttempt(openai, {
        provider: "openai",
        requestBody: encoder.encode(JSON.stringify({ model: "gpt-5.6-2026-08-01" })),
        requestMediaType: "application/json",
        requestedModelFromRoute: "gpt-5.5-2026-06-01",
        logicalRequestId: "openai-request",
        attemptNumber: 1,
        retryOfOccurrenceSha256: null,
        policy: policy("openai", "gpt-5.6-2026-08-01"),
      }),
    /provider_request_model_route_mismatch/,
  );
});

test("Anthropic cache creation totals are not double counted", () => {
  const recorder = new GatewayRecorder({ directory: directory("anthropic-cache") });
  const prepared = prepare(recorder, "anthropic", "claude-opus-5-20260801", {
    model: "claude-opus-5-20260801",
  });
  const frame = completeProviderAttempt(prepared, {
    responseBody: encoder.encode(
      JSON.stringify({
        model: "claude-opus-5-20260801",
        usage: {
          input_tokens: 17,
          output_tokens: 9,
          cache_creation_input_tokens: 7,
          cache_creation: {
            ephemeral_5m_input_tokens: 2,
            ephemeral_1h_input_tokens: 5,
          },
        },
      }),
    ),
    responseMediaType: "application/json",
    httpStatus: 200,
  });
  assert.equal(frame.usage?.cache_write_input_tokens, 7);
  recorder.finalize();
  assert.equal(verifyGatewayBundle(recorder.directory).ok, true);
});
