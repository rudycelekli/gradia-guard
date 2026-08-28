import {
  GatewayRecorder,
  type GatewayAttempt,
  type GatewayPolicyDecisionInput,
} from "./gateway.js";
import type {
  GatewayActionFrame,
  GatewayProvider,
  GatewayUsage,
} from "./types.js";

export type NativeGatewayProvider = Exclude<GatewayProvider, `custom:${string}`>;

export interface PrepareProviderAttemptInput {
  provider: NativeGatewayProvider;
  requestBody: Uint8Array;
  requestMediaType: "application/json";
  requestedModelFromRoute: string | null;
  logicalRequestId: string;
  attemptNumber: number;
  retryOfOccurrenceSha256: string | null;
  policy: GatewayPolicyDecisionInput;
}

export interface PreparedProviderAttempt {
  provider: NativeGatewayProvider;
  requestedModel: string;
  attempt: GatewayAttempt;
}

export interface CompleteProviderAttemptInput {
  responseBody: Uint8Array;
  responseMediaType: string;
  httpStatus: number;
}

export function prepareProviderAttempt(
  recorder: GatewayRecorder,
  input: PrepareProviderAttemptInput,
): PreparedProviderAttempt {
  const requestedModel = requestedModelFromProviderRequest(
    input.provider,
    input.requestBody,
    input.requestedModelFromRoute,
  );
  const attempt = recorder.prepare({
    provider: input.provider,
    requestedModel,
    logicalRequestId: input.logicalRequestId,
    attemptNumber: input.attemptNumber,
    retryOfOccurrenceSha256: input.retryOfOccurrenceSha256,
    requestBody: input.requestBody,
    requestMediaType: input.requestMediaType,
    policy: input.policy,
  });
  return { provider: input.provider, requestedModel, attempt };
}

export function requestedModelFromProviderRequest(
  provider: NativeGatewayProvider,
  requestBody: Uint8Array,
  requestedModelFromRoute: string | null,
): string {
  const request = parseJsonObject(requestBody, "provider_request");
  const bodyModel = optionalString(request["model"]);
  if (provider === "gemini") {
    if (bodyModel !== null) throw new Error("gemini_request_model_must_come_from_route");
    if (!requestedModelFromRoute) throw new Error("gemini_requested_model_route_missing");
    return requestedModelFromRoute;
  }
  if (!bodyModel) throw new Error("provider_request_model_missing");
  if (requestedModelFromRoute !== null && requestedModelFromRoute !== bodyModel) {
    throw new Error("provider_request_model_route_mismatch");
  }
  return bodyModel;
}

export function completeProviderAttempt(
  prepared: PreparedProviderAttempt,
  input: CompleteProviderAttemptInput,
): GatewayActionFrame {
  if (input.httpStatus < 200 || input.httpStatus > 299) {
    return prepared.attempt.fail({
      outcome: "provider_failure",
      responseBody: input.responseBody,
      responseMediaType: input.responseMediaType,
      resolvedModel: null,
      usage: null,
      httpStatus: input.httpStatus,
      failureCode: `provider_http_${input.httpStatus}`,
    });
  }

  let parsed: { resolvedModel: string; usage: GatewayUsage };
  try {
    const response = parseJsonObject(input.responseBody, "provider_response");
    parsed = parseSuccessfulResponse(prepared.provider, response);
  } catch {
    return prepared.attempt.fail({
      outcome: "protocol_failure",
      responseBody: input.responseBody,
      responseMediaType: input.responseMediaType,
      resolvedModel: null,
      usage: null,
      httpStatus: input.httpStatus,
      failureCode: "provider_response_contract_invalid",
    });
  }
  return prepared.attempt.succeed({
    responseBody: input.responseBody,
    responseMediaType: input.responseMediaType,
    resolvedModel: parsed.resolvedModel,
    usage: parsed.usage,
    httpStatus: input.httpStatus,
  });
}

export function failProviderTransport(
  prepared: PreparedProviderAttempt,
  failureCode: string,
): GatewayActionFrame {
  return prepared.attempt.fail({
    outcome: "transport_failure",
    responseBody: null,
    responseMediaType: null,
    resolvedModel: null,
    usage: null,
    httpStatus: null,
    failureCode,
  });
}

function parseSuccessfulResponse(
  provider: NativeGatewayProvider,
  response: Record<string, unknown>,
): { resolvedModel: string; usage: GatewayUsage } {
  if (provider === "openai" || provider === "xai") {
    const usage = requiredObject(response["usage"], "provider_usage_missing");
    const inputTokens = requiredInteger(usage["input_tokens"], "provider_input_tokens_missing");
    const outputTokens = requiredInteger(usage["output_tokens"], "provider_output_tokens_missing");
    const details = optionalObject(usage["input_tokens_details"]);
    return {
      resolvedModel: requiredString(response["model"], "provider_resolved_model_missing"),
      usage: checkedUsage({
        input_tokens: inputTokens,
        output_tokens: outputTokens,
        cache_read_input_tokens: optionalInteger(details?.["cached_tokens"]),
        cache_write_input_tokens: null,
        provider_total_tokens: optionalInteger(usage["total_tokens"]),
      }),
    };
  }
  if (provider === "anthropic") {
    const usage = requiredObject(response["usage"], "provider_usage_missing");
    const topLevelCacheCreation = optionalInteger(usage["cache_creation_input_tokens"]);
    const granularCacheCreation = optionalObject(usage["cache_creation"]);
    const cacheCreation =
      topLevelCacheCreation ??
      sumOptionalIntegers([
        granularCacheCreation?.["ephemeral_5m_input_tokens"],
        granularCacheCreation?.["ephemeral_1h_input_tokens"],
      ]);
    return {
      resolvedModel: requiredString(response["model"], "provider_resolved_model_missing"),
      usage: checkedUsage({
        input_tokens: requiredInteger(usage["input_tokens"], "provider_input_tokens_missing"),
        output_tokens: requiredInteger(usage["output_tokens"], "provider_output_tokens_missing"),
        cache_read_input_tokens: optionalInteger(usage["cache_read_input_tokens"]),
        cache_write_input_tokens: cacheCreation,
        provider_total_tokens: null,
      }),
    };
  }

  const usage = requiredObject(response["usageMetadata"], "provider_usage_missing");
  const inputTokens = requiredInteger(usage["promptTokenCount"], "provider_input_tokens_missing");
  const totalTokens = optionalInteger(usage["totalTokenCount"]);
  const candidateTokens = optionalInteger(usage["candidatesTokenCount"]);
  const thoughtTokens = optionalInteger(usage["thoughtsTokenCount"]) ?? 0;
  let outputTokens: number;
  if (totalTokens !== null) outputTokens = totalTokens - inputTokens;
  else if (candidateTokens !== null) outputTokens = candidateTokens + thoughtTokens;
  else throw new Error("provider_output_tokens_missing");
  return {
    resolvedModel: requiredString(response["modelVersion"], "provider_resolved_model_missing"),
    usage: checkedUsage({
      input_tokens: inputTokens,
      output_tokens: outputTokens,
      cache_read_input_tokens: optionalInteger(usage["cachedContentTokenCount"]),
      cache_write_input_tokens: null,
      provider_total_tokens: totalTokens,
    }),
  };
}

function parseJsonObject(bytes: Uint8Array, label: string): Record<string, unknown> {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0) throw new Error(`${label}_missing`);
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    throw new Error(`${label}_invalid_json`);
  }
  return requiredObject(value, `${label}_not_object`);
}

function requiredObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(label);
  return value as Record<string, unknown>;
}

function optionalObject(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(label);
  return value;
}

function optionalString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function requiredInteger(value: unknown, label: string): number {
  const parsed = optionalInteger(value);
  if (parsed === null) throw new Error(label);
  return parsed;
}

function optionalInteger(value: unknown): number | null {
  return Number.isSafeInteger(value) && (value as number) >= 0 ? (value as number) : null;
}

function sumOptionalIntegers(values: readonly unknown[]): number | null {
  const present = values.map(optionalInteger).filter((value): value is number => value !== null);
  return present.length > 0 ? present.reduce((total, value) => total + value, 0) : null;
}

function checkedUsage(usage: GatewayUsage): GatewayUsage {
  if (usage.output_tokens < 0) throw new Error("provider_output_tokens_inconsistent");
  if (
    usage.provider_total_tokens !== null &&
    usage.provider_total_tokens < usage.input_tokens + usage.output_tokens
  ) {
    throw new Error("provider_total_tokens_inconsistent");
  }
  return usage;
}
