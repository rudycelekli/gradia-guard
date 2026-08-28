import { generateKeyPairSync } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { request as httpsRequest } from "node:https";
import {
  LocalHttpEgressDispatcher,
  createProviderCredentiallessGatewayServer,
  digestCanonical,
  issueWorkloadIdentity,
  sealHttpEgressConfiguration,
  sealPolicy,
  sha256,
  tokenReviewNonceSha256,
  verifyGatewayBundle,
  verifyWorkloadIdentity,
} from "/opt/guard/dist/src/index.js";

const capability = process.env.GRADIA_GUARD_LOCAL_CAPABILITY;
const runtimeId = process.env.GRADIA_GUARD_RUNTIME_ID ?? "docker-sdk-runtime-01";
const provider = process.env.GRADIA_GUARD_PROOF_PROVIDER;
if (!capability) throw new Error("container_gateway_capability_missing");

function projectedKubernetesIdentity() {
  const path = process.env.GRADIA_GUARD_KUBERNETES_TOKEN_PATH;
  if (!path) return null;
  const token = readFileSync(path, "utf8").trim();
  const parts = token.split(".");
  if (parts.length !== 3 || !parts[1]) throw new Error("kubernetes_projected_token_invalid");
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (
    audiences.length !== 1 ||
    audiences[0] !== "gradia-guard-workload-identity" ||
    typeof payload.sub !== "string" ||
    typeof payload.iat !== "number" ||
    typeof payload.exp !== "number" ||
    payload.exp - payload.iat > 600
  ) {
    throw new Error("kubernetes_projected_token_claims_invalid");
  }
  return {
    rawToken: token,
    observation: {
      token_sha256: sha256(Buffer.from(token)),
      subject: payload.sub,
      audiences,
      issued_at_unix: payload.iat,
      expires_at_unix: payload.exp,
      lifetime_seconds: payload.exp - payload.iat,
    },
  };
}

const kubernetesIdentity = projectedKubernetesIdentity();

const cases = {
  anthropic: {
    model: "claude-opus-5-20260801",
    targetUrl: "https://api.anthropic.example/v1/messages",
    response: () => ({
      id: "message-container-proof",
      type: "message",
      role: "assistant",
      model: "claude-opus-5-20260801",
      stop_reason: "end_turn",
      stop_sequence: null,
      usage: { input_tokens: 12, output_tokens: 7 },
      content: [{ type: "text", text: "ok" }],
    }),
  },
  gemini: {
    model: "gemini-4-pro",
    targetUrl: "https://generativelanguage.googleapis.example/v1beta/models/gemini-4-pro:generateContent",
    response: () => ({
      modelVersion: "gemini-4-pro",
      usageMetadata: { promptTokenCount: 12, candidatesTokenCount: 7, totalTokenCount: 19 },
      candidates: [{
        index: 0,
        finishReason: "STOP",
        content: { role: "model", parts: [{ text: "ok" }] },
      }],
    }),
  },
  openai: {
    model: "gpt-5.6-2026-08-01",
    targetUrl: "https://api.openai.example/v1/responses",
    response: (now) => responsesPayload("gpt-5.6-2026-08-01", now),
  },
  xai: {
    model: "grok-4.6",
    targetUrl: "https://api.x.ai.example/v1/responses",
    response: (now) => responsesPayload("grok-4.6", now),
  },
};
const selected = cases[provider];
if (!selected) throw new Error("container_gateway_provider_invalid");

function responsesPayload(model, now) {
  return {
    id: "response-container-proof",
    object: "response",
    created_at: now,
    status: "completed",
    model,
    usage: { input_tokens: 12, output_tokens: 7, total_tokens: 19 },
    output: [{
      id: "message-container-proof",
      type: "message",
      status: "completed",
      role: "assistant",
      content: [{ type: "output_text", text: "ok", annotations: [], logprobs: [] }],
    }],
  };
}

const policy = sealPolicy({
  schema_version: "gradia.guard.policy.v1",
  policy_id: `container-sdk-${provider}-policy`,
  policy_version: "v1",
  default_decision: "blocked",
  model_routes: [{
    provider,
    requested_model: selected.model,
    authority_scope_ids: ["model.invoke"],
    max_request_bytes: 10_000,
    max_attempt_number: 1,
  }],
  tool_routes: [],
});
const configuration = sealHttpEgressConfiguration({
  schema_version: "gradia.guard.local-http-egress-configuration.v1",
  configuration_id: `container-sdk-${provider}-egress`,
  configuration_version: "v1",
  default_decision: "blocked",
  model_routes: [{
    provider,
    target_url: selected.targetUrl,
    method: "POST",
    request_media_type: "application/json",
    redirect_mode: "error",
    timeout_ms: 5_000,
    max_response_bytes: 100_000,
  }],
});
const exchangeOrigin = process.env.GRADIA_GUARD_KUBERNETES_IDENTITY_EXCHANGE_ORIGIN;
const exchanged = Boolean(exchangeOrigin);
const claimsTemplate = {
  issuer_id: exchanged ? "gradia-kubernetes-tokenreview" : "gradia-managed",
  organization_id: exchanged ? "org-kubernetes-proof" : "org-container-proof",
  project_id: exchanged ? "project-kubernetes-proof" : "project-container-proof",
  workload_id: exchanged ? `agent-kubernetes-${provider}-proof` : `agent-container-${provider}-proof`,
  deployment_id: exchanged ? "deployment-kubernetes-proof" : "deployment-container-proof",
  audience: "guard-runtime",
  policy_sha256: policy.policy_sha256,
  image_sha256: process.env.GRADIA_GUARD_WORKLOAD_IMAGE_SHA256 ??
    digestCanonical({ image: "node-22-alpine-fixture" }),
  configuration_sha256: configuration.configuration_sha256,
  collector_sha256: digestCanonical({ collector: "container-sdk-route-v1", provider }),
  authority_scope_ids: ["model.invoke"],
};
const expectation = {
  issuerId: claimsTemplate.issuer_id,
  organizationId: claimsTemplate.organization_id,
  projectId: claimsTemplate.project_id,
  workloadId: claimsTemplate.workload_id,
  deploymentId: claimsTemplate.deployment_id,
  audience: claimsTemplate.audience,
  policySha256: claimsTemplate.policy_sha256,
  imageSha256: claimsTemplate.image_sha256,
  configurationSha256: claimsTemplate.configuration_sha256,
  collectorSha256: claimsTemplate.collector_sha256,
};

function postIdentityExchange(origin, ca, token) {
  const target = new URL("/v1/exchange", origin);
  const body = Buffer.from(JSON.stringify({ projected_service_account_token: token }));
  return new Promise((resolve, reject) => {
    const request = httpsRequest({
      hostname: target.hostname,
      port: Number(target.port || 443),
      path: target.pathname,
      method: "POST",
      ca,
      servername: target.hostname,
      headers: {
        "content-type": "application/json",
        "content-length": body.length,
      },
      timeout: 10_000,
    }, (response) => {
      const chunks = [];
      let length = 0;
      response.on("data", (chunk) => {
        length += chunk.length;
        if (length > 256_000) response.destroy(new Error("kubernetes_identity_exchange_response_too_large"));
        else chunks.push(chunk);
      });
      response.on("end", () => {
        if (response.statusCode !== 200) {
          reject(new Error(`kubernetes_identity_exchange_http_${response.statusCode ?? 0}`));
          return;
        }
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
        } catch {
          reject(new Error("kubernetes_identity_exchange_response_invalid"));
        }
      });
    });
    request.once("timeout", () => request.destroy(new Error("kubernetes_identity_exchange_timeout")));
    request.once("error", reject);
    request.end(body);
  });
}

let identity;
let trustedPublicKeys;
let identityExchange = null;
if (exchangeOrigin) {
  if (!kubernetesIdentity) throw new Error("kubernetes_identity_exchange_token_missing");
  const caPath = process.env.GRADIA_GUARD_KUBERNETES_IDENTITY_EXCHANGE_CA_PATH;
  const publicKeyPath = process.env.GRADIA_GUARD_ISSUER_PUBLIC_KEY_PATH;
  if (!caPath || !publicKeyPath) throw new Error("kubernetes_identity_exchange_trust_missing");
  identityExchange = await postIdentityExchange(
    exchangeOrigin,
    readFileSync(caPath),
    kubernetesIdentity.rawToken,
  );
  if (
    !identityExchange ||
    identityExchange.schema_version !== "gradia.guard.kubernetes-tokenreview-exchange-response.v1" ||
    !identityExchange.token_review ||
    !identityExchange.guard_workload_identity ||
    identityExchange.token_review.token_sha256 !== kubernetesIdentity.observation.token_sha256
  ) {
    throw new Error("kubernetes_identity_exchange_binding_invalid");
  }
  identity = identityExchange.guard_workload_identity;
  trustedPublicKeys = {
    "kubernetes-tokenreview-issuer-v1": readFileSync(publicKeyPath, "utf8"),
  };
  if (
    identity.claims.nonce_sha256 !==
      tokenReviewNonceSha256(runtimeId, identityExchange.token_review)
  ) {
    throw new Error("kubernetes_identity_exchange_nonce_invalid");
  }
} else {
  const now = Math.floor(Date.now() / 1000);
  const keys = generateKeyPairSync("ed25519");
  identity = issueWorkloadIdentity({
    ...claimsTemplate,
    issued_at_unix: now,
    not_before_unix: now,
    expires_at_unix: now + 3_600,
    nonce_sha256: digestCanonical({ runtime_id: runtimeId, nonce: "container-sdk-proof", provider }),
  }, "issuer-key-v1", keys.privateKey);
  trustedPublicKeys = { "issuer-key-v1": keys.publicKey };
}
const verificationNow = identity.claims.issued_at_unix;
const maxIdentityLifetimeSeconds = exchanged ? 300 : 3_600;
const verifiedIdentity = verifyWorkloadIdentity(identity, {
  trustedPublicKeys,
  expectation: { ...expectation, requiredAuthorityScopeIds: claimsTemplate.authority_scope_ids },
  nowUnix: verificationNow,
  maxLifetimeSeconds: maxIdentityLifetimeSeconds,
  clockSkewSeconds: 0,
});

const gatewayDirectory = "/tmp/model-gateway";
const dispatcher = new LocalHttpEgressDispatcher({
  directory: gatewayDirectory,
  policy,
  configuration,
  workloadIdentity: identity,
  trustedPublicKeys,
  workloadExpectation: expectation,
  maxIdentityLifetimeSeconds,
  nowUnix: exchanged ? () => Math.floor(Date.now() / 1_000) : () => verificationNow,
  transport: async (input) => {
    if (
      input.provider !== provider ||
      input.requestedModel !== selected.model ||
      input.targetUrl !== selected.targetUrl
    ) {
      throw new Error("container_gateway_transport_binding_mismatch");
    }
    return {
      responseBody: Buffer.from(JSON.stringify(selected.response(verificationNow))),
      responseMediaType: "application/json",
      httpStatus: 200,
      finalUrl: selected.targetUrl,
      redirected: false,
    };
  },
});
const counters = { accepted: 0, explicitEnvelope: 0, nativeProvider: 0, unauthorized: 0, malformed: 0 };
const server = createProviderCredentiallessGatewayServer(
  dispatcher,
  capability,
  counters,
  policy,
  configuration,
  runtimeId,
  claimsTemplate.authority_scope_ids,
);

function writeStatus(finalized, gatewayVerification = null) {
  writeFileSync("/tmp/guard-status.json", `${JSON.stringify({
    runtime_id: runtimeId,
    provider,
    policy_sha256: policy.policy_sha256,
    configuration_sha256: configuration.configuration_sha256,
    workload_identity_sha256: verifiedIdentity.identitySha256,
    local_capability_sha256: sha256(Buffer.from(capability)),
    kubernetes_projected_identity: kubernetesIdentity?.observation ?? null,
    kubernetes_identity_exchange: identityExchange,
    accepted_local_requests: counters.accepted,
    native_provider_requests: counters.nativeProvider,
    unauthorized_local_requests: counters.unauthorized,
    malformed_local_requests: counters.malformed,
    finalized,
    gateway_verification: gatewayVerification,
  })}\n`, { mode: 0o600 });
}

let finalized = false;
const finalizer = setInterval(() => {
  if (finalized || counters.accepted !== 1) return;
  finalized = true;
  dispatcher.finalize();
  writeStatus(true, verifyGatewayBundle(gatewayDirectory));
}, 10);
finalizer.unref();

server.listen(8787, "0.0.0.0", () => writeStatus(false));

for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => {
    if (!finalized && counters.accepted > 0) dispatcher.finalize();
    server.close(() => process.exit(0));
  });
}
