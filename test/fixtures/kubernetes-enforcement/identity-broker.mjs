import { request as httpsRequest, createServer } from "node:https";
import { readFileSync, writeFileSync } from "node:fs";
import {
  issueWorkloadIdentity,
  sha256,
  tokenReviewNonceSha256,
} from "/opt/guard/dist/src/index.js";

const required = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`identity_broker_environment_missing:${name}`);
  return value;
};

const runtimeId = required("GRADIA_GUARD_RUNTIME_ID");
const keyId = "kubernetes-tokenreview-issuer-v1";
const issuerPrivateKey = readFileSync(required("GRADIA_GUARD_ISSUER_PRIVATE_KEY_PATH"), "utf8");
const reviewerTokenPath = required("GRADIA_GUARD_REVIEWER_TOKEN_PATH");
const kubernetesCa = readFileSync(required("GRADIA_GUARD_KUBERNETES_CA_PATH"));
const tlsKey = readFileSync(required("GRADIA_GUARD_BROKER_TLS_KEY_PATH"));
const tlsCertificate = readFileSync(required("GRADIA_GUARD_BROKER_TLS_CERT_PATH"));
const apiHost = required("KUBERNETES_SERVICE_HOST");
const apiPort = Number(required("KUBERNETES_SERVICE_PORT_HTTPS"));
const expected = Object.freeze({
  issuer_id: "gradia-kubernetes-tokenreview",
  organization_id: "org-kubernetes-proof",
  project_id: "project-kubernetes-proof",
  workload_id: "agent-kubernetes-openai-proof",
  deployment_id: "deployment-kubernetes-proof",
  audience: "guard-runtime",
  policy_sha256: required("GRADIA_GUARD_EXPECTED_POLICY_SHA256"),
  image_sha256: required("GRADIA_GUARD_EXPECTED_IMAGE_SHA256"),
  configuration_sha256: required("GRADIA_GUARD_EXPECTED_CONFIGURATION_SHA256"),
  collector_sha256: required("GRADIA_GUARD_EXPECTED_COLLECTOR_SHA256"),
  authority_scope_ids: ["model.invoke"],
});
const expectedServiceAccountUidSha256 = required(
  "GRADIA_GUARD_EXPECTED_SERVICE_ACCOUNT_UID_SHA256",
);
const usedTokenDigests = new Set();
const status = { accepted_exchanges: 0, replay_rejections: 0, last_exchange: null };

function writeStatus() {
  writeFileSync("/tmp/broker-status.json", `${JSON.stringify(status)}\n`, { mode: 0o600 });
}

function exactObject(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label}_shape_invalid`);
  }
  const actual = Object.keys(value).sort();
  const expectedKeys = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expectedKeys)) {
    throw new Error(`${label}_keys_invalid`);
  }
  return value;
}

function decodeAuthenticatedToken(token) {
  const parts = token.split(".");
  if (parts.length !== 3 || !parts[1]) throw new Error("identity_broker_token_invalid");
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (
    JSON.stringify(audiences) !== JSON.stringify(["gradia-guard-workload-identity"]) ||
    payload.sub !== "system:serviceaccount:gradia-guard:gradia-guard-gateway" ||
    !Number.isSafeInteger(payload.iat) ||
    !Number.isSafeInteger(payload.exp) ||
    payload.exp - payload.iat !== 600
  ) {
    throw new Error("identity_broker_token_claims_invalid");
  }
  return payload;
}

function postTokenReview(token) {
  const reviewerToken = readFileSync(reviewerTokenPath, "utf8").trim();
  const requestBody = Buffer.from(JSON.stringify({
    apiVersion: "authentication.k8s.io/v1",
    kind: "TokenReview",
    spec: {
      token,
      audiences: ["gradia-guard-workload-identity"],
    },
  }));
  return new Promise((resolve, reject) => {
    const request = httpsRequest({
      hostname: apiHost,
      port: apiPort,
      path: "/apis/authentication.k8s.io/v1/tokenreviews",
      method: "POST",
      ca: kubernetesCa,
      headers: {
        authorization: `Bearer ${reviewerToken}`,
        "content-type": "application/json",
        "content-length": requestBody.length,
      },
      timeout: 3_000,
    }, (response) => {
      const chunks = [];
      let length = 0;
      response.on("data", (chunk) => {
        length += chunk.length;
        if (length > 128_000) {
          response.destroy(new Error("identity_broker_tokenreview_response_too_large"));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => {
        if (response.statusCode !== 201) {
          reject(new Error(`identity_broker_tokenreview_http_${response.statusCode ?? 0}`));
          return;
        }
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
        } catch {
          reject(new Error("identity_broker_tokenreview_json_invalid"));
        }
      });
    });
    request.once("timeout", () => request.destroy(new Error("identity_broker_tokenreview_timeout")));
    request.once("error", reject);
    request.end(requestBody);
  });
}

function oneExtra(extra, name) {
  const value = extra?.[name];
  if (!Array.isArray(value) || value.length !== 1 || typeof value[0] !== "string") {
    throw new Error(`identity_broker_tokenreview_extra_invalid:${name}`);
  }
  return value[0];
}

async function exchange(token) {
  const tokenSha256 = sha256(Buffer.from(token));
  if (usedTokenDigests.has(tokenSha256)) {
    status.replay_rejections += 1;
    writeStatus();
    return { statusCode: 409, body: { error: "identity_broker_token_replay_rejected" } };
  }
  usedTokenDigests.add(tokenSha256);
  let review;
  try {
    review = await postTokenReview(token);
  } catch (error) {
    usedTokenDigests.delete(tokenSha256);
    throw error;
  }
  const reviewStatus = review?.status;
  const user = reviewStatus?.user;
  const groups = Array.isArray(user?.groups) ? [...user.groups].sort() : [];
  const returnedAudiences = Array.isArray(reviewStatus?.audiences)
    ? [...reviewStatus.audiences].sort()
    : [];
  if (
    review?.apiVersion !== "authentication.k8s.io/v1" ||
    review?.kind !== "TokenReview" ||
    reviewStatus?.authenticated !== true ||
    user?.username !== "system:serviceaccount:gradia-guard:gradia-guard-gateway" ||
    typeof user?.uid !== "string" ||
    sha256(Buffer.from(user.uid)) !== expectedServiceAccountUidSha256 ||
    JSON.stringify(groups) !== JSON.stringify([
      "system:authenticated",
      "system:serviceaccounts",
      "system:serviceaccounts:gradia-guard",
    ]) ||
    JSON.stringify(returnedAudiences) !== JSON.stringify(["gradia-guard-workload-identity"])
  ) {
    throw new Error("identity_broker_tokenreview_result_invalid");
  }
  const payload = decodeAuthenticatedToken(token);
  const observation = {
    api_version: "authentication.k8s.io/v1",
    authenticated: true,
    token_sha256: tokenSha256,
    requested_audiences: ["gradia-guard-workload-identity"],
    returned_audiences: returnedAudiences,
    username: user.username,
    user_uid_sha256: sha256(Buffer.from(user.uid)),
    credential_id_sha256: sha256(Buffer.from(oneExtra(
      user.extra,
      "authentication.kubernetes.io/credential-id",
    ))),
    groups,
    pod_name_sha256: sha256(Buffer.from(oneExtra(
      user.extra,
      "authentication.kubernetes.io/pod-name",
    ))),
    pod_uid_sha256: sha256(Buffer.from(oneExtra(
      user.extra,
      "authentication.kubernetes.io/pod-uid",
    ))),
    issued_at_unix: payload.iat,
    expires_at_unix: payload.exp,
    lifetime_seconds: payload.exp - payload.iat,
  };
  const now = Math.floor(Date.now() / 1_000);
  if (now < payload.iat || now >= payload.exp) throw new Error("identity_broker_token_time_invalid");
  const expires = Math.min(now + 300, payload.exp);
  if (expires <= now) throw new Error("identity_broker_identity_lifetime_invalid");
  const identity = issueWorkloadIdentity({
    ...expected,
    issued_at_unix: now,
    not_before_unix: now,
    expires_at_unix: expires,
    nonce_sha256: tokenReviewNonceSha256(runtimeId, observation),
  }, keyId, issuerPrivateKey);
  status.accepted_exchanges += 1;
  status.last_exchange = {
    token_review: observation,
    workload_identity_sha256: identity.identity_sha256,
  };
  writeStatus();
  return {
    statusCode: 200,
    body: {
      schema_version: "gradia.guard.kubernetes-tokenreview-exchange-response.v1",
      token_review: observation,
      guard_workload_identity: identity,
    },
  };
}

const server = createServer({ key: tlsKey, cert: tlsCertificate }, async (request, response) => {
  if (request.method === "GET" && request.url === "/health") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end('{"ok":true}\n');
    return;
  }
  if (request.method !== "POST" || request.url !== "/v1/exchange") {
    response.writeHead(404, { "content-type": "application/json" });
    response.end('{"error":"not_found"}\n');
    return;
  }
  const chunks = [];
  let length = 0;
  request.on("data", (chunk) => {
    length += chunk.length;
    if (length > 64_000) request.destroy(new Error("identity_broker_request_too_large"));
    else chunks.push(chunk);
  });
  request.on("end", async () => {
    try {
      const body = exactObject(
        JSON.parse(Buffer.concat(chunks).toString("utf8")),
        ["projected_service_account_token"],
        "identity_broker_exchange_request",
      );
      if (typeof body.projected_service_account_token !== "string") {
        throw new Error("identity_broker_exchange_token_invalid");
      }
      const result = await exchange(body.projected_service_account_token);
      response.writeHead(result.statusCode, { "content-type": "application/json" });
      response.end(`${JSON.stringify(result.body)}\n`);
    } catch (error) {
      status.last_error = error instanceof Error ? error.message : "exchange_failed";
      writeStatus();
      response.writeHead(401, { "content-type": "application/json" });
      response.end(`${JSON.stringify({ error: error instanceof Error ? error.message : "exchange_failed" })}\n`);
    }
  });
});

writeStatus();
server.listen(9443, "0.0.0.0");
