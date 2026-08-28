import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  createNoRedirectFetchTransport,
  enforcementBoundary,
  issueWorkloadIdentity,
  LocalHttpEgressDispatcher,
  sealHttpEgressConfiguration,
  sealPolicy,
  verifyEnforcementBoundary,
  verifyGatewayBundle,
  type GuardHttpEgressConfiguration,
  type GuardHttpEgressTransport,
  type GuardPolicy,
  type GuardPolicyBody,
  type GuardWorkloadIdentity,
  type GuardWorkloadIdentityClaims,
} from "../src/index.js";
import { canonicalJson, digestCanonical } from "../src/canonical.js";

const keys = generateKeyPairSync("ed25519");
const foreignKeys = generateKeyPairSync("ed25519");
const now = 1_787_549_400;
const model = "gpt-5.6-2026-08-01";
const targetUrl = "https://api.openai.example/v1/responses";
const interfaceSha256 = digestCanonical({ tool: "case.read", version: "v1" });

function policyBody(): GuardPolicyBody {
  return {
    schema_version: "gradia.guard.policy.v1",
    policy_id: "enforced-egress-policy",
    policy_version: "v1",
    default_decision: "blocked",
    model_routes: [
      {
        provider: "openai",
        requested_model: model,
        authority_scope_ids: ["model.invoke"],
        max_request_bytes: 10_000,
        max_attempt_number: 2,
      },
    ],
    tool_routes: [
      {
        registry_id: "case-tools",
        tool_id: "case.read",
        tool_version: "v1",
        interface_sha256: interfaceSha256,
        authority_scope_ids: ["case.read"],
        max_request_bytes: 10_000,
        max_attempt_number: 2,
      },
    ],
  };
}

function configuration(): GuardHttpEgressConfiguration {
  return sealHttpEgressConfiguration({
    schema_version: "gradia.guard.local-http-egress-configuration.v1",
    configuration_id: "local-model-egress",
    configuration_version: "v1",
    default_decision: "blocked",
    model_routes: [
      {
        provider: "openai",
        target_url: targetUrl,
        method: "POST",
        request_media_type: "application/json",
        redirect_mode: "error",
        timeout_ms: 5_000,
        max_response_bytes: 100_000,
      },
    ],
  });
}

function claims(policy: GuardPolicy, config: GuardHttpEgressConfiguration): GuardWorkloadIdentityClaims {
  return {
    issuer_id: "gradia-managed",
    organization_id: "org-1",
    project_id: "project-1",
    workload_id: "agent-1",
    deployment_id: "deployment-1",
    audience: "guard-egress",
    policy_sha256: policy.policy_sha256,
    image_sha256: digestCanonical({ image: "v1" }),
    configuration_sha256: config.configuration_sha256,
    collector_sha256: digestCanonical({ collector: "v1" }),
    authority_scope_ids: ["case.read", "model.invoke"],
    issued_at_unix: now,
    not_before_unix: now,
    expires_at_unix: now + 300,
    nonce_sha256: digestCanonical({ nonce: "http-egress" }),
  };
}

function responseBody(resolvedModel = model): Uint8Array {
  return Buffer.from(
    JSON.stringify({
      id: "response-1",
      model: resolvedModel,
      usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 },
      output: [],
    }),
  );
}

function requestBody(): Uint8Array {
  return Buffer.from(JSON.stringify({ model, input: "secret customer case" }));
}

function bundleDirectory(label = "gradia-http-egress-"): string {
  return join(mkdtempSync(join(tmpdir(), label)), "bundle");
}

function makeDispatcher(
  directory: string,
  transport: GuardHttpEgressTransport,
  overrides: {
    policy?: GuardPolicy;
    configuration?: GuardHttpEgressConfiguration;
    identity?: GuardWorkloadIdentity;
  } = {},
): LocalHttpEgressDispatcher {
  const policy = overrides.policy ?? sealPolicy(policyBody());
  const config = overrides.configuration ?? configuration();
  const source = claims(policy, config);
  const identity =
    overrides.identity ?? issueWorkloadIdentity(source, "issuer-key-v1", keys.privateKey);
  return new LocalHttpEgressDispatcher({
    directory,
    policy,
    configuration: config,
    workloadIdentity: identity,
    trustedPublicKeys: { "issuer-key-v1": keys.publicKey },
    workloadExpectation: {
      issuerId: source.issuer_id,
      organizationId: source.organization_id,
      projectId: source.project_id,
      workloadId: source.workload_id,
      deploymentId: source.deployment_id,
      audience: source.audience,
      policySha256: source.policy_sha256,
      imageSha256: source.image_sha256,
      configurationSha256: source.configuration_sha256,
      collectorSha256: source.collector_sha256,
    },
    maxIdentityLifetimeSeconds: 600,
    nowUnix: () => now + 1,
    transport,
  });
}

const request = {
  provider: "openai" as const,
  targetUrl,
  requestBody: requestBody(),
  requestMediaType: "application/json" as const,
  requestedModelFromRoute: null,
  logicalRequestId: "request-1",
  attemptNumber: 1,
  retryOfOccurrenceSha256: null,
  authorityScopeIds: ["model.invoke"],
};

test("covered HTTP dispatch verifies signed identity, configuration, and policy before upstream", async () => {
  const directory = bundleDirectory();
  let dispatches = 0;
  const dispatcher = makeDispatcher(directory, async (input) => {
    dispatches += 1;
    assert.equal(input.targetUrl, targetUrl);
    assert.equal(input.requestedModel, model);
    return {
      responseBody: responseBody(),
      responseMediaType: "application/json",
      httpStatus: 200,
      finalUrl: targetUrl,
      redirected: false,
    };
  });
  const result = await dispatcher.dispatch(request);
  dispatcher.finalize();
  assert.equal(dispatches, 1);
  assert.equal(result.disposition, "completed");
  assert.equal(result.action?.outcome, "success");
  assert.equal(result.boundary.bypass_possible, true);
  assert.equal(result.boundary.full_host_enforcement, false);
  assert.doesNotThrow(() => verifyEnforcementBoundary(result.boundary));
  assert.deepEqual(verifyGatewayBundle(directory).blockers, []);
  const evidence = readFileSync(join(directory, "frames.ndjson"), "utf8");
  assert.match(evidence, new RegExp(result.boundary.boundary_sha256));
  assert.doesNotMatch(evidence, /secret customer case/);
});

test("unlisted target, host suffix confusion, and query confusion deny without upstream calls", async () => {
  for (const confusedTarget of [
    "https://api.openai.example.evil.test/v1/responses",
    "https://api.openai.example/v1/responses?redirect=https://evil.test/",
    "https://evil.test/v1/responses",
  ]) {
    const directory = bundleDirectory("gradia-http-deny-");
    let dispatches = 0;
    const dispatcher = makeDispatcher(directory, async () => {
      dispatches += 1;
      throw new Error("must not dispatch");
    });
    const result = await dispatcher.dispatch({
      ...request,
      logicalRequestId: `deny-${dispatches}-${confusedTarget.length}`,
      targetUrl: confusedTarget,
    });
    dispatcher.finalize();
    assert.equal(dispatches, 0);
    assert.equal(result.disposition, "blocked");
    assert.deepEqual(verifyGatewayBundle(directory).blockers, []);
  }
});

test("tampered or policy-mismatched workload identity denies before upstream", async () => {
  const policy = sealPolicy(policyBody());
  const config = configuration();
  const source = claims(policy, config);
  const identity = issueWorkloadIdentity(source, "issuer-key-v1", keys.privateKey);
  const tampered = JSON.parse(canonicalJson(identity)) as GuardWorkloadIdentity;
  tampered.claims.workload_id = "agent-2";
  let dispatches = 0;
  const directory = bundleDirectory("gradia-http-identity-");
  const dispatcher = makeDispatcher(
    directory,
    async () => {
      dispatches += 1;
      throw new Error("must not dispatch");
    },
    { policy, configuration: config, identity: tampered },
  );
  const result = await dispatcher.dispatch(request);
  dispatcher.finalize();
  assert.equal(dispatches, 0);
  assert.equal(result.disposition, "blocked");
  assert.equal(result.identitySha256, null);
  assert.deepEqual(verifyGatewayBundle(directory).blockers, []);

  const foreignClaims = { ...source, policy_sha256: digestCanonical({ policy: "other" }) };
  const foreignIdentity = issueWorkloadIdentity(foreignClaims, "foreign-key-v1", foreignKeys.privateKey);
  const secondDirectory = bundleDirectory("gradia-http-policy-identity-");
  const second = makeDispatcher(
    secondDirectory,
    async () => {
      dispatches += 1;
      throw new Error("must not dispatch");
    },
    { policy, configuration: config, identity: foreignIdentity },
  );
  const secondResult = await second.dispatch({ ...request, logicalRequestId: "request-2" });
  second.finalize();
  assert.equal(dispatches, 0);
  assert.equal(secondResult.disposition, "blocked");
});

test("tampered sealed policy and configuration refuse before a recorder or transport exists", () => {
  const policy = sealPolicy(policyBody());
  const config = configuration();
  const tamperedPolicy = JSON.parse(canonicalJson(policy)) as GuardPolicy;
  tamperedPolicy.model_routes[0]!.max_request_bytes += 1;
  assert.throws(
    () => makeDispatcher(bundleDirectory(), async () => invalidTransportResponse(), { policy: tamperedPolicy, configuration: config }),
    /guard_policy_digest_mismatch/,
  );

  const tamperedConfig = JSON.parse(canonicalJson(config)) as GuardHttpEgressConfiguration;
  tamperedConfig.model_routes[0]!.target_url = "https://evil.test/v1/responses";
  assert.throws(
    () => makeDispatcher(bundleDirectory(), async () => invalidTransportResponse(), { policy, configuration: tamperedConfig }),
    /configuration_digest_mismatch/,
  );
});

test("redirect and final-host substitution are typed protocol failures and never returned", async () => {
  for (const response of [
    {
      responseBody: Buffer.from('{"redirect":true}'),
      responseMediaType: "application/json",
      httpStatus: 302,
      finalUrl: targetUrl,
      redirected: false,
    },
    {
      responseBody: responseBody(),
      responseMediaType: "application/json",
      httpStatus: 200,
      finalUrl: "https://evil.test/harvest",
      redirected: true,
    },
  ]) {
    const directory = bundleDirectory("gradia-http-redirect-");
    const dispatcher = makeDispatcher(directory, async () => response);
    const result = await dispatcher.dispatch(request);
    dispatcher.finalize();
    assert.equal(result.disposition, "protocol_failure");
    assert.equal(result.response, null);
    assert.equal(result.action?.outcome, "protocol_failure");
    assert.deepEqual(verifyGatewayBundle(directory).blockers, []);
  }
});

test("provider model substitution is withheld and makes the evidence bundle fail closed", async () => {
  const directory = bundleDirectory("gradia-http-model-substitution-");
  const dispatcher = makeDispatcher(directory, async () => ({
    responseBody: responseBody("gpt-5.6-2026-09-01"),
    responseMediaType: "application/json",
    httpStatus: 200,
    finalUrl: targetUrl,
    redirected: false,
  }));
  const result = await dispatcher.dispatch(request);
  dispatcher.finalize();
  assert.equal(result.disposition, "identity_mismatch");
  assert.equal(result.response, null);
  assert.ok(verifyGatewayBundle(directory).blockers.some((item) => item.includes("identity_mismatch_recorded")));
});

test("transport, provider, and provider-protocol failures remain separately typed", async () => {
  const cases: readonly [string, GuardHttpEgressTransport, string][] = [
    ["transport", async () => { throw new Error("socket secret detail"); }, "transport_failure"],
    [
      "provider",
      async () => ({
        responseBody: Buffer.from('{"error":"rate_limited"}'),
        responseMediaType: "application/json",
        httpStatus: 429,
        finalUrl: targetUrl,
        redirected: false,
      }),
      "provider_failure",
    ],
    [
      "protocol",
      async () => ({
        responseBody: Buffer.from('{"missing":"model_and_usage"}'),
        responseMediaType: "application/json",
        httpStatus: 200,
        finalUrl: targetUrl,
        redirected: false,
      }),
      "protocol_failure",
    ],
  ];
  for (const [label, transport, expected] of cases) {
    const directory = bundleDirectory(`gradia-http-${label}-`);
    const dispatcher = makeDispatcher(directory, transport);
    const result = await dispatcher.dispatch(request);
    dispatcher.finalize();
    assert.equal(result.disposition, expected);
    assert.deepEqual(verifyGatewayBundle(directory).blockers, []);
    assert.doesNotMatch(readFileSync(join(directory, "frames.ndjson"), "utf8"), /socket secret detail/);
  }
});

test("no-redirect fetch transport uses closure credentials without capturing them", async () => {
  const directory = bundleDirectory("gradia-http-secret-");
  let observedAuthorization = "";
  let observedRedirect = "";
  const transport = createNoRedirectFetchTransport({
    credentialHeaders: () => ({ authorization: "Bearer top-secret-provider-key" }),
    fetchImpl: async (_input, init) => {
      const headers = new Headers(init?.headers);
      observedAuthorization = headers.get("authorization") ?? "";
      observedRedirect = String(init?.redirect);
      return new Response(Buffer.from(responseBody()), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });
  const dispatcher = makeDispatcher(directory, transport);
  const result = await dispatcher.dispatch(request);
  dispatcher.finalize();
  assert.equal(result.disposition, "completed");
  assert.equal(observedAuthorization, "Bearer top-secret-provider-key");
  assert.equal(observedRedirect, "manual");
  const evidence = readFileSync(join(directory, "frames.ndjson"), "utf8");
  assert.doesNotMatch(evidence, /top-secret-provider-key|authorization/i);
});

test("credential closure accepts only the provider authentication header", async () => {
  const cases = [
    ["openai", "authorization"],
    ["xai", "authorization"],
    ["anthropic", "x-api-key"],
    ["gemini", "x-goog-api-key"],
  ] as const;
  for (const [provider, credentialHeader] of cases) {
    let observedHeaders: Headers | null = null;
    const transport = createNoRedirectFetchTransport({
      credentialHeaders: () => ({ [credentialHeader]: "credential-value" }),
      fetchImpl: async (_input, init) => {
        observedHeaders = new Headers(init?.headers);
        return new Response(Buffer.from(responseBody()), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
    });
    await transport({
      provider,
      targetUrl,
      method: "POST",
      requestBody: requestBody(),
      requestMediaType: "application/json",
      requestedModel: model,
      timeoutMs: 5_000,
      maxResponseBytes: 100_000,
    });
    assert.equal((observedHeaders as Headers | null)?.get(credentialHeader), "credential-value");
    assert.equal((observedHeaders as Headers | null)?.get("content-type"), "application/json");
  }
});

test("credential closure cannot smuggle routing, request, or ambiguous authentication headers", async () => {
  const refused = [
    {},
    { "openai-organization": "other-tenant" },
    { host: "evil.test" },
    { cookie: "session=secret" },
    { "content-type": "text/plain" },
    { "x-forwarded-host": "evil.test" },
    { "x-api-key": "wrong-provider-credential" },
    { Authorization: "Bearer one", authorization: "Bearer two" },
    { authorization: " Bearer leading-space" },
    { authorization: "Bearer trailing-space " },
    { authorization: "Bearer control\u0000character" },
  ];
  for (const credentialHeaders of refused) {
    let fetches = 0;
    const transport = createNoRedirectFetchTransport({
      credentialHeaders: () => credentialHeaders,
      fetchImpl: async () => {
        fetches += 1;
        return new Response(Buffer.from(responseBody()), { status: 200 });
      },
    });
    await assert.rejects(() =>
      transport({
        provider: "openai",
        targetUrl,
        method: "POST",
        requestBody: requestBody(),
        requestMediaType: "application/json",
        requestedModel: model,
        timeoutMs: 5_000,
        maxResponseBytes: 100_000,
      }),
    );
    assert.equal(fetches, 0);
  }
});

test("credential-header refusal is a verified transport failure without secret disclosure", async () => {
  const directory = bundleDirectory("gradia-http-secret-refused-");
  let fetches = 0;
  const transport = createNoRedirectFetchTransport({
    credentialHeaders: () => ({ cookie: "session=must-never-land" }),
    fetchImpl: async () => {
      fetches += 1;
      return new Response(Buffer.from(responseBody()), { status: 200 });
    },
  });
  const dispatcher = makeDispatcher(directory, transport);
  const result = await dispatcher.dispatch(request);
  dispatcher.finalize();
  assert.equal(fetches, 0);
  assert.equal(result.disposition, "transport_failure");
  assert.deepEqual(verifyGatewayBundle(directory).blockers, []);
  const evidence = readFileSync(join(directory, "frames.ndjson"), "utf8");
  assert.doesNotMatch(evidence, /must-never-land|cookie|credential_header/i);
});

test("boundary disclosure cannot be edited into a host or Kubernetes enforcement claim", () => {
  const expected = enforcementBoundary("local_http_proxy");
  const tampered = JSON.parse(canonicalJson(expected)) as typeof expected;
  (tampered as unknown as { bypass_possible: boolean }).bypass_possible = false;
  assert.throws(() => verifyEnforcementBoundary(tampered), /boundary_mismatch/);

  const hostClaim = JSON.parse(canonicalJson(expected)) as typeof expected;
  (hostClaim as unknown as { full_host_enforcement: boolean }).full_host_enforcement = true;
  assert.throws(() => verifyEnforcementBoundary(hostClaim), /boundary_mismatch/);
});

function invalidTransportResponse() {
  return {
    responseBody: responseBody(),
    responseMediaType: "application/json",
    httpStatus: 200,
    finalUrl: targetUrl,
    redirected: false,
  };
}
