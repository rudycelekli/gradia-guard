import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import {
  canonicalJson,
  createProviderCredentiallessGatewayServer,
  digestCanonical,
  issueWorkloadIdentity,
  runProviderCredentiallessChild,
  sealHttpEgressConfiguration,
  sealPolicy,
  verifyCredentiallessChildBoundary,
  verifyCredentiallessRuntime,
  type CredentiallessChildRuntimeOptions,
  type CredentiallessRuntimeReceipt,
  type GuardHttpEgressConfiguration,
  type LocalHttpEgressDispatcher,
  type GuardPolicy,
  type GuardPolicyBody,
  type GuardWorkloadIdentity,
  type GuardWorkloadIdentityClaims,
} from "../src/index.js";

const keys = generateKeyPairSync("ed25519");
const now = 1_787_549_400;
const model = "gpt-5.6-2026-08-01";
const targetUrl = "https://api.openai.example/v1/responses";

test("standalone sidecar server refuses weak capabilities and reused counters", () => {
  const exactPolicy = policy();
  const exactConfiguration = configuration();
  const empty = { accepted: 0, explicitEnvelope: 0, nativeProvider: 0, unauthorized: 0, malformed: 0 };
  assert.throws(
    () =>
      createProviderCredentiallessGatewayServer(
        null as unknown as LocalHttpEgressDispatcher,
        "weak",
        empty,
        exactPolicy,
        exactConfiguration,
        "sidecar-test-runtime",
        ["model.invoke"],
      ),
    /credentialless_runtime_local_capability_invalid/,
  );
  assert.throws(
    () =>
      createProviderCredentiallessGatewayServer(
        null as unknown as LocalHttpEgressDispatcher,
        "a".repeat(32),
        { ...empty, accepted: 1 },
        exactPolicy,
        exactConfiguration,
        "sidecar-test-runtime",
        ["model.invoke"],
      ),
    /credentialless_runtime_counters_not_empty/,
  );
});

const nativeCases = {
  anthropic: {
    model: "claude-opus-5-20260801",
    targetUrl: "https://api.anthropic.example/v1/messages",
    response: {
      id: "message-1",
      type: "message",
      role: "assistant",
      model: "claude-opus-5-20260801",
      stop_reason: "end_turn",
      stop_sequence: null,
      usage: { input_tokens: 12, output_tokens: 7 },
      content: [{ type: "text", text: "ok" }],
    },
  },
  gemini: {
    model: "gemini-4-pro",
    targetUrl:
      "https://generativelanguage.googleapis.example/v1beta/models/gemini-4-pro:generateContent",
    response: {
      modelVersion: "gemini-4-pro",
      usageMetadata: {
        promptTokenCount: 12,
        candidatesTokenCount: 7,
        totalTokenCount: 19,
      },
      candidates: [
        {
          index: 0,
          finishReason: "STOP",
          content: { role: "model", parts: [{ text: "ok" }] },
        },
      ],
    },
  },
  openai: {
    model,
    targetUrl,
    response: {
      id: "response-1",
      object: "response",
      created_at: 1_787_549_400,
      status: "completed",
      model,
      usage: { input_tokens: 12, output_tokens: 7, total_tokens: 19 },
      output: [
        {
          id: "message-1",
          type: "message",
          status: "completed",
          role: "assistant",
          content: [
            { type: "output_text", text: "ok", annotations: [], logprobs: [] },
          ],
        },
      ],
    },
  },
  xai: {
    model: "grok-4.6",
    targetUrl: "https://api.x.ai.example/v1/responses",
    response: {
      id: "response-1",
      object: "response",
      created_at: 1_787_549_400,
      status: "completed",
      model: "grok-4.6",
      usage: { input_tokens: 12, output_tokens: 7, total_tokens: 19 },
      output: [
        {
          id: "message-1",
          type: "message",
          status: "completed",
          role: "assistant",
          content: [
            { type: "output_text", text: "ok", annotations: [], logprobs: [] },
          ],
        },
      ],
    },
  },
} as const;

function policy(): GuardPolicy {
  const body: GuardPolicyBody = {
    schema_version: "gradia.guard.policy.v1",
    policy_id: "credentialless-runtime-policy",
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
    tool_routes: [],
  };
  return sealPolicy(body);
}

function configuration(): GuardHttpEgressConfiguration {
  return sealHttpEgressConfiguration({
    schema_version: "gradia.guard.local-http-egress-configuration.v1",
    configuration_id: "credentialless-runtime-egress",
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

function claims(
  exactPolicy: GuardPolicy,
  exactConfiguration: GuardHttpEgressConfiguration,
): GuardWorkloadIdentityClaims {
  return {
    issuer_id: "gradia-managed",
    organization_id: "org-1",
    project_id: "project-1",
    workload_id: "credentialless-agent-1",
    deployment_id: "deployment-1",
    audience: "guard-runtime",
    policy_sha256: exactPolicy.policy_sha256,
    image_sha256: digestCanonical({ image: "v1" }),
    configuration_sha256: exactConfiguration.configuration_sha256,
    collector_sha256: digestCanonical({ collector: "v1" }),
    authority_scope_ids: ["model.invoke"],
    issued_at_unix: now,
    not_before_unix: now,
    expires_at_unix: now + 300,
    nonce_sha256: digestCanonical({ nonce: "credentialless-runtime" }),
  };
}

function identity(
  exactPolicy: GuardPolicy,
  exactConfiguration: GuardHttpEgressConfiguration,
): GuardWorkloadIdentity {
  return issueWorkloadIdentity(
    claims(exactPolicy, exactConfiguration),
    "issuer-key-v1",
    keys.privateKey,
  );
}

function runtimeOptions(mode = "success"): {
  options: CredentiallessChildRuntimeOptions;
  upstreamCalls: () => number;
} {
  const exactPolicy = policy();
  const exactConfiguration = configuration();
  const source = claims(exactPolicy, exactConfiguration);
  let calls = 0;
  return {
    options: {
      directory: join(mkdtempSync(join(tmpdir(), "gradia-credentialless-runtime-")), "runtime"),
      command: [
        process.execPath,
        join(process.cwd(), "test/fixtures/credentialless-child.mjs"),
        mode,
      ],
      cwd: process.cwd(),
      policy: exactPolicy,
      configuration: exactConfiguration,
      workloadIdentity: identity(exactPolicy, exactConfiguration),
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
      transport: async () => {
        calls += 1;
        return {
          responseBody: Buffer.from(
            JSON.stringify({
              id: "response-1",
              model,
              usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 },
              output: [],
            }),
          ),
          responseMediaType: "application/json",
          httpStatus: 200,
          finalUrl: targetUrl,
          redirected: false,
        };
      },
    },
    upstreamCalls: () => calls,
  };
}

function nativeRuntimeOptions(
  provider: keyof typeof nativeCases,
  mode = `native-${provider}`,
): {
  options: CredentiallessChildRuntimeOptions;
  upstreamCalls: () => number;
} {
  const candidate = nativeCases[provider];
  const exactPolicy = sealPolicy({
    schema_version: "gradia.guard.policy.v1",
    policy_id: `credentialless-native-${provider}`,
    policy_version: "v1",
    default_decision: "blocked",
    model_routes: [
      {
        provider,
        requested_model: candidate.model,
        authority_scope_ids: ["model.invoke"],
        max_request_bytes: 10_000,
        max_attempt_number: 2,
      },
    ],
    tool_routes: [],
  });
  const exactConfiguration = sealHttpEgressConfiguration({
    schema_version: "gradia.guard.local-http-egress-configuration.v1",
    configuration_id: `credentialless-native-${provider}`,
    configuration_version: "v1",
    default_decision: "blocked",
    model_routes: [
      {
        provider,
        target_url: candidate.targetUrl,
        method: "POST",
        request_media_type: "application/json",
        redirect_mode: "error",
        timeout_ms: 5_000,
        max_response_bytes: 100_000,
      },
    ],
  });
  const source = claims(exactPolicy, exactConfiguration);
  let calls = 0;
  return {
    options: {
      directory: join(mkdtempSync(join(tmpdir(), "gradia-native-runtime-")), "runtime"),
      command: [
        process.execPath,
        join(process.cwd(), "test/fixtures/credentialless-child.mjs"),
        mode,
      ],
      cwd: process.cwd(),
      policy: exactPolicy,
      configuration: exactConfiguration,
      workloadIdentity: identity(exactPolicy, exactConfiguration),
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
      transport: async (input) => {
        calls += 1;
        assert.equal(input.provider, provider);
        assert.equal(input.targetUrl, candidate.targetUrl);
        assert.equal(input.requestedModel, candidate.model);
        return {
          responseBody: Buffer.from(JSON.stringify(candidate.response)),
          responseMediaType: "application/json",
          httpStatus: 200,
          finalUrl: candidate.targetUrl,
          redirected: false,
        };
      },
    },
    upstreamCalls: () => calls,
  };
}

test("parent-owned gateway runs a provider-credentialless child and binds both evidence bundles", async () => {
  const rootProviderCredential = "provider-key-must-stay-in-parent";
  const previous = process.env["OPENAI_API_KEY"];
  process.env["OPENAI_API_KEY"] = rootProviderCredential;
  try {
    const { options, upstreamCalls } = runtimeOptions();
    const result = await runProviderCredentiallessChild(options);
    assert.equal(upstreamCalls(), 1);
    assert.equal(result.verification.ok, true, result.verification.blockers.join(","));
    assert.equal(result.receipt.accepted_local_requests, 1);
    assert.equal(result.receipt.explicit_envelope_requests, 1);
    assert.equal(result.receipt.native_provider_requests, 0);
    assert.equal(result.receipt.unauthorized_local_requests, 0);
    assert.equal(result.receipt.malformed_local_requests, 0);
    assert.equal(
      result.receipt.boundary.provider_credentials_forwarded_by_parent_environment,
      false,
    );
    assert.equal(result.receipt.boundary.bypass_possible, true);
    assert.doesNotThrow(() => verifyCredentiallessChildBoundary(result.receipt.boundary));
    const evidence = [
      readFileSync(join(result.directory, "runtime.json"), "utf8"),
      readFileSync(join(result.directory, "model-gateway", "frames.ndjson"), "utf8"),
      readFileSync(
        join(result.directory, "process", result.receipt.process_bundle_name, "frames.ndjson"),
        "utf8",
      ),
    ].join("\n");
    assert.doesNotMatch(evidence, /provider-key-must-stay-in-parent/);
    assert.match(evidence, /OPENAI_API_KEY/);
  } finally {
    if (previous === undefined) delete process.env["OPENAI_API_KEY"];
    else process.env["OPENAI_API_KEY"] = previous;
  }
});

test("native provider routes work with local-only SDK credentials for all four providers", async () => {
  for (const provider of Object.keys(nativeCases) as (keyof typeof nativeCases)[]) {
    const { options, upstreamCalls } = nativeRuntimeOptions(provider);
    const result = await runProviderCredentiallessChild(options);
    assert.equal(upstreamCalls(), 1, provider);
    assert.equal(result.verification.ok, true, `${provider}:${result.verification.blockers.join(",")}`);
    assert.equal(result.receipt.accepted_local_requests, 1);
    assert.equal(result.receipt.explicit_envelope_requests, 0);
    assert.equal(result.receipt.native_provider_requests, 1);
    assert.equal(
      result.receipt.boundary.provider_sdk_auth_values_are_local_capability_only,
      true,
    );
    assert.equal(result.receipt.boundary.provider_credentials_forwarded_by_parent_environment, false);
    assert.deepEqual(result.receipt.boundary.native_provider_route_ids, [
      "anthropic.messages",
      "gemini.generateContent",
      "openai.responses",
      "xai.responses",
    ]);
  }
});

for (const provider of Object.keys(nativeCases) as (keyof typeof nativeCases)[]) {
  test(`pinned ${provider} SDK reaches the exact native Guard route without provider credentials`, async () => {
    const credentialName = {
      anthropic: "ANTHROPIC_API_KEY",
      gemini: "GEMINI_API_KEY",
      openai: "OPENAI_API_KEY",
      xai: "XAI_API_KEY",
    }[provider];
    const priorCredential = process.env[credentialName];
    const parentOnlyCredential = `parent-provider-credential-${provider}-must-not-cross`;
    process.env[credentialName] = parentOnlyCredential;
    try {
      const { options, upstreamCalls } = nativeRuntimeOptions(provider, `sdk-${provider}`);
      options.command = [
        process.execPath,
        join(process.cwd(), "test/fixtures/credentialless-sdk-child.mjs"),
        provider,
      ];
      const result = await runProviderCredentiallessChild(options);
      assert.equal(upstreamCalls(), 1);
      assert.equal(result.verification.ok, true, result.verification.blockers.join(","));
      assert.equal(result.receipt.accepted_local_requests, 1);
      assert.equal(result.receipt.native_provider_requests, 1);
      assert.equal(result.receipt.explicit_envelope_requests, 0);
      assert.equal(
        result.receipt.boundary.provider_credentials_forwarded_by_parent_environment,
        false,
      );
      const evidence = [
        readFileSync(join(result.directory, "runtime.json"), "utf8"),
        readFileSync(join(result.directory, "model-gateway", "frames.ndjson"), "utf8"),
        readFileSync(
          join(result.directory, "process", result.receipt.process_bundle_name, "frames.ndjson"),
          "utf8",
        ),
      ].join("\n");
      assert.doesNotMatch(evidence, new RegExp(parentOnlyCredential));
    } finally {
      if (priorCredential === undefined) delete process.env[credentialName];
      else process.env[credentialName] = priorCredential;
    }
  });
}

for (const provider of Object.keys(nativeCases) as (keyof typeof nativeCases)[]) {
  test(`pinned Vercel AI SDK ${provider} provider reaches the exact native Guard route`, async () => {
    const credentialName = {
      anthropic: "ANTHROPIC_API_KEY",
      gemini: "GEMINI_API_KEY",
      openai: "OPENAI_API_KEY",
      xai: "XAI_API_KEY",
    }[provider];
    const priorCredential = process.env[credentialName];
    const parentOnlyCredential = `parent-vercel-ai-credential-${provider}-must-not-cross`;
    process.env[credentialName] = parentOnlyCredential;
    try {
      const { options, upstreamCalls } = nativeRuntimeOptions(provider, `vercel-ai-${provider}`);
      options.command = [
        process.execPath,
        join(process.cwd(), "test/fixtures/credentialless-vercel-ai-child.mjs"),
        provider,
      ];
      const result = await runProviderCredentiallessChild(options);
      assert.equal(upstreamCalls(), 1);
      assert.equal(result.verification.ok, true, result.verification.blockers.join(","));
      assert.equal(result.receipt.accepted_local_requests, 1);
      assert.equal(result.receipt.native_provider_requests, 1);
      assert.equal(result.receipt.explicit_envelope_requests, 0);
      assert.equal(
        result.receipt.boundary.provider_credentials_forwarded_by_parent_environment,
        false,
      );
      const evidence = [
        readFileSync(join(result.directory, "runtime.json"), "utf8"),
        readFileSync(join(result.directory, "model-gateway", "frames.ndjson"), "utf8"),
        readFileSync(
          join(result.directory, "process", result.receipt.process_bundle_name, "frames.ndjson"),
          "utf8",
        ),
      ].join("\n");
      assert.doesNotMatch(evidence, new RegExp(parentOnlyCredential));
    } finally {
      if (priorCredential === undefined) delete process.env[credentialName];
      else process.env[credentialName] = priorCredential;
    }
  });
}

if (process.env["GRADIA_GUARD_TEST_PYTHON_SDKS"] === "1") {
  const projectRoot = resolve(process.cwd(), "../..");
  const pythonExecutable = join(
    projectRoot,
    ".venv",
    process.platform === "win32" ? "Scripts/python.exe" : "bin/python",
  );
  if (!existsSync(pythonExecutable)) {
    throw new Error("python_sdk_matrix_pinned_virtual_environment_missing");
  }
  for (const provider of Object.keys(nativeCases) as (keyof typeof nativeCases)[]) {
    test(`pinned Python ${provider} SDK reaches the exact native Guard route without provider credentials`, async () => {
      const credentialName = {
        anthropic: "ANTHROPIC_API_KEY",
        gemini: "GEMINI_API_KEY",
        openai: "OPENAI_API_KEY",
        xai: "XAI_API_KEY",
      }[provider];
      const priorCredential = process.env[credentialName];
      const parentOnlyCredential = `parent-python-provider-credential-${provider}-must-not-cross`;
      process.env[credentialName] = parentOnlyCredential;
      try {
        const { options, upstreamCalls } = nativeRuntimeOptions(provider, `python-${provider}`);
        options.command = [
          pythonExecutable,
          join(process.cwd(), "test/fixtures/credentialless-python-sdk-child.py"),
          provider,
        ];
        const result = await runProviderCredentiallessChild(options);
        assert.equal(upstreamCalls(), 1);
        assert.equal(result.verification.ok, true, result.verification.blockers.join(","));
        assert.equal(result.receipt.accepted_local_requests, 1);
        assert.equal(result.receipt.native_provider_requests, 1);
        assert.equal(result.receipt.explicit_envelope_requests, 0);
        assert.equal(
          result.receipt.boundary.provider_credentials_forwarded_by_parent_environment,
          false,
        );
        const evidence = [
          readFileSync(join(result.directory, "runtime.json"), "utf8"),
          readFileSync(join(result.directory, "model-gateway", "frames.ndjson"), "utf8"),
          readFileSync(
            join(result.directory, "process", result.receipt.process_bundle_name, "frames.ndjson"),
            "utf8",
          ),
        ].join("\n");
        assert.doesNotMatch(evidence, new RegExp(parentOnlyCredential));
      } finally {
        if (priorCredential === undefined) delete process.env[credentialName];
        else process.env[credentialName] = priorCredential;
      }
    });
  }
}

if (process.env["GRADIA_GUARD_TEST_LANGCHAIN"] === "1") {
  const projectRoot = resolve(process.cwd(), "../..");
  const pythonExecutable = join(
    projectRoot,
    ".venv",
    process.platform === "win32" ? "Scripts/python.exe" : "bin/python",
  );
  if (!existsSync(pythonExecutable)) {
    throw new Error("python_framework_matrix_pinned_virtual_environment_missing");
  }
  for (const provider of Object.keys(nativeCases) as (keyof typeof nativeCases)[]) {
    test(`pinned LangChain ${provider} provider reaches the exact native Guard route`, async () => {
      const credentialName = {
        anthropic: "ANTHROPIC_API_KEY",
        gemini: "GEMINI_API_KEY",
        openai: "OPENAI_API_KEY",
        xai: "XAI_API_KEY",
      }[provider];
      const priorCredential = process.env[credentialName];
      const parentOnlyCredential = `parent-langchain-credential-${provider}-must-not-cross`;
      process.env[credentialName] = parentOnlyCredential;
      try {
        const { options, upstreamCalls } = nativeRuntimeOptions(provider, `langchain-${provider}`);
        options.command = [
          pythonExecutable,
          join(process.cwd(), "test/fixtures/credentialless-langchain-child.py"),
          provider,
        ];
        const result = await runProviderCredentiallessChild(options);
        assert.equal(upstreamCalls(), 1);
        assert.equal(result.verification.ok, true, result.verification.blockers.join(","));
        assert.equal(result.receipt.accepted_local_requests, 1);
        assert.equal(result.receipt.native_provider_requests, 1);
        assert.equal(result.receipt.explicit_envelope_requests, 0);
        assert.equal(
          result.receipt.boundary.provider_credentials_forwarded_by_parent_environment,
          false,
        );
        const evidence = [
          readFileSync(join(result.directory, "runtime.json"), "utf8"),
          readFileSync(join(result.directory, "model-gateway", "frames.ndjson"), "utf8"),
          readFileSync(
            join(result.directory, "process", result.receipt.process_bundle_name, "frames.ndjson"),
            "utf8",
          ),
        ].join("\n");
        assert.doesNotMatch(evidence, new RegExp(parentOnlyCredential));
      } finally {
        if (priorCredential === undefined) delete process.env[credentialName];
        else process.env[credentialName] = priorCredential;
      }
    });
  }
}

test("wrong local capability is refused, never reaches upstream, and makes admission fail closed", async () => {
  const { options, upstreamCalls } = runtimeOptions("wrong-then-correct");
  const result = await runProviderCredentiallessChild(options);
  assert.equal(upstreamCalls(), 1);
  assert.equal(result.receipt.unauthorized_local_requests, 1);
  assert.equal(result.verification.ok, false);
  assert.ok(
    result.verification.blockers.includes("credentialless_runtime_unauthorized_local_request"),
  );
});

test("wrong native SDK capability is refused before dispatch and poisons admission", async () => {
  const { options, upstreamCalls } = nativeRuntimeOptions(
    "openai",
    "native-openai-wrong-capability-then-correct",
  );
  const result = await runProviderCredentiallessChild(options);
  assert.equal(upstreamCalls(), 1);
  assert.equal(result.receipt.unauthorized_local_requests, 1);
  assert.equal(result.receipt.native_provider_requests, 1);
  assert.equal(result.verification.ok, false);
  assert.ok(
    result.verification.blockers.includes("credentialless_runtime_unauthorized_local_request"),
  );
});

test("an unlisted native model creates blocked evidence and cannot reach upstream", async () => {
  const { options, upstreamCalls } = nativeRuntimeOptions(
    "openai",
    "native-openai-unlisted-then-correct",
  );
  const result = await runProviderCredentiallessChild(options);
  assert.equal(upstreamCalls(), 1);
  assert.equal(result.receipt.accepted_local_requests, 2);
  assert.equal(result.receipt.native_provider_requests, 2);
  assert.equal(result.receipt.malformed_local_requests, 0);
  assert.equal(result.verification.ok, true, result.verification.blockers.join(","));
  const frames = readFileSync(
    join(result.directory, "model-gateway", "frames.ndjson"),
    "utf8",
  );
  assert.match(frames, /model_route_not_allowed/);
  assert.match(frames, /"dispatch_occurred":false/);
});

test("unsupported native endpoint is refused locally and poisons admission", async () => {
  const { options, upstreamCalls } = nativeRuntimeOptions(
    "openai",
    "native-openai-bad-path-then-correct",
  );
  const result = await runProviderCredentiallessChild(options);
  assert.equal(upstreamCalls(), 1);
  assert.equal(result.receipt.malformed_local_requests, 1);
  assert.equal(result.receipt.native_provider_requests, 1);
  assert.equal(result.verification.ok, false);
  assert.ok(result.verification.blockers.includes("credentialless_runtime_malformed_local_request"));
});

test("unknown local request fields are refused and cannot disappear behind a later success", async () => {
  const { options, upstreamCalls } = runtimeOptions("malformed-then-correct");
  const result = await runProviderCredentiallessChild(options);
  assert.equal(upstreamCalls(), 1);
  assert.equal(result.receipt.malformed_local_requests, 1);
  assert.equal(result.verification.ok, false);
  assert.ok(result.verification.blockers.includes("credentialless_runtime_malformed_local_request"));
});

test("a child with no observed local model dispatch cannot produce admitted runtime evidence", async () => {
  const { options, upstreamCalls } = runtimeOptions("no-call");
  const result = await runProviderCredentiallessChild(options);
  assert.equal(upstreamCalls(), 0);
  assert.equal(result.verification.ok, false);
  assert.ok(result.verification.blockers.includes("credentialless_runtime_no_model_dispatch"));
  assert.ok(result.verification.blockers.includes("credentialless_runtime_gateway_bundle_invalid"));
});

test("receipt and enforcement-claim mutation fail even after attacker recomputes the outer digest", async () => {
  const { options } = runtimeOptions();
  const result = await runProviderCredentiallessChild(options);
  const receiptPath = join(result.directory, "runtime.json");
  const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as CredentiallessRuntimeReceipt;
  receipt.boundary.full_host_enforcement = true as never;
  const { receipt_sha256: _old, ...body } = receipt;
  receipt.receipt_sha256 = digestCanonical(body);
  writeFileSync(receiptPath, `${canonicalJson(receipt)}\n`);
  const verification = verifyCredentiallessRuntime(result.directory);
  assert.equal(verification.ok, false);
  assert.ok(verification.blockers.includes("credentialless_runtime_boundary_mismatch"));
});

test("a rehashed configuration substitution cannot detach the runtime receipt from gateway evidence", async () => {
  const { options } = runtimeOptions();
  const result = await runProviderCredentiallessChild(options);
  const receiptPath = join(result.directory, "runtime.json");
  const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as CredentiallessRuntimeReceipt;
  receipt.configuration_sha256 = digestCanonical({ configuration: "substituted" });
  const { receipt_sha256: _old, ...body } = receipt;
  receipt.receipt_sha256 = digestCanonical(body);
  writeFileSync(receiptPath, `${canonicalJson(receipt)}\n`);
  const verification = verifyCredentiallessRuntime(result.directory);
  assert.equal(verification.ok, false);
  assert.ok(
    verification.blockers.includes("credentialless_runtime_configuration_binding_mismatch"),
  );
});

test("a rehashed child-environment substitution cannot detach the receipt from process evidence", async () => {
  const { options } = runtimeOptions();
  const result = await runProviderCredentiallessChild(options);
  const receiptPath = join(result.directory, "runtime.json");
  const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as CredentiallessRuntimeReceipt;
  receipt.local_capability_sha256 = digestCanonical({ capability: "substituted" });
  receipt.environment_sha256 = digestCanonical({ environment: "substituted" });
  const { receipt_sha256: _old, ...body } = receipt;
  receipt.receipt_sha256 = digestCanonical(body);
  writeFileSync(receiptPath, `${canonicalJson(receipt)}\n`);
  const verification = verifyCredentiallessRuntime(result.directory);
  assert.equal(verification.ok, false);
  assert.ok(
    verification.blockers.includes("credentialless_runtime_environment_binding_mismatch"),
  );
  assert.ok(
    verification.blockers.includes("credentialless_runtime_environment_composition_mismatch"),
  );
});

test("relative commands are refused before any runtime directory exists", async () => {
  const { options } = runtimeOptions();
  options.command = ["node", "test/fixtures/credentialless-child.mjs"];
  await assert.rejects(
    () => runProviderCredentiallessChild(options),
    /credentialless_runtime_absolute_command_required/,
  );
});
