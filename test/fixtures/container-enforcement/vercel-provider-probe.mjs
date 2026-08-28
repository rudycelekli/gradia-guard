import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const provider = process.argv[2];
const candidates = {
  anthropic: {
    model: "claude-opus-5-20260801",
    package: "@ai-sdk/anthropic",
    baseName: "ANTHROPIC_BASE_URL",
    keyName: "ANTHROPIC_API_KEY",
  },
  gemini: {
    model: "gemini-4-pro",
    package: "@ai-sdk/google",
    baseName: "GOOGLE_GEMINI_BASE_URL",
    keyName: "GEMINI_API_KEY",
  },
  openai: {
    model: "gpt-5.6-2026-08-01",
    package: "@ai-sdk/openai",
    baseName: "OPENAI_BASE_URL",
    keyName: "OPENAI_API_KEY",
  },
  xai: {
    model: "grok-4.6",
    package: "@ai-sdk/xai",
    baseName: "XAI_BASE_URL",
    keyName: "XAI_API_KEY",
  },
};
const candidate = candidates[provider];
if (!candidate) throw new Error("container_sdk_provider_invalid");
for (const name of [
  "GRADIA_GUARD_LOCAL_CAPABILITY",
  "GRADIA_GUARD_LOCAL_ORIGIN",
  "GRADIA_GUARD_RUNTIME_ID",
  candidate.baseName,
  candidate.keyName,
]) {
  if (!process.env[name]) throw new Error(`container_sdk_environment_missing:${name}`);
}
if (process.env[candidate.keyName] !== process.env.GRADIA_GUARD_LOCAL_CAPABILITY) {
  throw new Error("container_sdk_nonlocal_auth_value");
}

const origin = process.env.GRADIA_GUARD_LOCAL_ORIGIN;
const expectedBases = {
  anthropic: `${origin}/anthropic`,
  gemini: `${origin}/gemini`,
  openai: `${origin}/openai/v1`,
  xai: `${origin}/xai/v1`,
};
if (process.env[candidate.baseName] !== expectedBases[provider]) {
  throw new Error("container_sdk_origin_mismatch");
}

const require = createRequire(import.meta.url);
function packageVersion(name) {
  const path = require.resolve(`${name}/package.json`);
  return JSON.parse(readFileSync(path, "utf8")).version;
}

const { generateText } = await import("ai");
let model;
let routeId;
if (provider === "anthropic") {
  const { createAnthropic } = await import("@ai-sdk/anthropic");
  model = createAnthropic({
    apiKey: process.env.ANTHROPIC_API_KEY,
    baseURL: `${process.env.ANTHROPIC_BASE_URL}/v1`,
  }).messages(candidate.model);
  routeId = "anthropic.messages";
} else if (provider === "gemini") {
  const { createGoogle } = await import("@ai-sdk/google");
  model = createGoogle({
    apiKey: process.env.GEMINI_API_KEY,
    baseURL: `${process.env.GOOGLE_GEMINI_BASE_URL}/v1beta`,
  }).chat(candidate.model);
  routeId = "gemini.generateContent";
} else if (provider === "openai") {
  const { createOpenAI } = await import("@ai-sdk/openai");
  model = createOpenAI({
    apiKey: process.env.OPENAI_API_KEY,
    baseURL: process.env.OPENAI_BASE_URL,
  }).responses(candidate.model);
  routeId = "openai.responses";
} else {
  const { createXai } = await import("@ai-sdk/xai");
  model = createXai({
    apiKey: process.env.XAI_API_KEY,
    baseURL: process.env.XAI_BASE_URL,
  }).responses(candidate.model);
  routeId = "xai.responses";
}

const result = await generateText({ model, prompt: "case", maxOutputTokens: 16, maxRetries: 0 });
if (result.text !== "ok") throw new Error("container_sdk_response_mismatch");
process.stdout.write(`${JSON.stringify({
  schema_version: "gradia.guard.container-sdk-probe-output.v1",
  runtime_id: process.env.GRADIA_GUARD_RUNTIME_ID,
  framework: "vercel_ai_sdk",
  provider,
  framework_core_package: "ai",
  framework_core_version: packageVersion("ai"),
  provider_package: candidate.package,
  provider_package_version: packageVersion(candidate.package),
  route_id: routeId,
  requested_model: candidate.model,
  response_text: "ok",
})}\n`);
