const expectedNames = [
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_BASE_URL",
  "GEMINI_API_KEY",
  "GOOGLE_API_KEY",
  "GOOGLE_GEMINI_BASE_URL",
  "GRADIA_GUARD_LOCAL_CAPABILITY",
  "GRADIA_GUARD_LOCAL_ORIGIN",
  "GRADIA_GUARD_RUNTIME_ID",
  "OPENAI_API_KEY",
  "OPENAI_BASE_URL",
  "XAI_API_KEY",
  "XAI_BASE_URL",
];
const unexpectedNames = Object.keys(process.env).filter(
  (name) => !expectedNames.includes(name) && name !== "__CF_USER_TEXT_ENCODING",
);
if (unexpectedNames.length > 0) process.exit(21);

const provider = process.argv[2];
const { generateText } = await import("ai");
let model;
if (provider === "openai") {
  const { createOpenAI } = await import("@ai-sdk/openai");
  model = createOpenAI({
    apiKey: process.env.OPENAI_API_KEY,
    baseURL: process.env.OPENAI_BASE_URL,
  }).responses("gpt-5.6-2026-08-01");
} else if (provider === "xai") {
  const { createXai } = await import("@ai-sdk/xai");
  model = createXai({
    apiKey: process.env.XAI_API_KEY,
    baseURL: process.env.XAI_BASE_URL,
  }).responses("grok-4.6");
} else if (provider === "anthropic") {
  const { createAnthropic } = await import("@ai-sdk/anthropic");
  model = createAnthropic({
    apiKey: process.env.ANTHROPIC_API_KEY,
    // Vercel's provider appends `/messages`; Anthropic's official client
    // appends `/v1/messages` to the same Guard base environment variable.
    baseURL: `${process.env.ANTHROPIC_BASE_URL}/v1`,
  }).messages("claude-opus-5-20260801");
} else if (provider === "gemini") {
  const { createGoogle } = await import("@ai-sdk/google");
  model = createGoogle({
    apiKey: process.env.GEMINI_API_KEY,
    // Vercel's provider appends `/models/...`; google-genai inserts its
    // configured API version.  Both resolve to Guard's exact v1beta route.
    baseURL: `${process.env.GOOGLE_GEMINI_BASE_URL}/v1beta`,
  }).chat("gemini-4-pro");
} else {
  process.exit(22);
}

const result = await generateText({
  model,
  prompt: "case",
  maxOutputTokens: 16,
  maxRetries: 0,
});
if (result.text !== "ok") process.exit(23);
process.stdout.write(`credentialless Vercel AI SDK ${provider} completed\n`);
