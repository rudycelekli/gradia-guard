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
let resolvedModel;
if (provider === "openai" || provider === "xai") {
  const { default: OpenAI } = await import("openai");
  const client = new OpenAI({
    apiKey: process.env[provider === "openai" ? "OPENAI_API_KEY" : "XAI_API_KEY"],
    baseURL: process.env[provider === "openai" ? "OPENAI_BASE_URL" : "XAI_BASE_URL"],
    maxRetries: 0,
    timeout: 5_000,
  });
  const model = provider === "openai" ? "gpt-5.6-2026-08-01" : "grok-4.6";
  const response = await client.responses.create({ model, input: "case" });
  resolvedModel = response.model;
} else if (provider === "anthropic") {
  const { default: Anthropic } = await import("@anthropic-ai/sdk");
  const client = new Anthropic({
    apiKey: process.env.ANTHROPIC_API_KEY,
    baseURL: process.env.ANTHROPIC_BASE_URL,
    maxRetries: 0,
    timeout: 5_000,
  });
  const response = await client.messages.create({
    model: "claude-opus-5-20260801",
    max_tokens: 16,
    messages: [{ role: "user", content: "case" }],
  });
  resolvedModel = response.model;
} else if (provider === "gemini") {
  const geminiCapability = process.env.GEMINI_API_KEY;
  delete process.env.GOOGLE_API_KEY;
  const { GoogleGenAI } = await import("@google/genai");
  const client = new GoogleGenAI({
    apiKey: geminiCapability,
    apiVersion: "v1beta",
    httpOptions: { baseUrl: process.env.GOOGLE_GEMINI_BASE_URL },
  });
  const response = await client.models.generateContent({
    model: "gemini-4-pro",
    contents: "case",
  });
  resolvedModel = response.modelVersion;
} else {
  process.exit(22);
}
if (typeof resolvedModel !== "string" || resolvedModel.length === 0) process.exit(23);
process.stdout.write(`credentialless SDK ${provider} completed\n`);
