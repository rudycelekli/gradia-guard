const mode = process.argv[2] ?? "success";
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
if (unexpectedNames.length > 0) {
  process.exit(21);
}
if (!process.env.GRADIA_GUARD_LOCAL_ORIGIN || !process.env.GRADIA_GUARD_LOCAL_CAPABILITY) {
  process.exit(22);
}
if (mode === "no-call") process.exit(0);

if (mode.startsWith("native-")) {
  const routes = {
    anthropic: {
      url: `${process.env.ANTHROPIC_BASE_URL}/v1/messages`,
      headers: { "x-api-key": process.env.ANTHROPIC_API_KEY },
      body: { model: "claude-opus-5-20260801", messages: [{ role: "user", content: "case" }] },
    },
    gemini: {
      url: `${process.env.GOOGLE_GEMINI_BASE_URL}/v1beta/models/gemini-4-pro:generateContent`,
      headers: { "x-goog-api-key": process.env.GEMINI_API_KEY },
      body: { contents: [{ parts: [{ text: "case" }] }] },
    },
    openai: {
      url: `${process.env.OPENAI_BASE_URL}/responses`,
      headers: { authorization: `Bearer ${process.env.OPENAI_API_KEY}` },
      body: { model: "gpt-5.6-2026-08-01", input: "case" },
    },
    xai: {
      url: `${process.env.XAI_BASE_URL}/responses`,
      headers: { authorization: `Bearer ${process.env.XAI_API_KEY}` },
      body: { model: "grok-4.6", input: "case" },
    },
  };
  if (mode === "native-openai-wrong-capability-then-correct") {
    const route = routes.openai;
    const refused = await fetch(route.url, {
      method: "POST",
      headers: { authorization: "Bearer wrong-local-capability", "content-type": "application/json" },
      body: JSON.stringify(route.body),
    });
    if (refused.status !== 401) process.exit(33);
  }
  if (mode === "native-openai-unlisted-then-correct") {
    const route = routes.openai;
    const refused = await fetch(route.url, {
      method: "POST",
      headers: { authorization: `Bearer ${process.env.OPENAI_API_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ ...route.body, model: "gpt-unlisted-2026-08-01" }),
    });
    if (refused.status !== 403) {
      process.stderr.write(`${await refused.text()}\n`);
      process.exit(34);
    }
  }
  if (mode === "native-openai-bad-path-then-correct") {
    const refused = await fetch(`${process.env.OPENAI_BASE_URL}/chat/completions`, {
      method: "POST",
      headers: { authorization: `Bearer ${process.env.OPENAI_API_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "gpt-5.6-2026-08-01", messages: [] }),
    });
    if (refused.status !== 400) process.exit(35);
  }
  const provider = mode
    .replace("native-", "")
    .replace("-wrong-capability-then-correct", "")
    .replace("-unlisted-then-correct", "")
    .replace("-bad-path-then-correct", "");
  const route = routes[provider];
  if (!route) process.exit(30);
  const nativeResponse = await fetch(route.url, {
    method: "POST",
    headers: { ...route.headers, "content-type": "application/json" },
    body: JSON.stringify(route.body),
  });
  if (nativeResponse.status !== 200) {
    process.stderr.write(`${await nativeResponse.text()}\n`);
    process.exit(31);
  }
  const payload = await nativeResponse.json();
  if (!payload || typeof payload !== "object") process.exit(32);
  process.stdout.write(`credentialless native ${provider} completed\n`);
  process.exit(0);
}

const providerRequest = Buffer.from(
  JSON.stringify({ model: "gpt-5.6-2026-08-01", input: "customer case bytes" }),
).toString("base64");
const envelope = {
  provider: "openai",
  target_url: "https://api.openai.example/v1/responses",
  request_body_base64: providerRequest,
  request_media_type: "application/json",
  requested_model_from_route: null,
  logical_request_id: "credentialless-request-1",
  attempt_number: 1,
  retry_of_occurrence_sha256: null,
  authority_scope_ids: ["model.invoke"],
};

async function dispatch(capability, body = envelope) {
  return fetch(`${process.env.GRADIA_GUARD_LOCAL_ORIGIN}/v1/model-dispatch`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${capability}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

if (mode === "wrong-then-correct") {
  const refused = await dispatch("wrong-local-capability");
  if (refused.status !== 401) process.exit(23);
}
if (mode === "malformed-then-correct") {
  const malformed = await dispatch(process.env.GRADIA_GUARD_LOCAL_CAPABILITY, {
    ...envelope,
    unbound_extension: true,
  });
  if (malformed.status !== 400) process.exit(24);
}

const response = await dispatch(process.env.GRADIA_GUARD_LOCAL_CAPABILITY);
if (response.status !== 200) process.exit(25);
const result = await response.json();
if (
  result.disposition !== "completed" ||
  typeof result.occurrence_sha256 !== "string" ||
  typeof result.response_body_base64 !== "string"
) {
  process.exit(26);
}
process.stdout.write("credentialless child completed\n");
