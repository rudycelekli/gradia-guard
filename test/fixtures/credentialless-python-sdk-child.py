from __future__ import annotations

import importlib.metadata
import os
import sys

EXPECTED_ENVIRONMENT_NAMES = {
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
}
EXPECTED_PACKAGE_VERSIONS = {
    "anthropic": "0.123.0",
    "google-genai": "2.20.0",
    "openai": "3.3.0",
}


OPERATING_SYSTEM_ADDITIONS = {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"}
unexpected_names = sorted(
    set(os.environ) - EXPECTED_ENVIRONMENT_NAMES - OPERATING_SYSTEM_ADDITIONS
)
if unexpected_names:
    raise SystemExit(21)

for package_name, expected_version in EXPECTED_PACKAGE_VERSIONS.items():
    if importlib.metadata.version(package_name) != expected_version:
        raise SystemExit(22)

provider = sys.argv[1]
resolved_model: str | None = None

if provider in {"openai", "xai"}:
    from openai import OpenAI

    is_openai = provider == "openai"
    client = OpenAI(
        api_key=os.environ["OPENAI_API_KEY" if is_openai else "XAI_API_KEY"],
        base_url=os.environ["OPENAI_BASE_URL" if is_openai else "XAI_BASE_URL"],
        max_retries=0,
        timeout=5.0,
    )
    model = "gpt-5.6-2026-08-01" if is_openai else "grok-4.6"
    response = client.responses.create(model=model, input="case")
    resolved_model = response.model
    client.close()
elif provider == "anthropic":
    from anthropic import Anthropic

    client = Anthropic(
        api_key=os.environ["ANTHROPIC_API_KEY"],
        base_url=os.environ["ANTHROPIC_BASE_URL"],
        max_retries=0,
        timeout=5.0,
    )
    response = client.messages.create(
        model="claude-opus-5-20260801",
        max_tokens=16,
        messages=[{"role": "user", "content": "case"}],
    )
    resolved_model = response.model
    client.close()
elif provider == "gemini":
    # google-genai warns and gives GOOGLE_API_KEY precedence when both aliases
    # exist.  The runtime supplies both because official clients differ; this
    # exact client is bound to the explicit GEMINI capability instead.
    del os.environ["GOOGLE_API_KEY"]
    from google import genai

    client = genai.Client(
        api_key=os.environ["GEMINI_API_KEY"],
        http_options={
            "api_version": "v1beta",
            "base_url": os.environ["GOOGLE_GEMINI_BASE_URL"],
            "timeout": 5_000,
        },
    )
    response = client.models.generate_content(
        model="gemini-4-pro",
        contents="case",
        config={"automatic_function_calling": {"disable": True}},
    )
    resolved_model = response.model_version
    client.close()
else:
    raise SystemExit(23)

if not isinstance(resolved_model, str) or not resolved_model:
    raise SystemExit(24)

print(f"credentialless Python SDK {provider} completed")
