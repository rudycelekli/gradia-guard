from __future__ import annotations

import os
import sys
from importlib import metadata

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
OPERATING_SYSTEM_ADDITIONS = {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"}
EXPECTED_PACKAGE_VERSIONS = {
    "langchain-anthropic": "1.7.0",
    "langchain-core": "1.6.1",
    "langchain-google-genai": "4.3.7",
    "langchain-openai": "1.6.0",
    "langchain-xai": "1.3.0",
}


unexpected_names = sorted(
    set(os.environ) - EXPECTED_ENVIRONMENT_NAMES - OPERATING_SYSTEM_ADDITIONS
)
if unexpected_names:
    raise SystemExit(21)

for package_name, expected_version in EXPECTED_PACKAGE_VERSIONS.items():
    if metadata.version(package_name) != expected_version:
        raise SystemExit(22)

provider = sys.argv[1]

if provider == "anthropic":
    from langchain_anthropic import ChatAnthropic

    model = ChatAnthropic(
        model_name="claude-opus-5-20260801",
        api_key=os.environ["ANTHROPIC_API_KEY"],
        base_url=os.environ["ANTHROPIC_BASE_URL"],
        max_retries=0,
        max_tokens_to_sample=16,
        timeout=5.0,
    )
elif provider == "gemini":
    del os.environ["GOOGLE_API_KEY"]
    from langchain_google_genai import ChatGoogleGenerativeAI

    model = ChatGoogleGenerativeAI(
        model="gemini-4-pro",
        api_key=os.environ["GEMINI_API_KEY"],
        base_url=os.environ["GOOGLE_GEMINI_BASE_URL"],
        api_version="v1beta",
        retries=0,
        request_timeout=5.0,
        max_tokens=16,
    )
elif provider == "openai":
    from langchain_openai import ChatOpenAI

    model = ChatOpenAI(
        model="gpt-5.6-2026-08-01",
        api_key=os.environ["OPENAI_API_KEY"],
        base_url=os.environ["OPENAI_BASE_URL"],
        max_retries=0,
        timeout=5.0,
        max_completion_tokens=16,
        use_responses_api=True,
    )
elif provider == "xai":
    from langchain_xai import ChatXAI

    model = ChatXAI(
        model="grok-4.6",
        api_key=os.environ["XAI_API_KEY"],
        base_url=os.environ["XAI_BASE_URL"],
        max_retries=0,
        timeout=5.0,
        max_tokens=16,
        use_responses_api=True,
    )
else:
    raise SystemExit(23)

response = model.invoke("case")
if response.text != "ok":
    raise SystemExit(24)

print(f"credentialless LangChain {provider} completed")
