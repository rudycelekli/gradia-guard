from __future__ import annotations

import contextlib
import io
import json
import os
import sys
from importlib import metadata

CASES = {
    "anthropic": {
        "model": "claude-opus-5-20260801",
        "base_name": "ANTHROPIC_BASE_URL",
        "key_name": "ANTHROPIC_API_KEY",
        "package": "langchain-anthropic",
        "package_version": "1.7.0",
        "route_id": "anthropic.messages",
    },
    "gemini": {
        "model": "gemini-4-pro",
        "base_name": "GOOGLE_GEMINI_BASE_URL",
        "key_name": "GEMINI_API_KEY",
        "package": "langchain-google-genai",
        "package_version": "4.3.7",
        "route_id": "gemini.generateContent",
    },
    "openai": {
        "model": "gpt-5.6-2026-08-01",
        "base_name": "OPENAI_BASE_URL",
        "key_name": "OPENAI_API_KEY",
        "package": "langchain-openai",
        "package_version": "1.6.0",
        "route_id": "openai.responses",
    },
    "xai": {
        "model": "grok-4.6",
        "base_name": "XAI_BASE_URL",
        "key_name": "XAI_API_KEY",
        "package": "langchain-xai",
        "package_version": "1.3.0",
        "route_id": "xai.responses",
    },
}
EXPECTED_PACKAGE_VERSIONS = {
    "langchain-anthropic": "1.7.0",
    "langchain-core": "1.6.1",
    "langchain-google-genai": "4.3.7",
    "langchain-openai": "1.6.0",
    "langchain-xai": "1.3.0",
}


provider = sys.argv[1] if len(sys.argv) == 2 else None
candidate = CASES.get(provider)
if candidate is None:
    raise SystemExit(23)

for name in (
    "GRADIA_GUARD_LOCAL_CAPABILITY",
    "GRADIA_GUARD_LOCAL_ORIGIN",
    "GRADIA_GUARD_RUNTIME_ID",
    candidate["base_name"],
    candidate["key_name"],
):
    if not os.environ.get(name):
        raise SystemExit(21)
if os.environ[candidate["key_name"]] != os.environ["GRADIA_GUARD_LOCAL_CAPABILITY"]:
    raise SystemExit(22)

origin = os.environ["GRADIA_GUARD_LOCAL_ORIGIN"]
expected_bases = {
    "anthropic": f"{origin}/anthropic",
    "gemini": f"{origin}/gemini",
    "openai": f"{origin}/openai/v1",
    "xai": f"{origin}/xai/v1",
}
if os.environ[candidate["base_name"]] != expected_bases[provider]:
    raise SystemExit(24)
for package_name, version in EXPECTED_PACKAGE_VERSIONS.items():
    if metadata.version(package_name) != version:
        raise SystemExit(25)

captured_stderr = io.StringIO()
with contextlib.redirect_stderr(captured_stderr):
    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        model = ChatAnthropic(
            model_name=candidate["model"],
            api_key=os.environ["ANTHROPIC_API_KEY"],
            base_url=os.environ["ANTHROPIC_BASE_URL"],
            max_retries=0,
            max_tokens_to_sample=16,
            timeout=5.0,
        )
    elif provider == "gemini":
        os.environ.pop("GOOGLE_API_KEY", None)
        from langchain_google_genai import ChatGoogleGenerativeAI

        model = ChatGoogleGenerativeAI(
            model=candidate["model"],
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
            model=candidate["model"],
            api_key=os.environ["OPENAI_API_KEY"],
            base_url=os.environ["OPENAI_BASE_URL"],
            max_retries=0,
            timeout=5.0,
            max_completion_tokens=16,
            use_responses_api=True,
        )
    else:
        from langchain_xai import ChatXAI

        model = ChatXAI(
            model=candidate["model"],
            api_key=os.environ["XAI_API_KEY"],
            base_url=os.environ["XAI_BASE_URL"],
            max_retries=0,
            timeout=5.0,
            max_tokens=16,
            use_responses_api=True,
        )
    response = model.invoke("case")

diagnostic = captured_stderr.getvalue().strip()
if diagnostic and not (
    provider == "gemini"
    and diagnostic.startswith("Direct use of automatic function calling (AFC)")
):
    raise SystemExit(26)
if response.text != "ok":
    raise SystemExit(27)

print(
    json.dumps(
        {
            "schema_version": "gradia.guard.container-sdk-probe-output.v1",
            "runtime_id": os.environ["GRADIA_GUARD_RUNTIME_ID"],
            "framework": "langchain",
            "provider": provider,
            "framework_core_package": "langchain-core",
            "framework_core_version": metadata.version("langchain-core"),
            "provider_package": candidate["package"],
            "provider_package_version": candidate["package_version"],
            "route_id": candidate["route_id"],
            "requested_model": candidate["model"],
            "response_text": "ok",
        },
        separators=(",", ":"),
        sort_keys=True,
    )
)
