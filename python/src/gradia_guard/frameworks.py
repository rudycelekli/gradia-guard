"""Framework-visible Guard hooks with explicit, conservative claim ceilings."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import threading
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from .core import GuardError, GuardRecorder, Operation, canonical_json

PolicyResolver = Callable[[str, Mapping[str, Any]], Mapping[str, Any]]


class LangChainGuardCallback:
    """A dependency-free LangChain callback protocol implementation.

    LangChain invokes start callbacks before the provider/tool dispatch and end
    callbacks after it. ``raise_error`` stays true so a recorder failure cannot
    silently become an uncovered call. This remains voluntary SDK evidence:
    code can omit the callback or perform direct I/O around it.
    """

    raise_error = True
    run_inline = True
    ignore_llm = False
    ignore_chat_model = False
    ignore_chain = True
    ignore_agent = True
    ignore_retriever = True
    ignore_retry = True
    ignore_custom_event = True

    def __init__(
        self,
        *,
        recorder: GuardRecorder,
        actor_id: str,
        principal_id: str,
        authority_scope_ids: Sequence[str],
        model_identity: Mapping[str, Any],
        tool_identities: Mapping[str, Mapping[str, Any]],
        policy_resolver: PolicyResolver,
    ) -> None:
        self.recorder = recorder
        self.actor_id = actor_id
        self.principal_id = principal_id
        self.authority_scope_ids = tuple(authority_scope_ids)
        self.model_identity = dict(model_identity)
        self.tool_identities = {key: dict(value) for key, value in tool_identities.items()}
        self.policy_resolver = policy_resolver
        self._lock = threading.RLock()
        self._operations: dict[str, Operation] = {}
        self._occurrences: dict[str, str] = {}

    def on_chat_model_start(
        self,
        serialized: Mapping[str, Any],
        messages: Sequence[Sequence[Any]],
        *,
        run_id: Any,
        parent_run_id: Any | None = None,
        **kwargs: Any,
    ) -> None:
        self._begin_model(serialized, messages, run_id, parent_run_id, kwargs)

    def on_llm_start(
        self,
        serialized: Mapping[str, Any],
        prompts: Sequence[str],
        *,
        run_id: Any,
        parent_run_id: Any | None = None,
        **kwargs: Any,
    ) -> None:
        self._begin_model(serialized, prompts, run_id, parent_run_id, kwargs)

    def on_llm_end(self, response: Any, *, run_id: Any, **_: Any) -> None:
        operation = self._take(run_id)
        operation.succeed(
            resolved_identity=self.model_identity,
            output=_evidence_bytes(response),
            output_media_type="application/json",
        )

    def on_llm_error(self, error: BaseException, *, run_id: Any, **_: Any) -> None:
        self._take(run_id).fail(
            failure_code=_error_code(error),
            outcome="decision_failure",
            resolved_identity=self.model_identity,
        )

    def on_tool_start(
        self,
        serialized: Mapping[str, Any],
        input_str: str,
        *,
        run_id: Any,
        parent_run_id: Any | None = None,
        inputs: Mapping[str, Any] | None = None,
        **_: Any,
    ) -> None:
        with self._lock:
            name = _tool_name(serialized)
            identity = self.tool_identities.get(name)
            if identity is None:
                raise GuardError("framework_unregistered_tool_refused")
            run_key = _run_key(run_id)
            self._assert_new(run_key)
            parent_key = _run_key(parent_run_id) if parent_run_id is not None else None
            operation = self.recorder.begin_registered_tool_call(
                actor_id=self.actor_id,
                principal_id=self.principal_id,
                authority_scope_ids=self.authority_scope_ids,
                logical_operation_id=f"langchain.tool.{run_key}",
                attempt_number=1,
                tool_identity=identity,
                tool_request=_evidence_bytes(inputs if inputs is not None else input_str),
                tool_request_media_type="application/json",
                policy=self.policy_resolver("registered_tool_call", identity),
                parent_occurrence_sha256=self._occurrences.get(parent_key) if parent_key else None,
            )
            self._remember(run_key, operation)

    def on_tool_end(self, output: Any, *, run_id: Any, **_: Any) -> None:
        operation = self._take(run_id)
        operation.succeed(
            resolved_identity=operation.requested_identity,
            output=_evidence_bytes(output),
            output_media_type="application/json",
        )

    def on_tool_error(self, error: BaseException, *, run_id: Any, **_: Any) -> None:
        operation = self._take(run_id)
        operation.fail(
            failure_code=_error_code(error),
            outcome="tool_failure",
            resolved_identity=operation.requested_identity,
        )

    async def aon_chat_model_start(self, *args: Any, **kwargs: Any) -> None:
        self.on_chat_model_start(*args, **kwargs)

    async def aon_llm_start(self, *args: Any, **kwargs: Any) -> None:
        self.on_llm_start(*args, **kwargs)

    async def aon_llm_end(self, *args: Any, **kwargs: Any) -> None:
        self.on_llm_end(*args, **kwargs)

    async def aon_llm_error(self, *args: Any, **kwargs: Any) -> None:
        self.on_llm_error(*args, **kwargs)

    async def aon_tool_start(self, *args: Any, **kwargs: Any) -> None:
        self.on_tool_start(*args, **kwargs)

    async def aon_tool_end(self, *args: Any, **kwargs: Any) -> None:
        self.on_tool_end(*args, **kwargs)

    async def aon_tool_error(self, *args: Any, **kwargs: Any) -> None:
        self.on_tool_error(*args, **kwargs)

    def _begin_model(
        self,
        serialized: Mapping[str, Any],
        payload: object,
        run_id: Any,
        parent_run_id: Any | None,
        invocation: Mapping[str, Any],
    ) -> None:
        with self._lock:
            run_key = _run_key(run_id)
            self._assert_new(run_key)
            parent_key = _run_key(parent_run_id) if parent_run_id is not None else None
            operation = self.recorder.begin_application_decision(
                actor_id=self.actor_id,
                principal_id=self.principal_id,
                authority_scope_ids=self.authority_scope_ids,
                logical_operation_id=f"langchain.model.{run_key}",
                attempt_number=1,
                decision_identity=self.model_identity,
                decision_input=_evidence_bytes(
                    {"serialized": serialized, "input": payload, "invocation": invocation}
                ),
                decision_input_media_type="application/json",
                policy=self.policy_resolver("application_decision", self.model_identity),
                parent_occurrence_sha256=self._occurrences.get(parent_key) if parent_key else None,
            )
            self._remember(run_key, operation)

    def _assert_new(self, run_key: str) -> None:
        if run_key in self._operations or run_key in self._occurrences:
            raise GuardError("framework_run_duplicate")

    def _remember(self, run_key: str, operation: Operation) -> None:
        with self._lock:
            self._assert_new(run_key)
            self._operations[run_key] = operation
            self._occurrences[run_key] = operation.occurrence_sha256
            if operation.censored:
                # ``raise_error = True`` asks LangChain to propagate this callback
                # failure before its provider/tool call. The receipt already says
                # dispatch did not occur. If a framework release swallows the
                # exception, that release is not a supported enforcement cell.
                raise GuardError("framework_pre_dispatch_censored")
            operation.mark_dispatched()

    def _take(self, run_id: Any) -> Operation:
        with self._lock:
            run_key = _run_key(run_id)
            operation = self._operations.pop(run_key, None)
            if operation is None:
                raise GuardError("framework_run_not_started")
            if operation.censored:
                raise GuardError("framework_censored_run_dispatched")
            return operation


def _run_key(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:32]


def _tool_name(serialized: Mapping[str, Any]) -> str:
    name = serialized.get("name")
    if not isinstance(name, str) or not name:
        raise GuardError("framework_tool_name_missing")
    return name


def _error_code(error: BaseException) -> str:
    name = error.__class__.__name__.lower()
    safe = re_sub(r"[^a-z0-9_.:]", "_", name)[:120]
    return f"framework_{safe or 'error'}"


def _evidence_bytes(value: object) -> bytes:
    return canonical_json(_normalize(value))


def _normalize(value: object) -> object:
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, bytes):
        return {"byte_length": len(value), "sha256": hashlib.sha256(value).hexdigest()}
    if isinstance(value, Mapping):
        return {str(key): _normalize(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_normalize(item) for item in value]
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _normalize(dataclasses.asdict(value))
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return _normalize(model_dump(mode="json"))
    to_json = getattr(value, "to_json", None)
    if callable(to_json):
        candidate = to_json()
        if isinstance(candidate, str):
            return _normalize(json.loads(candidate))
        return _normalize(candidate)
    raise GuardError(f"framework_payload_not_serializable:{value.__class__.__name__}")


def re_sub(pattern: str, replacement: str, value: str) -> str:
    import re

    return re.sub(pattern, replacement, value)
