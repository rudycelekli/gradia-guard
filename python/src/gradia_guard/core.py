"""Dependency-free G2 evidence recorder for the Python Guard beta candidate.

The emitted bytes intentionally match ``@gradia/guard``'s
``gradia.guard.sdk-bundle.v1`` ABI.  This module is a recorder, not an
authority: identity, policy, actor and state-root fields are application
declarations, and uninstrumented I/O remains invisible.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

GUARD_ABI_VERSION = "0.1.0"
GENESIS_SHA256 = hashlib.sha256(b"").hexdigest()
SDK_FRAME_SCHEMA_VERSION = "gradia.guard.sdk-frame.v1"
SDK_BUNDLE_SCHEMA_VERSION = "gradia.guard.sdk-bundle.v1"

_STABLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
_PORTABLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UNPINNED = re.compile(r"(?:^|[._:/-])(?:latest|current|default|auto)(?:$|[._:/-])", re.I)
_MEDIA_TYPE = re.compile(r"^[\x20-\x7e]{1,200}$")
_FORBIDDEN_KEY = re.compile(
    r"(?:^|[_-])(api[_-]?key|authorization|bearer|cookie|credential|password|"
    r"private[_-]?key|secret|session[_-]?token|token)(?:$|[_-])",
    re.I,
)
_PRIVATE_REASONING_KEY = re.compile(
    r"(?:^|[_-])(chain[_-]?of[_-]?thought|hidden[_-]?reasoning|private[_-]?reasoning|"
    r"reasoning|scratchpad|thoughts?)(?:$|[_-])",
    re.I,
)

SDK_COVERAGE: dict[str, Any] = {
    "schema_version": "gradia.guard.coverage.v1",
    "tier": "sdk",
    "observed_surfaces": [
        "application.state_root.identity",
        "decision.identity",
        "decision.input",
        "decision.output",
        "policy.receipt",
        "tool.identity",
        "tool.request",
        "tool.result",
    ],
    "unobserved_surfaces": [
        "agent.internal_state",
        "calls.outside_sdk",
        "credential.values",
        "filesystem.effects",
        "model.gateway_wire",
        "network.effects",
        "subprocess.lifecycle",
        "tool.unregistered_direct_io",
        "world.root",
    ],
    "isolation_enforced": False,
    "visibility_boundary_enforced": False,
    "full_world_capture": False,
}


class GuardError(ValueError):
    """A fail-closed recorder or verifier error with a stable reason code."""


class IdentityMismatchError(GuardError):
    """The resolved executor/tool identity differs from the requested pin."""

    def __init__(self, frame: Mapping[str, Any]) -> None:
        super().__init__("sdk_resolved_identity_mismatch")
        self.frame = dict(frame)


def canonical_json(value: object) -> bytes:
    """Return the shared compact, sorted UTF-8 JSON representation."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def digest_canonical(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _now_iso() -> str:
    instant = datetime.now(UTC)
    milliseconds = instant.microsecond // 1000
    return instant.replace(microsecond=milliseconds * 1000).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _stable_id(value: str, field: str) -> str:
    if not isinstance(value, str) or _STABLE_ID.fullmatch(value) is None:
        raise GuardError(f"{field}_invalid")
    return value


def _sha256(value: str, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise GuardError(f"{field}_invalid")
    return value


def _exact_version(value: str, field: str) -> str:
    if (
        not isinstance(value, str)
        or _PORTABLE_ID.fullmatch(value) is None
        or not any(character.isdigit() for character in value)
        or _UNPINNED.search(value) is not None
    ):
        raise GuardError(f"{field}_not_exact_pin")
    return value


def _canonical_ids(values: Iterable[str], field: str) -> list[str]:
    result = list(values)
    if not result or result != sorted(set(result)):
        raise GuardError(f"{field}_not_canonical")
    for value in result:
        _stable_id(value, field.removesuffix("s"))
    return result


def _assert_safe(value: object, path: str = "$") -> None:
    if value is None or isinstance(value, bool | int | float | str):
        return
    if isinstance(value, list | tuple):
        for index, item in enumerate(value):
            _assert_safe(item, f"{path}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise GuardError(f"evidence_unsupported_key:{path}")
            if _FORBIDDEN_KEY.search(key):
                raise GuardError(f"evidence_secret_shape_refused:{path}.{key}")
            if _PRIVATE_REASONING_KEY.search(key):
                raise GuardError(f"evidence_private_reasoning_refused:{path}.{key}")
            _assert_safe(item, f"{path}.{key}")
        return
    raise GuardError(f"evidence_unsupported_type:{path}")


def decision_identity(
    *,
    decision_type: str,
    executor_kind: Literal["model", "component", "human"],
    executor_id: str,
    executor_version: str,
    contract_sha256: str,
) -> dict[str, Any]:
    _stable_id(decision_type, "sdk_decision_type")
    if executor_kind not in {"model", "component", "human"}:
        raise GuardError("sdk_decision_executor_kind_invalid")
    if _PORTABLE_ID.fullmatch(executor_id) is None:
        raise GuardError("sdk_decision_executor_id_invalid")
    _exact_version(executor_version, "sdk_decision_executor_version")
    _sha256(contract_sha256, "sdk_decision_contract_digest")
    return {
        "schema_version": "gradia.guard.sdk-decision-identity.v1",
        "decision_type": decision_type,
        "executor_kind": executor_kind,
        "executor_id": executor_id,
        "executor_version": executor_version,
        "contract_sha256": contract_sha256,
    }


def tool_identity(
    *, registry_id: str, tool_id: str, tool_version: str, interface_sha256: str
) -> dict[str, Any]:
    _stable_id(registry_id, "sdk_tool_registry_id")
    if _PORTABLE_ID.fullmatch(tool_id) is None:
        raise GuardError("sdk_tool_id_invalid")
    _exact_version(tool_version, "sdk_tool_version")
    _sha256(interface_sha256, "sdk_tool_interface_digest")
    return {
        "schema_version": "gradia.guard.sdk-tool-identity.v1",
        "registry_id": registry_id,
        "tool_id": tool_id,
        "tool_version": tool_version,
        "interface_sha256": interface_sha256,
    }


def state_root(*, namespace_id: str, root_sha256: str) -> dict[str, Any]:
    _stable_id(namespace_id, "sdk_state_root_namespace_id")
    _sha256(root_sha256, "sdk_state_root_digest")
    return {
        "schema_version": "gradia.guard.sdk-state-root.v1",
        "source": "application_declared",
        "namespace_id": namespace_id,
        "root_sha256": root_sha256,
    }


def allowed_policy(policy_sha256: str, *reason_codes: str) -> dict[str, Any]:
    _sha256(policy_sha256, "sdk_policy_digest")
    reasons = _canonical_ids(reason_codes or ("allowed",), "sdk_policy_reason_codes")
    return {
        "decision": "allowed",
        "censor_kind": None,
        "reason_codes": reasons,
        "policy_sha256": policy_sha256,
    }


def blocked_policy(
    policy_sha256: str,
    *,
    censor_kind: Literal["policy", "budget", "authority"],
    reason_codes: Iterable[str],
) -> dict[str, Any]:
    _sha256(policy_sha256, "sdk_policy_digest")
    if censor_kind not in {"policy", "budget", "authority"}:
        raise GuardError("sdk_blocked_policy_censor_missing")
    return {
        "decision": "blocked",
        "censor_kind": censor_kind,
        "reason_codes": _canonical_ids(reason_codes, "sdk_policy_reason_codes"),
        "policy_sha256": policy_sha256,
    }


def content_reference(content: bytes, media_type: str) -> dict[str, Any]:
    if not isinstance(content, bytes) or not content:
        raise GuardError("sdk_content_bytes_missing")
    if not isinstance(media_type, str) or _MEDIA_TYPE.fullmatch(media_type) is None:
        raise GuardError("sdk_content_media_type_invalid")
    return {
        "schema_version": "gradia.guard.content-ref.v1",
        "media_type": media_type,
        "byte_length": len(content),
        "plaintext_sha256": hashlib.sha256(content).hexdigest(),
        "storage": "digest-only",
        "ciphertext_ref": None,
        "ciphertext_sha256": None,
        "key_id": None,
    }


class Operation:
    """One pre-dispatch decision paired with exactly one terminal action."""

    def __init__(self, recorder: GuardRecorder, decision: dict[str, Any], censored: bool) -> None:
        self._recorder = recorder
        self._decision = decision
        self._closed = censored
        self._dispatch_started_at: str | None = None
        self._dispatch_monotonic: float | None = None

    @property
    def occurrence_sha256(self) -> str:
        return str(self._decision["occurrence_sha256"])

    @property
    def requested_identity(self) -> dict[str, Any]:
        key = "decision_identity" if self._decision["operation_kind"] == "application_decision" else "tool_identity"
        return dict(self._decision[key])

    @property
    def censored(self) -> bool:
        return self._closed and self._dispatch_started_at is None

    def mark_dispatched(self) -> None:
        with self._recorder._lock:  # noqa: SLF001 - paired internal object
            if self._closed:
                raise GuardError("sdk_censored_operation_cannot_dispatch")
            if self._dispatch_started_at is not None:
                raise GuardError("sdk_operation_already_dispatched")
            self._dispatch_started_at = self._recorder.wall_time()
            self._dispatch_monotonic = self._recorder.monotonic_time()

    def succeed(
        self,
        *,
        resolved_identity: Mapping[str, Any],
        output: bytes,
        output_media_type: str,
        state_root_after: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self._recorder._lock:  # noqa: SLF001 - paired internal object
            identity_match = canonical_json(resolved_identity) == canonical_json(self.requested_identity)
            terminal = self._terminal()
            action = self._recorder._close_operation(  # noqa: SLF001 - paired internal object
                self._decision,
                outcome="success" if identity_match else "identity_mismatch",
                resolved_identity=dict(resolved_identity),
                output=content_reference(output, output_media_type),
                state_root_after=dict(state_root_after) if state_root_after is not None else None,
                failure_code=None if identity_match else "resolved_operation_identity_mismatch",
                **terminal,
            )
        if not identity_match:
            raise IdentityMismatchError(action)
        return action

    def fail(
        self,
        *,
        failure_code: str,
        outcome: Literal["decision_failure", "tool_failure", "protocol_failure"] | None = None,
        resolved_identity: Mapping[str, Any] | None = None,
        output: bytes | None = None,
        output_media_type: str | None = None,
        state_root_after: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self._recorder._lock:  # noqa: SLF001 - paired internal object
            _stable_id(failure_code, "sdk_failure_code")
            expected = "decision_failure" if self._decision["operation_kind"] == "application_decision" else "tool_failure"
            chosen = outcome or expected
            if chosen not in {expected, "protocol_failure"}:
                raise GuardError("sdk_failure_outcome_invalid")
            if (output is None) != (output_media_type is None):
                raise GuardError("sdk_failure_output_partial")
            resolved = dict(resolved_identity) if resolved_identity is not None else None
            identity_match = resolved is None or canonical_json(resolved) == canonical_json(self.requested_identity)
            terminal = self._terminal()
            action = self._recorder._close_operation(  # noqa: SLF001 - paired internal object
                self._decision,
                outcome=chosen if identity_match else "identity_mismatch",
                resolved_identity=resolved,
                output=(content_reference(output, output_media_type) if output is not None and output_media_type else None),
                state_root_after=dict(state_root_after) if state_root_after is not None else None,
                failure_code=failure_code if identity_match else "resolved_operation_identity_mismatch",
                **terminal,
            )
        if not identity_match:
            raise IdentityMismatchError(action)
        return action

    def _terminal(self) -> dict[str, Any]:
        if self._closed:
            raise GuardError("sdk_operation_already_closed")
        if self._dispatch_started_at is None or self._dispatch_monotonic is None:
            raise GuardError("sdk_operation_not_marked_dispatched")
        self._closed = True
        terminal_observed_at = self._recorder.wall_time()
        return {
            "dispatch_occurred": True,
            "dispatch_started_at": self._dispatch_started_at,
            "terminal_observed_at": terminal_observed_at,
            "latency_ms": max(0, round((self._recorder.monotonic_time() - self._dispatch_monotonic) * 1000)),
        }


class GuardRecorder:
    """Append-only, digest-only G2 recorder with atomic manifest updates."""

    def __init__(
        self,
        directory: str | os.PathLike[str],
        *,
        session_id: str | None = None,
        now: Callable[[], str] | None = None,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        self.directory = Path(directory).resolve()
        if self.directory.exists():
            raise GuardError("sdk_bundle_directory_exists")
        self.directory.mkdir(parents=True, mode=0o700)
        self.frames_path = self.directory / "frames.ndjson"
        self.manifest_path = self.directory / "bundle.json"
        self.frames_path.touch(mode=0o600, exist_ok=False)
        self._now = now or _now_iso
        self._monotonic = monotonic or time.monotonic
        self._lock = threading.RLock()
        self.session_id = _stable_id(session_id or str(uuid.uuid4()).replace("-", ":"), "session_id")
        self._head = GENESIS_SHA256
        self._sequence = 0
        self._operation_count = 0
        self._open_operations = 0
        self._known_occurrences: set[str] = set()
        self._logical_occurrences: dict[str, dict[int, dict[str, Any]]] = {}
        self.manifest: dict[str, Any] = {
            "schema_version": SDK_BUNDLE_SCHEMA_VERSION,
            "guard_version": GUARD_ABI_VERSION,
            "session_id": self.session_id,
            "created_at": self.wall_time(),
            "finalized_at": None,
            "status": "recording",
            "capture_mode": "digest-only",
            "coverage": dict(SDK_COVERAGE),
            "capture_boundary": "explicit_sdk",
            "bypass_possible": True,
            "bypass_declaration": "uninstrumented_or_direct_io_is_not_observed",
            "frame_count": 0,
            "operation_count": 0,
            "chain_head_sha256": GENESIS_SHA256,
        }
        self._write_manifest()

    def wall_time(self) -> str:
        value = self._now()
        if not isinstance(value, str):
            raise GuardError("sdk_wall_clock_invalid")
        return value

    def monotonic_time(self) -> float:
        value = self._monotonic()
        if not isinstance(value, int | float) or value < 0:
            raise GuardError("sdk_monotonic_clock_invalid")
        return float(value)

    def begin_application_decision(
        self,
        *,
        actor_id: str,
        principal_id: str,
        authority_scope_ids: Iterable[str],
        logical_operation_id: str,
        attempt_number: int,
        decision_identity: Mapping[str, Any],
        decision_input: bytes,
        decision_input_media_type: str,
        policy: Mapping[str, Any],
        retry_of_occurrence_sha256: str | None = None,
        parent_occurrence_sha256: str | None = None,
        state_root_before: Mapping[str, Any] | None = None,
    ) -> Operation:
        with self._lock:
            return self._begin(
                operation_kind="application_decision",
                actor_id=actor_id,
                principal_id=principal_id,
                authority_scope_ids=authority_scope_ids,
                logical_operation_id=logical_operation_id,
                attempt_number=attempt_number,
                identity=dict(decision_identity),
                input_ref=content_reference(decision_input, decision_input_media_type),
                policy=dict(policy),
                retry_of_occurrence_sha256=retry_of_occurrence_sha256,
                parent_occurrence_sha256=parent_occurrence_sha256,
                state_root_before=dict(state_root_before) if state_root_before is not None else None,
            )

    def begin_registered_tool_call(
        self,
        *,
        actor_id: str,
        principal_id: str,
        authority_scope_ids: Iterable[str],
        logical_operation_id: str,
        attempt_number: int,
        tool_identity: Mapping[str, Any],
        tool_request: bytes,
        tool_request_media_type: str,
        policy: Mapping[str, Any],
        retry_of_occurrence_sha256: str | None = None,
        parent_occurrence_sha256: str | None = None,
        state_root_before: Mapping[str, Any] | None = None,
    ) -> Operation:
        with self._lock:
            return self._begin(
                operation_kind="registered_tool_call",
                actor_id=actor_id,
                principal_id=principal_id,
                authority_scope_ids=authority_scope_ids,
                logical_operation_id=logical_operation_id,
                attempt_number=attempt_number,
                identity=dict(tool_identity),
                input_ref=content_reference(tool_request, tool_request_media_type),
                policy=dict(policy),
                retry_of_occurrence_sha256=retry_of_occurrence_sha256,
                parent_occurrence_sha256=parent_occurrence_sha256,
                state_root_before=dict(state_root_before) if state_root_before is not None else None,
            )

    def finalize(self) -> None:
        with self._lock:
            if self.manifest["status"] == "finalized":
                return
            if self._open_operations:
                raise GuardError("sdk_open_operations_prevent_finalization")
            if not self._operation_count:
                raise GuardError("sdk_empty_bundle_cannot_finalize")
            self.manifest["status"] = "finalized"
            self.manifest["finalized_at"] = self.wall_time()
            self._write_manifest()

    def _begin(
        self,
        *,
        operation_kind: Literal["application_decision", "registered_tool_call"],
        actor_id: str,
        principal_id: str,
        authority_scope_ids: Iterable[str],
        logical_operation_id: str,
        attempt_number: int,
        identity: dict[str, Any],
        input_ref: dict[str, Any],
        policy: dict[str, Any],
        retry_of_occurrence_sha256: str | None,
        parent_occurrence_sha256: str | None,
        state_root_before: dict[str, Any] | None,
    ) -> Operation:
        if self.manifest["status"] != "recording":
            raise GuardError("sdk_recorder_finalized")
        actor_id = _stable_id(actor_id, "actor_id")
        principal_id = _stable_id(principal_id, "principal_id")
        scopes = _canonical_ids(authority_scope_ids, "authority_scope_ids")
        logical_operation_id = _stable_id(logical_operation_id, "logical_operation_id")
        if not isinstance(attempt_number, int) or isinstance(attempt_number, bool) or attempt_number < 1:
            raise GuardError("sdk_attempt_number_invalid")
        if attempt_number == 1 and retry_of_occurrence_sha256 is not None:
            raise GuardError("sdk_first_attempt_has_retry_parent")
        if attempt_number > 1:
            _sha256(str(retry_of_occurrence_sha256), "sdk_retry_parent")
        if parent_occurrence_sha256 is not None:
            _sha256(parent_occurrence_sha256, "sdk_parent_occurrence")
            if parent_occurrence_sha256 not in self._known_occurrences:
                raise GuardError("sdk_parent_occurrence_not_recorded")
        _assert_identity(identity, operation_kind)
        if state_root_before is not None:
            _assert_state_root(state_root_before)
        policy = _assert_policy_input(policy)
        occurrence_body = {
            "schema_version": "gradia.guard.sdk-occurrence.v1",
            "operation_kind": operation_kind,
            "actor_id": actor_id,
            "principal_id": principal_id,
            "authority_scope_ids": scopes,
            "logical_operation_id": logical_operation_id,
            "attempt_number": attempt_number,
            "retry_of_occurrence_sha256": retry_of_occurrence_sha256,
            "parent_occurrence_sha256": parent_occurrence_sha256,
            "state_root_before": state_root_before,
            "identity": identity,
            "input_sha256": input_ref["plaintext_sha256"],
        }
        occurrence_sha256 = digest_canonical(occurrence_body)
        attempts = self._logical_occurrences.setdefault(logical_operation_id, {})
        if attempt_number in attempts:
            raise GuardError("sdk_logical_attempt_duplicate")
        if attempt_number > 1:
            predecessor = attempts.get(attempt_number - 1)
            if predecessor is None or predecessor["occurrence_sha256"] != retry_of_occurrence_sha256:
                raise GuardError("sdk_retry_parent_not_recorded")
            if not _retry_context_matches(predecessor, operation_kind, actor_id, principal_id, scopes, identity):
                raise GuardError("sdk_retry_identity_context_mismatch")
        evaluated_at = self.wall_time()
        policy_body = {
            "schema_version": "gradia.guard.sdk-policy-receipt.v1",
            "operation_kind": operation_kind,
            "occurrence_sha256": occurrence_sha256,
            "actor_id": actor_id,
            "principal_id": principal_id,
            "authority_scope_ids": scopes,
            "decision": policy["decision"],
            "censor_kind": policy["censor_kind"],
            "reason_codes": policy["reason_codes"],
            "policy_sha256": policy["policy_sha256"],
            "evaluated_at": evaluated_at,
        }
        policy_receipt = {**policy_body, "receipt_sha256": digest_canonical(policy_body)}
        specific = (
            {"decision_identity": identity, "decision_input": input_ref}
            if operation_kind == "application_decision"
            else {"tool_identity": identity, "tool_request": input_ref}
        )
        decision = self._frame(
            frame_kind="decision",
            operation_kind=operation_kind,
            actor_id=actor_id,
            principal_id=principal_id,
            authority_scope_ids=scopes,
            logical_operation_id=logical_operation_id,
            attempt_number=attempt_number,
            retry_of_occurrence_sha256=retry_of_occurrence_sha256,
            parent_occurrence_sha256=parent_occurrence_sha256,
            occurrence_sha256=occurrence_sha256,
            state_root_before=state_root_before,
            policy=policy_receipt,
            **specific,
        )
        self._append(decision)
        attempts[attempt_number] = decision
        self._known_occurrences.add(occurrence_sha256)
        censored = policy["decision"] == "blocked"
        if censored:
            censor_kind = str(policy["censor_kind"])
            outcome = "budget_censored" if censor_kind == "budget" else "authority_censored" if censor_kind == "authority" else "policy_censored"
            failure_code = str(policy["reason_codes"][0])
            self._close_operation(
                decision,
                outcome=outcome,
                dispatch_occurred=False,
                resolved_identity=None,
                output=None,
                state_root_after=state_root_before,
                dispatch_started_at=None,
                terminal_observed_at=None,
                latency_ms=None,
                failure_code=failure_code,
            )
        else:
            self._open_operations += 1
        return Operation(self, decision, censored)

    def _close_operation(
        self,
        decision: dict[str, Any],
        *,
        outcome: str,
        dispatch_occurred: bool,
        resolved_identity: dict[str, Any] | None,
        output: dict[str, Any] | None,
        state_root_after: dict[str, Any] | None,
        dispatch_started_at: str | None,
        terminal_observed_at: str | None,
        latency_ms: int | None,
        failure_code: str | None,
    ) -> dict[str, Any]:
        operation_kind = str(decision["operation_kind"])
        identity_key = "decision_identity" if operation_kind == "application_decision" else "tool_identity"
        input_key = "decision_input" if operation_kind == "application_decision" else "tool_request"
        resolved_key = "resolved_decision_identity" if operation_kind == "application_decision" else "resolved_tool_identity"
        output_key = "decision_output" if operation_kind == "application_decision" else "tool_result"
        action = self._frame(
            frame_kind="action",
            operation_kind=operation_kind,
            actor_id=decision["actor_id"],
            principal_id=decision["principal_id"],
            authority_scope_ids=decision["authority_scope_ids"],
            logical_operation_id=decision["logical_operation_id"],
            attempt_number=decision["attempt_number"],
            retry_of_occurrence_sha256=decision["retry_of_occurrence_sha256"],
            parent_occurrence_sha256=decision["parent_occurrence_sha256"],
            occurrence_sha256=decision["occurrence_sha256"],
            state_root_before=decision["state_root_before"],
            policy_receipt_sha256=decision["policy"]["receipt_sha256"],
            outcome=outcome,
            dispatch_occurred=dispatch_occurred,
            state_root_after=state_root_after,
            dispatch_started_at=dispatch_started_at,
            terminal_observed_at=terminal_observed_at,
            latency_ms=latency_ms,
            failure_code=failure_code,
            **{
                identity_key: decision[identity_key],
                resolved_key: resolved_identity,
                input_key: decision[input_key],
                output_key: output,
            },
        )
        self._append(action)
        if dispatch_occurred:
            if self._open_operations < 1:
                raise GuardError("sdk_open_operation_accounting_invalid")
            self._open_operations -= 1
        self._operation_count += 1
        self.manifest["operation_count"] = self._operation_count
        self._write_manifest()
        return action

    def _frame(self, **body: Any) -> dict[str, Any]:
        frame_body = {
            "schema_version": SDK_FRAME_SCHEMA_VERSION,
            "session_id": self.session_id,
            "sequence": self._sequence,
            "observed_at": self.wall_time(),
            "coverage": dict(SDK_COVERAGE),
            **body,
            "previous_frame_sha256": self._head,
        }
        _assert_safe(frame_body)
        return {**frame_body, "frame_sha256": digest_canonical(frame_body)}

    def _append(self, frame: dict[str, Any]) -> None:
        if frame["sequence"] != self._sequence or frame["previous_frame_sha256"] != self._head:
            raise GuardError("sdk_spool_chain_mismatch")
        with self.frames_path.open("ab") as stream:
            stream.write(canonical_json(frame) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        self._sequence += 1
        self._head = str(frame["frame_sha256"])
        self.manifest["frame_count"] = self._sequence
        self.manifest["chain_head_sha256"] = self._head
        self._write_manifest()

    def _write_manifest(self) -> None:
        temporary = self.manifest_path.with_suffix(".json.tmp")
        with temporary.open("xb") as stream:
            os.chmod(temporary, 0o600)
            stream.write(canonical_json(self.manifest) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.manifest_path)


def _assert_identity(identity: Mapping[str, Any], operation_kind: str) -> None:
    if operation_kind == "application_decision":
        expected = {
            "schema_version",
            "decision_type",
            "executor_kind",
            "executor_id",
            "executor_version",
            "contract_sha256",
        }
        if set(identity) != expected or identity.get("schema_version") != "gradia.guard.sdk-decision-identity.v1":
            raise GuardError("sdk_decision_identity_invalid")
        decision_identity(
            decision_type=str(identity["decision_type"]),
            executor_kind=identity["executor_kind"],
            executor_id=str(identity["executor_id"]),
            executor_version=str(identity["executor_version"]),
            contract_sha256=str(identity["contract_sha256"]),
        )
        return
    expected = {"schema_version", "registry_id", "tool_id", "tool_version", "interface_sha256"}
    if set(identity) != expected or identity.get("schema_version") != "gradia.guard.sdk-tool-identity.v1":
        raise GuardError("sdk_tool_identity_invalid")
    tool_identity(
        registry_id=str(identity["registry_id"]),
        tool_id=str(identity["tool_id"]),
        tool_version=str(identity["tool_version"]),
        interface_sha256=str(identity["interface_sha256"]),
    )


def _assert_state_root(value: Mapping[str, Any]) -> None:
    expected = {"schema_version", "source", "namespace_id", "root_sha256"}
    if set(value) != expected or value.get("schema_version") != "gradia.guard.sdk-state-root.v1" or value.get("source") != "application_declared":
        raise GuardError("sdk_state_root_invalid")
    state_root(namespace_id=str(value["namespace_id"]), root_sha256=str(value["root_sha256"]))


def _assert_policy_input(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = {"decision", "censor_kind", "reason_codes", "policy_sha256"}
    if set(value) != expected:
        raise GuardError("sdk_policy_input_invalid")
    decision = value["decision"]
    censor = value["censor_kind"]
    if decision == "allowed" and censor is not None:
        raise GuardError("sdk_allowed_policy_has_censor")
    if decision == "blocked" and censor not in {"policy", "budget", "authority"}:
        raise GuardError("sdk_blocked_policy_censor_missing")
    if decision not in {"allowed", "blocked"}:
        raise GuardError("sdk_policy_decision_invalid")
    return {
        "decision": decision,
        "censor_kind": censor,
        "reason_codes": _canonical_ids(value["reason_codes"], "sdk_policy_reason_codes"),
        "policy_sha256": _sha256(str(value["policy_sha256"]), "sdk_policy_digest"),
    }


def _retry_context_matches(
    predecessor: Mapping[str, Any],
    operation_kind: str,
    actor_id: str,
    principal_id: str,
    scopes: list[str],
    identity: Mapping[str, Any],
) -> bool:
    identity_key = "decision_identity" if operation_kind == "application_decision" else "tool_identity"
    return all(
        (
            predecessor["operation_kind"] == operation_kind,
            predecessor["actor_id"] == actor_id,
            predecessor["principal_id"] == principal_id,
            predecessor["authority_scope_ids"] == scopes,
            canonical_json(predecessor[identity_key]) == canonical_json(identity),
        )
    )
