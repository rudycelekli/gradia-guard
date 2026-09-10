"""Independent, dependency-free verification of Guard G2 SDK bundles."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .core import (
    GENESIS_SHA256,
    SDK_BUNDLE_SCHEMA_VERSION,
    SDK_COVERAGE,
    SDK_FRAME_SCHEMA_VERSION,
    canonical_json,
    digest_canonical,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_STABLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
_PORTABLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
_ISO_MILLIS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")
_UNPINNED = re.compile(r"(?:^|[._:/-])(?:latest|current|default|auto)(?:$|[._:/-])", re.I)
_MEDIA_TYPE = re.compile(r"^[\x20-\x7e]{1,200}$")

_MANIFEST_KEYS = {
    "schema_version",
    "guard_version",
    "session_id",
    "created_at",
    "finalized_at",
    "status",
    "capture_mode",
    "coverage",
    "capture_boundary",
    "bypass_possible",
    "bypass_declaration",
    "frame_count",
    "operation_count",
    "chain_head_sha256",
}
_FRAME_COMMON = {
    "schema_version",
    "session_id",
    "sequence",
    "frame_kind",
    "operation_kind",
    "observed_at",
    "coverage",
    "actor_id",
    "principal_id",
    "authority_scope_ids",
    "logical_operation_id",
    "attempt_number",
    "retry_of_occurrence_sha256",
    "parent_occurrence_sha256",
    "occurrence_sha256",
    "state_root_before",
    "previous_frame_sha256",
    "frame_sha256",
}
_FRAME_SPECIFIC = {
    ("decision", "application_decision"): {"decision_identity", "decision_input", "policy"},
    ("decision", "registered_tool_call"): {"tool_identity", "tool_request", "policy"},
    ("action", "application_decision"): {
        "decision_identity",
        "resolved_decision_identity",
        "decision_input",
        "decision_output",
        "policy_receipt_sha256",
        "outcome",
        "dispatch_occurred",
        "state_root_after",
        "dispatch_started_at",
        "terminal_observed_at",
        "latency_ms",
        "failure_code",
    },
    ("action", "registered_tool_call"): {
        "tool_identity",
        "resolved_tool_identity",
        "tool_request",
        "tool_result",
        "policy_receipt_sha256",
        "outcome",
        "dispatch_occurred",
        "state_root_after",
        "dispatch_started_at",
        "terminal_observed_at",
        "latency_ms",
        "failure_code",
    },
}


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    blockers: tuple[str, ...]
    session_id: str | None
    frame_count: int
    chain_head_sha256: str | None
    payloads_checked: int
    payloads_unavailable: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "blockers": list(self.blockers),
            "session_id": self.session_id,
            "frame_count": self.frame_count,
            "chain_head_sha256": self.chain_head_sha256,
            "payloads_checked": self.payloads_checked,
            "payloads_unavailable": self.payloads_unavailable,
        }


def verify_bundle(directory: str | Path) -> VerificationResult:
    """Recompute the manifest, chain, operations, retries, and policy timing."""

    root = Path(directory)
    blockers: set[str] = set()
    try:
        manifest = json.loads((root / "bundle.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _result({"sdk_bundle_manifest_unreadable"}, None, [], None, set())
    if not isinstance(manifest, dict):
        return _result({"sdk_bundle_manifest_shape_invalid"}, None, [], None, set())
    blockers.update(_manifest_blockers(manifest))

    try:
        raw_frames = (root / "frames.ndjson").read_bytes()
    except OSError:
        return _result(blockers | {"sdk_frame_log_unreadable"}, _string(manifest.get("session_id")), [], None, set())
    if raw_frames and not raw_frames.endswith(b"\n"):
        blockers.add("sdk_frame_log_truncated")
    frames: list[dict[str, Any]] = []
    for index, line in enumerate(raw_frames.splitlines()):
        if not line:
            continue
        try:
            frame = json.loads(line)
        except json.JSONDecodeError:
            blockers.add(f"sdk_frame_json_invalid:{index}")
            continue
        if not isinstance(frame, dict):
            blockers.add(f"sdk_frame_shape_unreadable:{index}")
            continue
        frames.append(frame)

    head = GENESIS_SHA256
    previous_observed_at: str | None = None
    pairs: dict[str, dict[str, tuple[int, dict[str, Any]] | None]] = {}
    attempts: dict[str, dict[int, dict[str, Any]]] = {}
    decision_indices: dict[str, int] = {}
    content_identities: set[tuple[str, int, str]] = set()
    session_id = _string(manifest.get("session_id"))

    for index, frame in enumerate(frames):
        blockers.update(f"{item}:{index}" for item in _frame_blockers(frame))
        if frame.get("session_id") != session_id:
            blockers.add(f"sdk_frame_session_mismatch:{index}")
        if canonical_json(frame.get("coverage")) != canonical_json(manifest.get("coverage")):
            blockers.add(f"sdk_frame_bundle_coverage_mismatch:{index}")
        if frame.get("sequence") != index:
            blockers.add(f"sdk_frame_sequence_gap:{index}")
        if frame.get("previous_frame_sha256") != head:
            blockers.add(f"sdk_frame_previous_hash_mismatch:{index}")
        frame_sha = _string(frame.get("frame_sha256"))
        if _is_sha(frame_sha):
            assert frame_sha is not None
            head = frame_sha
        observed = _string(frame.get("observed_at"))
        if previous_observed_at is not None and observed is not None and observed < previous_observed_at:
            blockers.add(f"sdk_frame_timestamp_regressed:{index}")
        if observed is not None:
            previous_observed_at = observed
        input_ref = _operation_input(frame)
        _add_content(content_identities, input_ref)
        occurrence = _string(frame.get("occurrence_sha256")) or f"invalid:{index}"
        pair = pairs.setdefault(occurrence, {"decision": None, "action": None})
        if frame.get("frame_kind") == "decision":
            if pair["decision"] is not None:
                blockers.add(f"sdk_decision_duplicate:{occurrence}")
            pair["decision"] = (index, frame)
            decision_indices[occurrence] = index
            logical_id = _string(frame.get("logical_operation_id")) or f"invalid:{index}"
            attempt = frame.get("attempt_number")
            if isinstance(attempt, int) and not isinstance(attempt, bool):
                logical = attempts.setdefault(logical_id, {})
                if attempt in logical:
                    blockers.add(f"sdk_logical_attempt_duplicate:{logical_id}:{attempt}")
                logical[attempt] = frame
        else:
            _add_content(content_identities, _operation_output(frame))
            if frame.get("outcome") == "identity_mismatch":
                blockers.add(f"sdk_identity_mismatch_recorded:{occurrence}")
            if pair["action"] is not None:
                blockers.add(f"sdk_action_duplicate:{occurrence}")
            pair["action"] = (index, frame)

    completed = 0
    for occurrence, pair in pairs.items():
        decision_item, action_item = pair["decision"], pair["action"]
        if decision_item is None:
            blockers.add(f"sdk_decision_missing:{occurrence}")
            continue
        if action_item is None:
            blockers.add(f"sdk_action_missing:{occurrence}")
            continue
        completed += 1
        decision_index, decision = decision_item
        action_index, action = action_item
        if action_index <= decision_index:
            blockers.add(f"sdk_action_precedes_decision:{occurrence}")
        if not _pair_matches(decision, action):
            blockers.add(f"sdk_operation_pair_binding_mismatch:{occurrence}")
        policy = decision.get("policy")
        if not isinstance(policy, dict) or action.get("policy_receipt_sha256") != policy.get("receipt_sha256"):
            blockers.add(f"sdk_action_policy_binding_mismatch:{occurrence}")
            continue
        expected_censor = _expected_censor(policy)
        outcome = action.get("outcome")
        if (expected_censor is None and outcome in {"policy_censored", "budget_censored", "authority_censored"}) or (
            expected_censor is not None and outcome != expected_censor
        ):
            blockers.add(f"sdk_policy_outcome_mismatch:{occurrence}")
        if expected_censor is not None and action.get("failure_code") not in policy.get("reason_codes", []):
            blockers.add(f"sdk_censor_reason_not_in_policy:{occurrence}")
        if action.get("dispatch_started_at") is not None and policy.get("evaluated_at", "") > action["dispatch_started_at"]:
            blockers.add(f"sdk_policy_not_pre_dispatch:{occurrence}")
        parent = decision.get("parent_occurrence_sha256")
        if parent is not None:
            parent_index = decision_indices.get(str(parent))
            if parent_index is None:
                blockers.add(f"sdk_parent_occurrence_missing:{occurrence}")
            elif parent_index >= decision_index:
                blockers.add(f"sdk_parent_not_prior:{occurrence}")

    for logical_id, logical_attempts in attempts.items():
        for attempt_number, decision in logical_attempts.items():
            if attempt_number == 1:
                continue
            predecessor = logical_attempts.get(attempt_number - 1)
            if predecessor is None:
                blockers.add(f"sdk_retry_predecessor_missing:{logical_id}:{attempt_number}")
            else:
                if decision.get("retry_of_occurrence_sha256") != predecessor.get("occurrence_sha256"):
                    blockers.add(f"sdk_retry_predecessor_mismatch:{logical_id}:{attempt_number}")
                if not _retry_matches(predecessor, decision):
                    blockers.add(f"sdk_retry_identity_context_mismatch:{logical_id}:{attempt_number}")

    if manifest.get("frame_count") != len(frames):
        blockers.add("sdk_manifest_frame_count_mismatch")
    if manifest.get("operation_count") != completed:
        blockers.add("sdk_manifest_operation_count_mismatch")
    if manifest.get("chain_head_sha256") != head:
        blockers.add("sdk_manifest_chain_head_mismatch")
    if manifest.get("status") != "finalized":
        blockers.add("sdk_bundle_not_finalized")
    if not frames:
        blockers.add("sdk_frame_log_empty")
    finalized = _string(manifest.get("finalized_at"))
    if finalized and previous_observed_at and finalized < previous_observed_at:
        blockers.add("sdk_bundle_finalized_before_last_frame")
    first_observed = _string(frames[0].get("observed_at")) if frames else None
    created = _string(manifest.get("created_at"))
    if first_observed and created and created > first_observed:
        blockers.add("sdk_bundle_created_after_first_frame")
    return _result(blockers, session_id, frames, head if _is_sha(head) else None, content_identities)


def _manifest_blockers(value: dict[str, Any]) -> set[str]:
    blockers: set[str] = set()
    if set(value) != _MANIFEST_KEYS:
        blockers.add("sdk_bundle_fields_invalid")
    if value.get("schema_version") != SDK_BUNDLE_SCHEMA_VERSION:
        blockers.add("sdk_bundle_schema_invalid")
    if _SEMVER.fullmatch(_string(value.get("guard_version")) or "") is None:
        blockers.add("sdk_bundle_guard_version_invalid")
    if _STABLE_ID.fullmatch(_string(value.get("session_id")) or "") is None:
        blockers.add("sdk_bundle_session_id_invalid")
    if value.get("capture_mode") != "digest-only":
        blockers.add("sdk_bundle_raw_retention_refused")
    if value.get("capture_boundary") != "explicit_sdk":
        blockers.add("sdk_bundle_boundary_invalid")
    if value.get("bypass_possible") is not True or value.get("bypass_declaration") != "uninstrumented_or_direct_io_is_not_observed":
        blockers.add("sdk_bundle_bypass_declaration_invalid")
    if canonical_json(value.get("coverage")) != canonical_json(SDK_COVERAGE):
        blockers.add("sdk_bundle_coverage_invalid")
    for key in ("frame_count", "operation_count"):
        if not isinstance(value.get(key), int) or isinstance(value.get(key), bool) or value[key] < 0:
            blockers.add(f"sdk_bundle_{key}_invalid")
    if not _is_sha(_string(value.get("chain_head_sha256"))):
        blockers.add("sdk_bundle_chain_head_invalid")
    created, finalized = _string(value.get("created_at")), _string(value.get("finalized_at"))
    if not _timestamp(created):
        blockers.add("sdk_bundle_created_at_invalid")
    if finalized is not None and (not _timestamp(finalized) or (created is not None and finalized < created)):
        blockers.add("sdk_bundle_finalized_at_invalid")
    if value.get("status") not in {"recording", "finalized"}:
        blockers.add("sdk_bundle_status_invalid")
    if value.get("status") == "recording" and finalized is not None:
        blockers.add("sdk_bundle_recording_finalized_conflict")
    if value.get("status") == "finalized" and finalized is None:
        blockers.add("sdk_bundle_finalization_incomplete")
    return blockers


def _frame_blockers(frame: dict[str, Any]) -> set[str]:
    blockers: set[str] = set()
    frame_kind = _string(frame.get("frame_kind"))
    operation_kind = _string(frame.get("operation_kind"))
    if frame_kind is None or operation_kind is None:
        return {"sdk_frame_discriminator_invalid"}
    discriminator = (frame_kind, operation_kind)
    specific = _FRAME_SPECIFIC.get(discriminator)
    if specific is None:
        return {"sdk_frame_discriminator_invalid"}
    if set(frame) != _FRAME_COMMON | specific:
        blockers.add("sdk_frame_fields_invalid")
    if frame.get("schema_version") != SDK_FRAME_SCHEMA_VERSION:
        blockers.add("sdk_frame_schema_invalid")
    for key in ("session_id", "actor_id", "principal_id", "logical_operation_id"):
        if _STABLE_ID.fullmatch(_string(frame.get(key)) or "") is None:
            blockers.add(f"sdk_frame_{key}_invalid")
    scopes = frame.get("authority_scope_ids")
    if not _canonical_id_list(scopes):
        blockers.add("sdk_frame_authority_scopes_not_canonical")
    if not isinstance(frame.get("sequence"), int) or isinstance(frame.get("sequence"), bool) or frame["sequence"] < 0:
        blockers.add("sdk_frame_sequence_invalid")
    if not _timestamp(_string(frame.get("observed_at"))):
        blockers.add("sdk_frame_timestamp_invalid")
    if canonical_json(frame.get("coverage")) != canonical_json(SDK_COVERAGE):
        blockers.add("sdk_frame_coverage_invalid")
    attempt = frame.get("attempt_number")
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        blockers.add("sdk_frame_attempt_number_invalid")
    if attempt == 1 and frame.get("retry_of_occurrence_sha256") is not None:
        blockers.add("sdk_frame_first_attempt_has_retry_parent")
    if isinstance(attempt, int) and attempt > 1 and not _is_sha(_string(frame.get("retry_of_occurrence_sha256"))):
        blockers.add("sdk_frame_retry_parent_missing")
    if frame.get("parent_occurrence_sha256") is not None and not _is_sha(_string(frame.get("parent_occurrence_sha256"))):
        blockers.add("sdk_frame_parent_occurrence_invalid")
    for key in ("occurrence_sha256", "previous_frame_sha256", "frame_sha256"):
        if not _is_sha(_string(frame.get(key))):
            blockers.add(f"sdk_frame_{key}_invalid")
    blockers.update(_identity_blockers(_operation_identity(frame), discriminator[1]))
    blockers.update(_state_root_blockers(frame.get("state_root_before"), "before"))
    blockers.update(_content_blockers(_operation_input(frame), "sdk_input"))
    if frame.get("occurrence_sha256") != _occurrence_digest(frame):
        blockers.add("sdk_frame_occurrence_digest_mismatch")
    if frame.get("frame_sha256") != _frame_digest(frame):
        blockers.add("sdk_frame_digest_mismatch")
    if discriminator[0] == "decision":
        blockers.update(_policy_blockers(frame.get("policy"), frame))
    else:
        blockers.update(_action_blockers(frame))
    return blockers


def _policy_blockers(value: object, frame: dict[str, Any]) -> set[str]:
    blockers: set[str] = set()
    if not isinstance(value, dict):
        return {"sdk_policy_shape_invalid"}
    expected = {
        "schema_version", "operation_kind", "occurrence_sha256", "actor_id", "principal_id",
        "authority_scope_ids", "decision", "censor_kind", "reason_codes", "policy_sha256",
        "evaluated_at", "receipt_sha256",
    }
    if set(value) != expected:
        blockers.add("sdk_policy_fields_invalid")
    if value.get("schema_version") != "gradia.guard.sdk-policy-receipt.v1":
        blockers.add("sdk_policy_schema_invalid")
    for key in ("operation_kind", "occurrence_sha256", "actor_id", "principal_id", "authority_scope_ids"):
        if canonical_json(value.get(key)) != canonical_json(frame.get(key)):
            blockers.add("sdk_policy_frame_binding_mismatch")
            break
    if not _is_sha(_string(value.get("policy_sha256"))):
        blockers.add("sdk_policy_digest_invalid")
    if not _canonical_id_list(value.get("reason_codes")):
        blockers.add("sdk_policy_reason_codes_not_canonical")
    if not _timestamp(_string(value.get("evaluated_at"))) or value.get("evaluated_at", "") > frame.get("observed_at", ""):
        blockers.add("sdk_policy_timing_invalid")
    decision, censor = value.get("decision"), value.get("censor_kind")
    if decision == "allowed" and censor is not None:
        blockers.add("sdk_allowed_policy_has_censor")
    if decision == "blocked" and censor not in {"policy", "budget", "authority"}:
        blockers.add("sdk_blocked_policy_censor_missing")
    if decision not in {"allowed", "blocked"}:
        blockers.add("sdk_policy_decision_invalid")
    body = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if value.get("receipt_sha256") != digest_canonical(body):
        blockers.add("sdk_policy_receipt_digest_mismatch")
    return blockers


def _action_blockers(frame: dict[str, Any]) -> set[str]:
    blockers = _content_blockers(_operation_output(frame), "sdk_output", optional=True)
    blockers.update(_state_root_blockers(frame.get("state_root_after"), "after"))
    if not _is_sha(_string(frame.get("policy_receipt_sha256"))):
        blockers.add("sdk_action_policy_receipt_invalid")
    failure_code = frame.get("failure_code")
    if failure_code is not None and _STABLE_ID.fullmatch(_string(failure_code) or "") is None:
        blockers.add("sdk_failure_code_invalid")
    outcome = frame.get("outcome")
    allowed = {"success", "decision_failure", "tool_failure", "protocol_failure", "identity_mismatch", "policy_censored", "budget_censored", "authority_censored"}
    if outcome not in allowed:
        blockers.add("sdk_action_outcome_invalid")
    censored = outcome in {"policy_censored", "budget_censored", "authority_censored"}
    resolved, output = _resolved_identity(frame), _operation_output(frame)
    if censored:
        if any((frame.get("dispatch_occurred") is not False, resolved is not None, output is not None, frame.get("dispatch_started_at") is not None, frame.get("terminal_observed_at") is not None, frame.get("latency_ms") is not None, frame.get("failure_code") is None, canonical_json(frame.get("state_root_after")) != canonical_json(frame.get("state_root_before")))):
            blockers.add("sdk_censor_shape_invalid")
        return blockers
    if frame.get("dispatch_occurred") is not True or not _timestamp(_string(frame.get("dispatch_started_at"))) or not _timestamp(_string(frame.get("terminal_observed_at"))) or not isinstance(frame.get("latency_ms"), int) or isinstance(frame.get("latency_ms"), bool) or frame.get("latency_ms", -1) < 0:
        blockers.add("sdk_dispatch_timing_missing")
    elif not (frame["dispatch_started_at"] <= frame["terminal_observed_at"] <= frame["observed_at"]):
        blockers.add("sdk_dispatch_timing_invalid")
    if resolved is not None:
        blockers.update(_identity_blockers(resolved, _string(frame.get("operation_kind"))))
    identity_match = resolved is not None and canonical_json(resolved) == canonical_json(_operation_identity(frame))
    if outcome == "success" and (not identity_match or output is None or frame.get("failure_code") is not None):
        blockers.add("sdk_success_shape_invalid")
    if outcome == "identity_mismatch" and (resolved is None or identity_match or not str(frame.get("failure_code", "")).startswith("resolved_")):
        blockers.add("sdk_identity_mismatch_shape_invalid")
    if outcome in {"decision_failure", "tool_failure", "protocol_failure"} and (frame.get("failure_code") is None or (resolved is not None and not identity_match)):
        blockers.add("sdk_failure_shape_invalid")
    return blockers


def _identity_blockers(value: object, operation_kind: str | None) -> set[str]:
    if not isinstance(value, dict):
        return {"sdk_operation_identity_invalid"}
    if operation_kind == "application_decision":
        expected = {"schema_version", "decision_type", "executor_kind", "executor_id", "executor_version", "contract_sha256"}
        blockers: set[str] = set()
        if set(value) != expected or value.get("schema_version") != "gradia.guard.sdk-decision-identity.v1":
            blockers.add("sdk_decision_identity_invalid")
        if _STABLE_ID.fullmatch(_string(value.get("decision_type")) or "") is None:
            blockers.add("sdk_decision_type_invalid")
        if value.get("executor_kind") not in {"model", "component", "human"}:
            blockers.add("sdk_decision_executor_kind_invalid")
        if _PORTABLE_ID.fullmatch(_string(value.get("executor_id")) or "") is None:
            blockers.add("sdk_decision_executor_id_invalid")
        if not _exact_version(_string(value.get("executor_version"))):
            blockers.add("sdk_decision_executor_version_not_exact_pin")
        if not _is_sha(_string(value.get("contract_sha256"))):
            blockers.add("sdk_decision_contract_digest_invalid")
        return blockers
    else:
        expected = {"schema_version", "registry_id", "tool_id", "tool_version", "interface_sha256"}
        blockers = set()
        if set(value) != expected or value.get("schema_version") != "gradia.guard.sdk-tool-identity.v1":
            blockers.add("sdk_tool_identity_invalid")
        if _STABLE_ID.fullmatch(_string(value.get("registry_id")) or "") is None:
            blockers.add("sdk_tool_registry_id_invalid")
        if _PORTABLE_ID.fullmatch(_string(value.get("tool_id")) or "") is None:
            blockers.add("sdk_tool_id_invalid")
        if not _exact_version(_string(value.get("tool_version"))):
            blockers.add("sdk_tool_version_not_exact_pin")
        if not _is_sha(_string(value.get("interface_sha256"))):
            blockers.add("sdk_tool_interface_digest_invalid")
        return blockers


def _state_root_blockers(value: object, position: str) -> set[str]:
    if value is None:
        return set()
    expected = {"schema_version", "source", "namespace_id", "root_sha256"}
    blockers: set[str] = set()
    if not isinstance(value, dict):
        return {f"sdk_state_root_{position}_invalid"}
    if (
        set(value) != expected
        or value.get("schema_version") != "gradia.guard.sdk-state-root.v1"
        or value.get("source") != "application_declared"
    ):
        blockers.add(f"sdk_state_root_{position}_invalid")
    if _STABLE_ID.fullmatch(_string(value.get("namespace_id")) or "") is None:
        blockers.add("sdk_state_root_namespace_id_invalid")
    if not _is_sha(_string(value.get("root_sha256"))):
        blockers.add("sdk_state_root_digest_invalid")
    return blockers


def _content_blockers(value: object, prefix: str, optional: bool = False) -> set[str]:
    if value is None and optional:
        return set()
    expected = {"schema_version", "media_type", "byte_length", "plaintext_sha256", "storage", "ciphertext_ref", "ciphertext_sha256", "key_id"}
    if not isinstance(value, dict) or set(value) != expected:
        return {f"{prefix}:content_shape_invalid"}
    blockers: set[str] = set()
    if value.get("schema_version") != "gradia.guard.content-ref.v1" or value.get("storage") != "digest-only":
        blockers.add(f"{prefix}:content_schema_invalid")
    if _MEDIA_TYPE.fullmatch(_string(value.get("media_type")) or "") is None:
        blockers.add(f"{prefix}:content_media_type_invalid")
    if not isinstance(value.get("byte_length"), int) or isinstance(value.get("byte_length"), bool) or value.get("byte_length", 0) <= 0:
        blockers.add(f"{prefix}:content_length_invalid")
    if not _is_sha(_string(value.get("plaintext_sha256"))):
        blockers.add(f"{prefix}:content_digest_invalid")
    if any(value.get(key) is not None for key in ("ciphertext_ref", "ciphertext_sha256", "key_id")):
        blockers.add(f"{prefix}:digest_only_content_has_storage_fields")
    return blockers


def _operation_identity(frame: dict[str, Any]) -> object:
    return frame.get("decision_identity") if frame.get("operation_kind") == "application_decision" else frame.get("tool_identity")


def _resolved_identity(frame: dict[str, Any]) -> object:
    return frame.get("resolved_decision_identity") if frame.get("operation_kind") == "application_decision" else frame.get("resolved_tool_identity")


def _operation_input(frame: dict[str, Any]) -> object:
    return frame.get("decision_input") if frame.get("operation_kind") == "application_decision" else frame.get("tool_request")


def _operation_output(frame: dict[str, Any]) -> object:
    return frame.get("decision_output") if frame.get("operation_kind") == "application_decision" else frame.get("tool_result")


def _occurrence_digest(frame: dict[str, Any]) -> str:
    input_ref = _operation_input(frame)
    input_sha = input_ref.get("plaintext_sha256") if isinstance(input_ref, dict) else None
    return digest_canonical({
        "schema_version": "gradia.guard.sdk-occurrence.v1",
        "operation_kind": frame.get("operation_kind"),
        "actor_id": frame.get("actor_id"),
        "principal_id": frame.get("principal_id"),
        "authority_scope_ids": frame.get("authority_scope_ids"),
        "logical_operation_id": frame.get("logical_operation_id"),
        "attempt_number": frame.get("attempt_number"),
        "retry_of_occurrence_sha256": frame.get("retry_of_occurrence_sha256"),
        "parent_occurrence_sha256": frame.get("parent_occurrence_sha256"),
        "state_root_before": frame.get("state_root_before"),
        "identity": _operation_identity(frame),
        "input_sha256": input_sha,
    })


def _frame_digest(frame: dict[str, Any]) -> str:
    return digest_canonical({key: value for key, value in frame.items() if key != "frame_sha256"})


def _pair_matches(decision: dict[str, Any], action: dict[str, Any]) -> bool:
    fields = ("operation_kind", "actor_id", "principal_id", "authority_scope_ids", "logical_operation_id", "attempt_number", "retry_of_occurrence_sha256", "parent_occurrence_sha256", "state_root_before")
    return all(canonical_json(decision.get(key)) == canonical_json(action.get(key)) for key in fields) and canonical_json(_operation_identity(decision)) == canonical_json(_operation_identity(action)) and canonical_json(_operation_input(decision)) == canonical_json(_operation_input(action))


def _retry_matches(first: dict[str, Any], second: dict[str, Any]) -> bool:
    fields = ("operation_kind", "actor_id", "principal_id", "authority_scope_ids")
    return all(canonical_json(first.get(key)) == canonical_json(second.get(key)) for key in fields) and canonical_json(_operation_identity(first)) == canonical_json(_operation_identity(second))


def _expected_censor(policy: dict[str, Any]) -> str | None:
    if policy.get("decision") != "blocked":
        return None
    censor_kind = _string(policy.get("censor_kind"))
    return {"budget": "budget_censored", "authority": "authority_censored"}.get(
        censor_kind or "", "policy_censored"
    )


def _canonical_id_list(value: object) -> bool:
    return isinstance(value, list) and bool(value) and value == sorted(set(value)) and all(isinstance(item, str) and _STABLE_ID.fullmatch(item) for item in value)


def _add_content(target: set[tuple[str, int, str]], value: object) -> None:
    if isinstance(value, dict) and isinstance(value.get("plaintext_sha256"), str) and isinstance(value.get("byte_length"), int) and isinstance(value.get("media_type"), str):
        target.add((value["plaintext_sha256"], value["byte_length"], value["media_type"]))


def _timestamp(value: str | None) -> bool:
    return value is not None and _ISO_MILLIS.fullmatch(value) is not None


def _exact_version(value: str | None) -> bool:
    return bool(
        value
        and _PORTABLE_ID.fullmatch(value)
        and any(character.isdigit() for character in value)
        and _UNPINNED.search(value) is None
    )


def _is_sha(value: str | None) -> bool:
    return value is not None and _SHA256.fullmatch(value) is not None


def _string(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _result(blockers: set[str], session_id: str | None, frames: list[dict[str, Any]], head: str | None, content: set[tuple[str, int, str]]) -> VerificationResult:
    ordered = tuple(sorted(blockers))
    return VerificationResult(not ordered, ordered, session_id, len(frames), head, 0, len(content))
