#!/usr/bin/env python3
"""Offline, append-only verifier-integrity receipts for Harbor task trees.

This adapter is intentionally separate from Guard's G2 runtime ABI. It records
bounded evidence about named benchmark probes; it does not certify scientific
validity, complete exploit resistance, or non-bypassable execution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA = "gradia.guard.benchmark-integrity-receipt.v0.2"
PROBE_SET = "guard-harbor-near-miss/0.2"
STATIC_PROBES = ("artifacts-declared", "verifier-separate", "verifier-no-egress")
DYNAMIC_PROBES = (
    "oracle-1",
    "nop-0",
    "nearmiss-0/shuffle",
    "nearmiss-0/flatten",
    "nearmiss-0/scale",
    "nearmiss-0/signflip",
)
DATA_EXT = {".csv", ".tsv", ".json", ".jsonl", ".npz", ".npy"}
CODE_EXT = {".py", ".r", ".lean", ".js", ".sh", ".md"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_head(path: Path) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def _read_task(task_dir: Path) -> dict[str, object]:
    text = (task_dir / "task.toml").read_text(encoding="utf-8")
    try:
        import tomllib
    except ModuleNotFoundError:
        document = {}
    else:
        document = tomllib.loads(text)
    artifacts = [str(path) for path in document.get("artifacts", [])]
    if not artifacts:
        match = re.search(
            r"^artifacts\s*=\s*\[(.*?)\]", text, re.DOTALL | re.MULTILINE
        )
        artifacts = re.findall(r'"([^"]+)"', match.group(1)) if match else []
    verifier = document.get("verifier", {}) if isinstance(document, dict) else {}
    verifier = verifier if isinstance(verifier, dict) else {}
    environment = verifier.get("environment", {})
    environment = environment if isinstance(environment, dict) else {}
    mode = verifier.get("environment_mode")
    network = environment.get("network_mode")
    if not document:
        mode_match = re.search(r'environment_mode\s*=\s*"([^"]+)"', text)
        network_match = re.search(
            r'\[verifier\.environment\][^\[]*?network_mode\s*=\s*"([^"]+)"',
            text,
            re.DOTALL,
        )
        mode = mode_match.group(1) if mode_match else None
        network = network_match.group(1) if network_match else None
    return {
        "artifacts": artifacts,
        "verifier_mode": mode,
        "verifier_network": network,
    }


def _artifact_class(paths: list[str]) -> str:
    if not paths:
        return "none"
    extensions = [Path(path).suffix.lower() for path in paths]
    if all(extension in CODE_EXT for extension in extensions):
        return "code"
    if all(extension in DATA_EXT for extension in extensions):
        return "data"
    if all(extension in DATA_EXT or not extension for extension in extensions):
        return "directory"
    return "mixed"


def _static_probes(task: dict[str, object]) -> dict[str, dict[str, str]]:
    artifacts = task["artifacts"]
    assert isinstance(artifacts, list)
    return {
        "artifacts-declared": {
            "status": "pass" if artifacts else "fail",
            "detail": f"{len(artifacts)} declared",
        },
        "verifier-separate": {
            "status": "pass" if task["verifier_mode"] == "separate" else "fail",
            "detail": f"environment_mode={task['verifier_mode']}",
        },
        "verifier-no-egress": {
            "status": "pass" if task["verifier_network"] == "no-network" else "fail",
            "detail": f"network_mode={task['verifier_network']}",
        },
    }


def _initial_dynamic(artifact_class: str) -> dict[str, dict[str, str]]:
    probes: dict[str, dict[str, str]] = {}
    for probe in DYNAMIC_PROBES:
        if probe.startswith("nearmiss-0/") and artifact_class == "code":
            probes[probe] = {
                "status": "not_applicable",
                "detail": "code artifact has no task-agnostic schema-preserving data mutation",
            }
        else:
            probes[probe] = {"status": "pending", "detail": "not observed"}
    return probes


def _projection(receipt: dict[str, object]) -> list[dict[str, object]]:
    genesis = receipt["genesis"]
    assert isinstance(genesis, dict)
    tasks = json.loads(json.dumps(genesis["tasks"]))
    by_name = {task["task"]: task for task in tasks}
    for event in receipt["events"]:
        task = by_name[event["task"]]
        task["dynamic_probes"][event["probe"]] = {
            "status": event["status"],
            "detail": event["detail"],
            "event_sha256": event["event_sha256"],
        }
    return tasks


def _summarize(tasks: list[dict[str, object]]) -> dict[str, object]:
    counts = {
        "pass": 0,
        "fail": 0,
        "pending": 0,
        "not_applicable": 0,
        "invalid": 0,
    }
    for task in tasks:
        for group in ("static_probes", "dynamic_probes"):
            for probe in task[group].values():
                counts[probe["status"]] += 1
    judged = counts["pass"] + counts["fail"]
    applicable = judged + counts["pending"]
    return {
        "tasks": len(tasks),
        "counts": counts,
        "judged": judged,
        "applicable": applicable,
        "integrity_fraction": round(counts["pass"] / judged, 6) if judged else None,
        "coverage_fraction": round(judged / applicable, 6) if applicable else None,
        "score_basis": "pass/judged; pending excluded; invalid and not_applicable never score",
    }


def _seal(receipt: dict[str, object]) -> dict[str, object]:
    body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    receipt["receipt_sha256"] = _sha256_bytes(_canonical(body))
    return receipt


def scan(tasks_dir: Path) -> dict[str, object]:
    tasks = []
    for task_toml in sorted(tasks_dir.rglob("task.toml")):
        task = _read_task(task_toml.parent)
        artifacts = task["artifacts"]
        assert isinstance(artifacts, list)
        artifact_class = _artifact_class(artifacts)
        tasks.append(
            {
                "task": task_toml.parent.name,
                "path": str(task_toml.parent.relative_to(tasks_dir)),
                "task_toml_sha256": _sha256_file(task_toml),
                "artifact_class": artifact_class,
                "static_probes": _static_probes(task),
                "dynamic_probes": _initial_dynamic(artifact_class),
            }
        )
    receipt: dict[str, object] = {
        "schema": SCHEMA,
        "probe_set": PROBE_SET,
        "probe_set_sha256": _sha256_bytes(_canonical([*STATIC_PROBES, *DYNAMIC_PROBES])),
        "claim_boundary": (
            "named_probe_survival_only;not_scientific_validity;not_complete_exploit_resistance;"
            "not_non_bypassable_execution"
        ),
        "execution_profile": {
            "network_calls_implemented": False,
            "network_enforcement_observed": False,
            "raw_artifact_payloads_embedded": False,
        },
        "genesis": {
            "created_at": _now(),
            "subject_path": str(tasks_dir),
            "subject_git_head": _git_head(tasks_dir),
            "tasks": tasks,
        },
        "events": [],
    }
    receipt["summary"] = _summarize(tasks)
    return _seal(receipt)


def _validate_digest(name: str, value: str | None) -> None:
    if value is not None and not HEX64.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


def record(
    receipt: dict[str, object],
    *,
    task: str,
    probe: str,
    disposition: str,
    reward: float | None,
    detail: str,
    harbor_result_sha256: str | None,
    runner_sha256: str | None,
    pre_artifacts_sha256: str | None,
    post_artifacts_sha256: str | None,
) -> dict[str, object]:
    ok, blockers = verify(receipt)
    if not ok:
        raise ValueError("receipt does not verify: " + ",".join(blockers))
    if probe not in DYNAMIC_PROBES:
        raise ValueError(f"unknown dynamic probe: {probe}")
    if disposition not in {"observed", "invalid", "not_applicable"}:
        raise ValueError("disposition must be observed, invalid, or not_applicable")
    for name, digest in (
        ("harbor_result_sha256", harbor_result_sha256),
        ("runner_sha256", runner_sha256),
        ("pre_artifacts_sha256", pre_artifacts_sha256),
        ("post_artifacts_sha256", post_artifacts_sha256),
    ):
        _validate_digest(name, digest)
    tasks = _projection(receipt)
    selected = next((candidate for candidate in tasks if candidate["task"] == task), None)
    if selected is None:
        raise ValueError(f"unknown task: {task}")
    current = selected["dynamic_probes"][probe]
    if current["status"] != "pending":
        raise ValueError(f"probe is already terminal: {task}/{probe}/{current['status']}")
    if disposition == "observed":
        if reward not in {0.0, 1.0}:
            raise ValueError("observed rewards must be exactly 0 or 1")
        if probe.startswith("nearmiss-0/"):
            if not pre_artifacts_sha256 or not post_artifacts_sha256:
                raise ValueError("near-miss observations require pre/post artifact-set digests")
            if pre_artifacts_sha256 == post_artifacts_sha256:
                raise ValueError("near-miss observation is byte-identical and must be invalid")
        expected = 1.0 if probe == "oracle-1" else 0.0
        status = "pass" if reward == expected else "fail"
        event_detail = f"reward={int(reward)} expected={int(expected)}; {detail}".rstrip("; ")
    else:
        if reward is not None:
            raise ValueError(f"{disposition} events cannot carry a reward")
        status = disposition
        event_detail = detail
    events = receipt["events"]
    assert isinstance(events, list)
    body = {
        "sequence": len(events) + 1,
        "recorded_at": _now(),
        "task": task,
        "probe": probe,
        "disposition": disposition,
        "status": status,
        "reward": reward,
        "detail": event_detail,
        "evidence": {
            "harbor_result_sha256": harbor_result_sha256,
            "runner_sha256": runner_sha256,
            "pre_artifacts_sha256": pre_artifacts_sha256,
            "post_artifacts_sha256": post_artifacts_sha256,
        },
        "previous_event_sha256": events[-1]["event_sha256"] if events else None,
    }
    body["event_sha256"] = _sha256_bytes(_canonical(body))
    events.append(body)
    receipt["summary"] = _summarize(_projection(receipt))
    return _seal(receipt)


def verify(receipt: dict[str, object]) -> tuple[bool, list[str]]:
    blockers: list[str] = []
    if receipt.get("schema") != SCHEMA:
        blockers.append("schema_mismatch")
    body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if receipt.get("receipt_sha256") != _sha256_bytes(_canonical(body)):
        blockers.append("receipt_digest_mismatch")
    previous = None
    seen: set[tuple[str, str]] = set()
    try:
        events = receipt["events"]
        for sequence, event in enumerate(events, start=1):
            event_body = {key: value for key, value in event.items() if key != "event_sha256"}
            if event.get("sequence") != sequence:
                blockers.append("event_sequence_mismatch")
            if event.get("previous_event_sha256") != previous:
                blockers.append("event_link_mismatch")
            event_sha = _sha256_bytes(_canonical(event_body))
            if event.get("event_sha256") != event_sha:
                blockers.append("event_digest_mismatch")
            key = (event["task"], event["probe"])
            if key in seen:
                blockers.append("duplicate_terminal_probe")
            seen.add(key)
            previous = event.get("event_sha256")
        projected = _projection(receipt)
        if receipt.get("summary") != _summarize(projected):
            blockers.append("summary_mismatch")
    except (KeyError, TypeError, ValueError):
        blockers.append("receipt_shape_invalid")
    return not blockers, sorted(set(blockers))


def badge_svg(receipt: dict[str, object]) -> str:
    summary = receipt["summary"]
    counts = summary["counts"]
    label = "guard near-miss 0.2"
    value = f"{counts['pass']}/{summary['judged']} judged"
    if counts["pending"]:
        value += f" · {counts['pending']} pending"
    color = "#2F7D5B" if not counts["fail"] else "#A8621A"
    label_width = 7 * len(label) + 14
    value_width = 7 * len(value) + 14
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{label_width + value_width}" height="20" '
        f'role="img" aria-label="{label}: {value}">'
        f'<rect width="{label_width}" height="20" fill="#3B3B3B"/>'
        f'<rect x="{label_width}" width="{value_width}" height="20" fill="{color}"/>'
        '<g fill="#fff" font-family="DejaVu Sans,Verdana,sans-serif" font-size="11">'
        f'<text x="{label_width / 2}" y="14" text-anchor="middle">{label}</text>'
        f'<text x="{label_width + value_width / 2}" y="14" text-anchor="middle">{value}</text>'
        "</g></svg>"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    scan_command = commands.add_parser("scan")
    scan_command.add_argument("tasks_dir", type=Path)
    scan_command.add_argument("-o", "--output", type=Path, default=Path("guard-receipt.json"))
    record_command = commands.add_parser("record")
    record_command.add_argument("receipt", type=Path)
    record_command.add_argument("task")
    record_command.add_argument("probe", choices=DYNAMIC_PROBES)
    record_command.add_argument(
        "--disposition", choices=("observed", "invalid", "not_applicable"), required=True
    )
    record_command.add_argument("--reward", type=float)
    record_command.add_argument("--detail", required=True)
    record_command.add_argument("--harbor-result-sha256")
    record_command.add_argument("--runner-sha256")
    record_command.add_argument("--pre-artifacts-sha256")
    record_command.add_argument("--post-artifacts-sha256")
    verify_command = commands.add_parser("verify")
    verify_command.add_argument("receipt", type=Path)
    badge_command = commands.add_parser("badge")
    badge_command.add_argument("receipt", type=Path)
    badge_command.add_argument("-o", "--output", type=Path, default=Path("guard-badge.svg"))
    arguments = parser.parse_args()
    if arguments.command == "scan":
        receipt = scan(arguments.tasks_dir)
        arguments.output.write_text(json.dumps(receipt, indent=1) + "\n", encoding="utf-8")
        print(json.dumps(receipt["summary"], sort_keys=True))
        return 0
    receipt = json.loads(arguments.receipt.read_text(encoding="utf-8"))
    if arguments.command == "verify":
        ok, blockers = verify(receipt)
        print(json.dumps({"ok": ok, "blockers": blockers}, sort_keys=True))
        return 0 if ok else 1
    if arguments.command == "badge":
        ok, blockers = verify(receipt)
        if not ok:
            print(json.dumps({"ok": False, "blockers": blockers}, sort_keys=True))
            return 1
        arguments.output.write_text(badge_svg(receipt), encoding="utf-8")
        return 0
    updated = record(
        receipt,
        task=arguments.task,
        probe=arguments.probe,
        disposition=arguments.disposition,
        reward=arguments.reward,
        detail=arguments.detail,
        harbor_result_sha256=arguments.harbor_result_sha256,
        runner_sha256=arguments.runner_sha256,
        pre_artifacts_sha256=arguments.pre_artifacts_sha256,
        post_artifacts_sha256=arguments.post_artifacts_sha256,
    )
    arguments.receipt.write_text(json.dumps(updated, indent=1) + "\n", encoding="utf-8")
    print(updated["events"][-1]["event_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
