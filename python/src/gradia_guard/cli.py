"""Account-free Python Guard command line."""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path

from .core import GUARD_ABI_VERSION
from .verify import verify_bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gradia-guard-python")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("doctor", help="show local defaults without network access")
    verify = subcommands.add_parser("verify", help="verify a local G2 bundle")
    verify.add_argument("directory", type=Path)
    inspect = subcommands.add_parser("inspect", help="verify, then show exact coverage")
    inspect.add_argument("directory", type=Path)
    arguments = parser.parse_args(argv)
    if arguments.command == "doctor":
        print(json.dumps({
            "ok": sys.version_info >= (3, 12),
            "guard_abi_version": GUARD_ABI_VERSION,
            "python": platform.python_version(),
            "runtime_requirement": "python>=3.12",
            "telemetry": "off",
            "capture_mode": "digest-only",
            "managed_connection": False,
            "assurance_ceiling": "G2 voluntary SDK",
            "bypass_possible": True,
        }, sort_keys=True))
        return 0 if sys.version_info >= (3, 12) else 1
    result = verify_bundle(arguments.directory)
    payload = result.as_dict()
    if arguments.command == "inspect" and result.ok:
        manifest = json.loads((arguments.directory / "bundle.json").read_text(encoding="utf-8"))
        payload["coverage"] = manifest["coverage"]
        payload["claim_boundary"] = (
            "framework_and_application_calls_explicitly_reported_through_this_sdk_only;"
            "direct_or_uninstrumented_io_remains_unobserved"
        )
    print(json.dumps(payload, sort_keys=True))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
