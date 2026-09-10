"""Offline distribution identity/content gate; never publishes or reads credentials."""
from __future__ import annotations

import argparse
import email
import hashlib
import json
import tarfile
import tomllib
import zipfile
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", required=True, type=Path)
    args = parser.parse_args()
    package = Path(__file__).resolve().parents[1]
    meta = tomllib.loads((package / "pyproject.toml").read_text())["project"]
    wheels = list(args.dist.glob("*.whl"))
    sdists = list(args.dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ValueError("exactly_one_wheel_and_sdist_required")
    receipts = []
    for path in [*wheels, *sdists]:
        if path.stat().st_size > 2_000_000:
            raise ValueError("unexpected_distribution_size")
        if path.suffix == ".whl":
            with zipfile.ZipFile(path) as archive:
                names = archive.namelist()
                metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
                if len(metadata) != 1:
                    raise ValueError("wheel_metadata_missing")
                info = email.message_from_bytes(archive.read(metadata[0]))
                if "gradia_guard/py.typed" not in names or "gradia_guard/__init__.py" not in names:
                    raise ValueError("wheel_runtime_missing")
        else:
            with tarfile.open(path, "r:gz") as archive:
                names = archive.getnames()
                metadata = [name for name in names if name.count("/") == 1 and name.endswith("/PKG-INFO")]
                if len(metadata) != 1:
                    raise ValueError("sdist_metadata_missing")
                member = archive.extractfile(metadata[0])
                assert member is not None
                info = email.message_from_bytes(member.read())
        if info["Name"] != meta["name"] or info["Version"] != meta["version"]:
            raise ValueError("distribution_identity_mismatch")
        for name in names:
            parts = Path(name).parts
            if Path(name).is_absolute() or ".." in parts or any(part in {".git", ".env", "node_modules"} for part in parts):
                raise ValueError("distribution_unsafe_content")
            if name.endswith((".pem", ".key", ".p12", ".pfx", ".sqlite", ".db")):
                raise ValueError("distribution_private_content")
        receipts.append({"file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "files": len(names)})
    print(json.dumps({"name": meta["name"], "version": meta["version"], "distributions": receipts, "published": False}))


if __name__ == "__main__":
    main()
