"""Exercise the installed Python distribution and the independent Node verifier."""
import json
import subprocess
import tempfile
from pathlib import Path

from gradia_guard import GuardRecorder, allowed_policy, decision_identity, verify_bundle


def main():
    root = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="guard-python-release-") as directory:
        bundle = Path(directory) / "evidence"
        identity = decision_identity(decision_type="model_completion", executor_kind="model",
            executor_id="synthetic.provider", executor_version="release-fixture-1", contract_sha256="1" * 64)
        recorder = GuardRecorder(bundle)
        operation = recorder.begin_application_decision(actor_id="release.operator", principal_id="local.fixture",
            authority_scope_ids=("model.invoke",), logical_operation_id="release-check", attempt_number=1,
            decision_identity=identity, decision_input=b"PRIVATE_RELEASE_INPUT", decision_input_media_type="text/plain",
            policy=allowed_policy("2" * 64))
        operation.mark_dispatched()
        operation.succeed(resolved_identity=identity, output=b"PRIVATE_RELEASE_OUTPUT", output_media_type="text/plain")
        recorder.finalize()
        verified = verify_bundle(bundle)
        assert verified.ok, verified.blockers
        assert "PRIVATE_RELEASE" not in "".join(p.read_text() for p in bundle.iterdir() if p.is_file())
        result = subprocess.run(["node", str(root / "dist/src/cli.js"), "verify", str(bundle)],
            capture_output=True, text=True, check=True)
        assert json.loads(result.stdout)["ok"]
        frames = bundle / "frames.ndjson"
        rows = frames.read_text().splitlines()
        value = json.loads(rows[0]); value["release_tamper"] = True
        rows[0] = json.dumps(value)
        frames.write_text("\n".join(rows) + "\n")
        assert not verify_bundle(bundle).ok
        result = subprocess.run(["node", str(root / "dist/src/cli.js"), "verify", str(bundle)], capture_output=True, text=True)
        assert result.returncode != 0
        print(json.dumps({"installed_python": True, "independent_node_verification": True,
            "digest_only": True, "tampering_refused_by_both": True}))


if __name__ == "__main__":
    main()
