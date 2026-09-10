"""Development-only Harbor agent for deterministic verifier near-miss controls.

The agent executes the task's reference solution, then mutates only the artifact
paths declared by that task.  A trial is invalid if no artifact changed or if a
declared artifact is missing; those conditions fail before verification.
"""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import override

from harbor.agents.base import BaseAgent
from harbor.environments.base import BaseEnvironment
from harbor.models.agent.context import AgentContext
from harbor.models.task.task import Task
from harbor.models.trial.paths import EnvironmentPaths
from harbor.utils.env import resolve_env_vars
from harbor.utils.scripts import build_execution_command, needs_chmod, quote_shell_arg


class NearMissAgent(BaseAgent):
    """Oracle-derived control that emits right-schema, wrong-content artifacts."""

    @staticmethod
    @override
    def name() -> str:
        return "near-miss"

    def __init__(
        self,
        *args,
        task_dir: str | Path,
        mode: str = "flatten",
        seed: int = 0,
        oracle_artifact_root: str | Path | None = None,
        **kwargs,
    ) -> None:
        if mode not in {"shuffle", "flatten", "scale", "signflip"}:
            raise ValueError(f"unsupported near-miss mode: {mode}")
        super().__init__(*args, **kwargs)
        self._guard_task_dir = Path(task_dir).resolve()
        self._task = Task(self._guard_task_dir)
        self._mode = mode
        self._seed = int(seed)
        self._oracle_artifact_root = Path(oracle_artifact_root).resolve() if oracle_artifact_root else None
        self._near_miss_source = Path(__file__).with_name("near_miss.py")

    @override
    def version(self) -> str:
        return "0.2.0-dev"

    @override
    async def setup(self, environment: BaseEnvironment) -> None:
        return

    @override
    async def run(
        self,
        instruction: str,
        environment: BaseEnvironment,
        context: AgentContext,
    ) -> None:
        env_paths = EnvironmentPaths.for_os(environment.os)
        if self._oracle_artifact_root is None:
            solution_dir = self._task.paths.solution_dir
            solve_path = self._task.paths.discovered_solve_path_for(self._task.config.environment.os)
            if solve_path is None:
                raise FileNotFoundError("no OS-compatible reference solution")
            await environment.upload_dir(
                source_dir=solution_dir,
                target_dir=str(env_paths.solution_dir),
            )
            container_solve_path = str(
                env_paths.solution_dir / solve_path.relative_to(solution_dir).as_posix()
            )
            container_oracle_log = str(env_paths.agent_dir / "oracle.txt")
            if needs_chmod(container_solve_path):
                await environment.exec(
                    command=f"chmod +x {quote_shell_arg(container_solve_path, self._task.config.environment.os)}",
                    user="root",
                )
            command = build_execution_command(
                container_solve_path,
                stdout_path=container_oracle_log,
                task_os=self._task.config.environment.os,
            )
            solution_env = (
                resolve_env_vars(self._task.config.solution.env) if self._task.config.solution.env else {}
            )
            with environment.scoped_exec_env(solution_env):
                solved = await environment.exec(
                    command=command,
                    env={"DEBIAN_FRONTEND": "noninteractive"},
                    user="root",
                )
            if not environment.capabilities.mounted:
                await environment.download_file(
                    source_path=container_oracle_log,
                    target_path=self.logs_dir / "oracle.txt",
                )
            if solved.return_code != 0:
                raise RuntimeError(
                    f"reference solution failed for {self._guard_task_dir.name}: "
                    f"{solved.stderr or solved.stdout}"
                )
        else:
            if not self._oracle_artifact_root.is_dir():
                raise FileNotFoundError("oracle artifact root does not exist")
            for declared in self._task.config.artifacts:
                local = self._oracle_artifact_root / declared.lstrip("/")
                if not local.exists():
                    raise FileNotFoundError(f"frozen oracle artifact missing: {declared}")
                if local.is_dir():
                    await environment.upload_dir(source_dir=local, target_dir=declared)
                else:
                    await environment.upload_file(local, declared)
        remote_root = "/tmp/gradia-near-miss"
        await environment.upload_file(
            self._near_miss_source,
            f"{remote_root}/near_miss.py",
        )
        await environment.upload_file(
            self._guard_task_dir / "task.toml",
            f"{remote_root}/task/task.toml",
        )
        report_path = "/logs/agent/near-miss.json"
        pre_hash_path = "/logs/agent/near-miss-pre.json"
        post_hash_path = "/logs/agent/near-miss-post.json"
        command = (
            f"python3 {remote_root}/near_miss.py fingerprint-task {remote_root}/task --root / "
            f"> {pre_hash_path} && "
            f"python3 {remote_root}/near_miss.py corrupt-task "
            f"{remote_root}/task --root / --mode {shlex.quote(self._mode)} "
            f"--seed {self._seed} > {report_path} && "
            f"python3 {remote_root}/near_miss.py fingerprint-task {remote_root}/task --root / "
            f"> {post_hash_path} && "
            'python3 -c "import json,pathlib; '
            f"d=json.loads(pathlib.Path('{report_path}').read_text()); "
            f"pre=json.loads(pathlib.Path('{pre_hash_path}').read_text()); "
            f"post=json.loads(pathlib.Path('{post_hash_path}').read_text()); "
            "assert d['corrupted'], 'no artifact content changed'; "
            "assert not d['missing'], 'declared artifact missing'; "
            "assert pre['files'] != post['files'], 'mutation was byte-identical to oracle artifact'\""
        )
        result = await environment.exec(command=command, user="root")
        if result.return_code != 0:
            raise RuntimeError(
                f"near-miss mutation failed for {self._guard_task_dir.name} "
                f"mode={self._mode}: {result.stderr or result.stdout}"
            )
