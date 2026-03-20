"""Scenario registry and execution helpers."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any

import docker
from docker.errors import DockerException, NotFound


_ROOT_DIR = Path(__file__).resolve().parents[3]
_SCENARIO_ROOT = _ROOT_DIR / "scenarios"

_SCENARIOS: dict[str, dict[str, Any]] = {
    "redis_drift": {
        "name": "redis_drift",
        "description": "Randomly toggles Redis/SSH/HTTP ports inside the Redis lab target to trigger drift.",
        "target_hint": "redis-4-unacc.lab.local",
        "container_name": "vuln-redis-4-unacc",
        "script_path": str((_SCENARIO_ROOT / "redis_drift" / "scenario.sh").resolve()),
        "script_dest": "/data/scenario.sh",
        "mode": "container_script",
    }
}


def list_scenarios() -> list[dict[str, Any]]:
    return list(_SCENARIOS.values())


def validate_scenario(name: str) -> dict[str, Any]:
    scenario = _SCENARIOS.get(name)
    if scenario is None:
        raise ValueError(f"unsupported scenario: {name}")
    return scenario


def _docker_client() -> docker.DockerClient:
    return docker.DockerClient(base_url="unix://var/run/docker.sock")


def _put_file(container: Any, source_path: Path, dest_path: str) -> None:
    source_bytes = source_path.read_bytes()
    archive = io.BytesIO()
    dest = PurePosixPath(dest_path)
    with tarfile.open(fileobj=archive, mode="w") as tar:
        info = tarfile.TarInfo(name=dest.name)
        info.size = len(source_bytes)
        info.mode = 0o755
        tar.addfile(info, io.BytesIO(source_bytes))
    archive.seek(0)
    if not container.put_archive(str(dest.parent), archive.getvalue()):
        raise RuntimeError(f"failed to copy scenario file into container: {container.name}")


def run_scenario(name: str, target: str) -> dict[str, Any]:
    scenario = validate_scenario(name)
    target_hint = scenario.get("target_hint")
    if target_hint and target != target_hint:
        raise ValueError(f"scenario '{name}' only supports target '{target_hint}'")

    script_path = Path(str(scenario.get("script_path", "")))
    script_dest = str(scenario.get("script_dest", "")).strip()
    container_name = str(scenario.get("container_name", "")).strip()

    if not script_path.is_file():
        raise ValueError(f"scenario '{name}' script is missing: {script_path}")
    if not script_dest:
        raise ValueError(f"scenario '{name}' is missing script_dest")
    if not container_name:
        raise ValueError(f"scenario '{name}' is missing container_name")

    try:
        client = _docker_client()
        container = client.containers.get(container_name)
        _put_file(container, script_path, script_dest)
        container.exec_run(["chmod", "+x", script_dest])
        container.exec_run(["sh", "-lc", f"pkill -f '{script_dest}' >/dev/null 2>&1 || true"])
        container.exec_run(["sh", script_dest], detach=True)
    except NotFound as exc:
        raise RuntimeError(f"scenario container not found: {container_name}") from exc
    except DockerException as exc:
        raise RuntimeError(f"docker scenario execution failed: {exc}") from exc

    return {
        "name": scenario["name"],
        "mode": scenario["mode"],
        "target": target,
        "container_name": container_name,
        "script_dest": script_dest,
    }
