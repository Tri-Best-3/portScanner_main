"""Scenario registry and execution helpers."""

from __future__ import annotations

import io
import json
import shlex
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any

import docker
from docker.errors import DockerException, NotFound


_ROOT_DIR = Path(__file__).resolve().parents[3]
_SCENARIO_ROOT = _ROOT_DIR / "scenarios"
_DEFAULT_MODE = "container_script"
_DEFAULT_SCRIPT_NAME = "scenario.sh"
_DEFAULT_SCRIPT_DEST_PREFIX = "/tmp"
_METADATA_NAME = "metadata.json"


def _normalize_script_path(script_path: str, scenario_dir: Path) -> str:
    if script_path.strip():
        return script_path.replace("\\", "/")
    default_script = (scenario_dir / _DEFAULT_SCRIPT_NAME).resolve()
    return default_script.relative_to(_ROOT_DIR).as_posix()


def _resolve_script_path(script_path: str) -> Path:
    path = Path(script_path)
    if path.is_absolute():
        resolved = path.resolve()
    else:
        resolved = (_ROOT_DIR / path).resolve()

    try:
        resolved.relative_to(_ROOT_DIR)
    except ValueError as exc:
        raise ValueError(f"scenario script must stay under repository root: {script_path}") from exc
    return resolved


def _load_scenarios() -> dict[str, dict[str, Any]]:
    scenarios: dict[str, dict[str, Any]] = {}
    if not _SCENARIO_ROOT.is_dir():
        return scenarios

    for scenario_dir in sorted(path for path in _SCENARIO_ROOT.iterdir() if path.is_dir()):
        metadata_path = scenario_dir / _METADATA_NAME
        if not metadata_path.is_file():
            continue

        try:
            raw = json.loads(metadata_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid scenario metadata JSON: {metadata_path}") from exc
        if not isinstance(raw, dict):
            raise ValueError(f"scenario metadata must be an object: {metadata_path}")

        name = str(raw.get("name") or scenario_dir.name).strip()
        container_name = str(raw.get("container_name") or "").strip()
        script_path = _normalize_script_path(str(raw.get("script_path") or "").strip(), scenario_dir)
        script_dest = str(raw.get("script_dest") or f"{_DEFAULT_SCRIPT_DEST_PREFIX}/{name}_scenario.sh").strip()

        if not name:
            raise ValueError(f"scenario metadata missing name: {metadata_path}")
        if not container_name:
            raise ValueError(f"scenario metadata missing container_name: {metadata_path}")
        if not script_dest.startswith("/"):
            raise ValueError(f"scenario metadata script_dest must be absolute: {metadata_path}")
        if name in scenarios:
            raise ValueError(f"duplicate scenario name in metadata: {name}")

        scenarios[name] = {
            "name": name,
            "description": str(raw.get("description") or "").strip(),
            "target_hint": str(raw.get("target_hint") or "").strip(),
            "container_name": container_name,
            "script_path": script_path,
            "script_dest": script_dest,
            "mode": str(raw.get("mode") or _DEFAULT_MODE).strip() or _DEFAULT_MODE,
        }

    return scenarios


def list_scenarios() -> list[dict[str, Any]]:
    scenarios = _load_scenarios()
    return [scenarios[name] for name in sorted(scenarios)]


def validate_scenario(name: str) -> dict[str, Any]:
    scenarios = _load_scenarios()
    scenario = scenarios.get(name)
    if scenario is None:
        available = ", ".join(sorted(scenarios)) or "none"
        raise ValueError(f"unsupported scenario: {name} (available: {available})")
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
    target_hint = str(scenario.get("target_hint") or "").strip()
    if target_hint and target != target_hint:
        raise ValueError(f"scenario '{name}' only supports target '{target_hint}'")

    script_path = _resolve_script_path(str(scenario.get("script_path", "")))
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
        container.exec_run(["sh", "-lc", f"pkill -f {shlex.quote(script_dest)} >/dev/null 2>&1 || true"])
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
        "script_path": scenario["script_path"],
    }
