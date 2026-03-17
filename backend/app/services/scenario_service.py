"""Scenario registry for future drift/integration workflows."""

from __future__ import annotations

from pathlib import Path
from typing import Any


_ROOT_DIR = Path(__file__).resolve().parents[3]
_SCENARIO_ROOT = _ROOT_DIR / "scenarios"

_SCENARIOS: dict[str, dict[str, Any]] = {
    "redis_drift": {
        "name": "redis_drift",
        "description": "Randomly toggles Redis/SSH/HTTP ports inside the Redis lab target to trigger drift.",
        "target_hint": "redis-4-unacc.lab.local",
        "setup_script": str((_SCENARIO_ROOT / "redis_drift" / "setup.sh").resolve()),
        "mode": "external_manual",
    }
}


def list_scenarios() -> list[dict[str, Any]]:
    return list(_SCENARIOS.values())


def validate_scenario(name: str) -> dict[str, Any]:
    scenario = _SCENARIOS.get(name)
    if scenario is None:
        raise ValueError(f"unsupported scenario: {name}")
    return scenario
