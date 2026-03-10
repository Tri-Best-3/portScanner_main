"""Runtime configuration for the backend API."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


@dataclass(slots=True)
class Settings:
    host: str = os.getenv("BACKEND_HOST", "0.0.0.0")
    port: int = int(os.getenv("BACKEND_PORT", "8000"))
    sqlite_path: Path = Path(os.getenv("BACKEND_SQLITE_PATH", "backend_data/app.db"))


settings = Settings()
