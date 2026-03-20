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
    use_live_nvd: bool = os.getenv("ANALYSIS_USE_LIVE_NVD", "true").lower() == "true"
    use_live_kev: bool = os.getenv("ANALYSIS_USE_LIVE_KEV", "true").lower() == "true"
    use_live_epss: bool = os.getenv("ANALYSIS_USE_LIVE_EPSS", "true").lower() == "true"
    request_timeout: float = float(os.getenv("ANALYSIS_REQUEST_TIMEOUT", "8.0"))
    nvd_api_key: str | None = os.getenv("NVD_API_KEY") or None


settings = Settings()
