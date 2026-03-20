"""EPSS lookup helpers with graceful degradation."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Optional

import requests

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class EpssLookupConfig:
    use_live_api: bool = False
    timeout: float = 5.0
    base_url: str = "https://api.first.org/data/v1/epss"


_OFFLINE_EPSS = {
    "CVE-2021-23017": 0.94,
    "CVE-2021-41773": 0.97,
    "CVE-2017-12615": 0.91,
    "CVE-2017-7494": 0.96,
    "CVE-2012-2122": 0.72,
    "CVE-2015-1427": 0.95,
    "CVE-2011-2523": 0.98,
}


def lookup_epss(
    cve_id: Optional[str],
    config: Optional[EpssLookupConfig] = None,
    session: Optional[requests.Session] = None,
) -> Optional[float]:
    if not cve_id:
        return None
    resolved = config or EpssLookupConfig()
    try:
        if resolved.use_live_api:
            return _lookup_epss_live(cve_id, resolved, session)
    except Exception as exc:
        LOGGER.warning("Falling back to offline EPSS data for %s: %s", cve_id, exc)
    return _OFFLINE_EPSS.get(cve_id)


def _lookup_epss_live(
    cve_id: str,
    config: EpssLookupConfig,
    session: Optional[requests.Session],
) -> Optional[float]:
    client = session or requests.Session()
    response = client.get(config.base_url, params={"cve": cve_id}, timeout=config.timeout)
    response.raise_for_status()
    payload = response.json()
    data = payload.get("data") or []
    if not data:
        return None
    value = data[0].get("epss")
    return float(value) if value is not None else None
