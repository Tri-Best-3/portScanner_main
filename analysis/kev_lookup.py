"""Known Exploited Vulnerabilities lookup with safe fallback behavior."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Optional

import requests

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class KevLookupConfig:
    use_live_api: bool = False
    timeout: float = 5.0
    base_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


_OFFLINE_KEV = {
    "CVE-2021-23017",
    "CVE-2021-41773",
    "CVE-2017-12615",
    "CVE-2017-7494",
    "CVE-2012-2122",
    "CVE-2015-1427",
    "CVE-2011-2523",
}


def lookup_kev(
    cve_id: Optional[str],
    config: Optional[KevLookupConfig] = None,
    session: Optional[requests.Session] = None,
) -> bool:
    if not cve_id:
        return False
    resolved = config or KevLookupConfig()
    try:
        if resolved.use_live_api:
            return _lookup_kev_live(cve_id, resolved, session)
    except Exception as exc:
        LOGGER.warning("Falling back to offline KEV data for %s: %s", cve_id, exc)
    return cve_id in _OFFLINE_KEV


def _lookup_kev_live(
    cve_id: str,
    config: KevLookupConfig,
    session: Optional[requests.Session],
) -> bool:
    client = session or requests.Session()
    response = client.get(config.base_url, timeout=config.timeout)
    response.raise_for_status()
    payload = response.json()
    for vulnerability in payload.get("vulnerabilities", []):
        if vulnerability.get("cveID") == cve_id:
            return True
    return False
