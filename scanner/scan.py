"""Scanner module entrypoint.

The backend should call this module instead of keeping scan logic under backend.
When the real scanner is ready, replace the body of ``run_scan`` or route it to the
actual implementation without changing the backend contract.
"""

from __future__ import annotations

from scanner.mock_scan import Profile, run_mock_scan


def run_scan(target: str, profile: Profile = "mixed") -> dict[str, object]:
    """Run a scan and return the shared scan-result JSON contract."""
    return run_mock_scan(target, profile=profile)
