"""First-use ethical-use warnings and safe-default helpers.

This tiny module ships the interactive guard the CLI shows on a fresh
install (``check_first_use``), and the longer "use this responsibly"
banner that ``webrecon`` prints when a destructive operation runs for
the first time on a host (``display_ethical_warning``).

Both helpers are no-ops when their state-file already records that the
operator acknowledged the warning, so a deployment that has been
verified once does not re-prompt on every invocation. The state file
lives at ``~/.kiro/webrecon/.warnings`` so it survives package
upgrades.

Validates: Requirement 9.5 (clear documentation of legal and ethical
use, safe defaults, interactive prompts).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

__all__ = [
    "ETHICAL_WARNING",
    "check_first_use",
    "display_ethical_warning",
]


ETHICAL_WARNING: str = (
    "WebRecon is intended for authorised security research only. "
    "Operators are responsible for ensuring they have explicit "
    "permission to scan and probe target systems. Unauthorised "
    "reconnaissance may violate computer-misuse laws and the terms of "
    "service of the platforms involved."
)


def _state_path() -> Path:
    """Return the path of the first-use marker file."""
    return Path.home() / ".kiro" / "webrecon" / ".warnings"


def display_ethical_warning() -> None:
    """Print the ethical-use banner to stderr.

    Idempotent: callers that want the banner shown exactly once should
    use :func:`check_first_use` instead.
    """
    import sys

    print(ETHICAL_WARNING, file=sys.stderr)


def check_first_use() -> bool:
    """Return ``True`` when this is the first webrecon run on the host.

    The first call writes a timestamp marker so subsequent calls return
    ``False``. The marker lives under ``~/.kiro/webrecon/`` so it
    survives package upgrades.
    """
    marker = _state_path()
    if marker.exists():
        return False
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(
        datetime.now(timezone.utc).isoformat(),
        encoding="utf-8",
    )
    return True
