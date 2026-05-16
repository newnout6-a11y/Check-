"""Top-level pytest configuration for the binchecker test suite.

Responsibilities
----------------
1. Register and load a Hypothesis profile named ``"ci"`` with
   ``max_examples=200`` and ``deadline=None``, matching the
   "Testing & Verification Strategy" section of ``design.md``.

2. Provide a ``pytest_collection_modifyitems`` hook that scans the design
   document's ``Property N`` tags (Properties 1-31) and reports any property
   number that lacks a matching test.  Behaviour is gated on the
   ``BINCHECKER_STRICT_PROPERTY_COVERAGE`` environment variable:

   * unset / empty (default) — emit a console warning summary at the end of
     collection so the suite stays green during early development.
   * ``"1"`` — fail the run with ``pytest.UsageError`` listing every missing
     property number.

   In both modes a coverage summary is printed showing which property numbers
   were detected in tests under ``tests/property/`` (markers of the form
   ``# Property N`` or ``Property N`` references in source / docstrings /
   nodeids).
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

try:
    from hypothesis import HealthCheck, settings
except ImportError:  # pragma: no cover - hypothesis is a dev dependency
    settings = None  # type: ignore[assignment]
    HealthCheck = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Hypothesis profile registration
# ---------------------------------------------------------------------------

_HYPOTHESIS_PROFILE_NAME = "ci"


def _register_hypothesis_profile() -> None:
    """Register and activate the project's Hypothesis profile.

    The profile mirrors the design document's PBT settings: ``max_examples=200``
    (≥100 iterations) and ``deadline=None`` because some properties exercise
    mocked network paths whose latency is non-deterministic.
    """
    if settings is None:  # hypothesis not installed - tests will fail naturally
        return

    settings.register_profile(
        _HYPOTHESIS_PROFILE_NAME,
        max_examples=200,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow] if HealthCheck else [],
    )
    settings.load_profile(_HYPOTHESIS_PROFILE_NAME)


_register_hypothesis_profile()


# ---------------------------------------------------------------------------
# Property coverage enforcement
# ---------------------------------------------------------------------------

# Range of property numbers declared in design.md.  Hard-coded per task 1.2;
# task 1.3+ may widen / narrow this once additional properties are added.
_EXPECTED_PROPERTY_RANGE: range = range(1, 32)  # Properties 1..31 inclusive

# Path to the property test directory.
_PROPERTY_TEST_DIR = Path(__file__).resolve().parent / "property"

# Match ``Property N`` references anywhere (comments, docstrings, nodeids).
_PROPERTY_REF_RE = re.compile(r"\bProperty\s+(\d+)\b", re.IGNORECASE)

# Match the canonical inline marker ``# Property N`` (with optional colon /
# title) that property test files are expected to carry.
_PROPERTY_MARKER_RE = re.compile(r"^\s*#\s*Property\s+(\d+)\b", re.MULTILINE)


def _scan_property_test_dir() -> set[int]:
    """Return property numbers that appear as ``# Property N`` markers in
    files under ``tests/property/``.

    A missing directory simply yields an empty set so the hook stays
    inert when the layout has not been fully created yet.
    """
    found: set[int] = set()
    if not _PROPERTY_TEST_DIR.is_dir():
        return found

    for path in _PROPERTY_TEST_DIR.rglob("*.py"):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for match in _PROPERTY_MARKER_RE.finditer(text):
            found.add(int(match.group(1)))
    return found


def _scan_collected_items(items: list[pytest.Item]) -> set[int]:
    """Augment the file-marker scan with anything visible from collected items
    (nodeids, docstrings, source files referenced by collected tests)."""
    covered: set[int] = set()
    seen_files: set[Path] = set()

    for item in items:
        for match in _PROPERTY_REF_RE.finditer(item.nodeid):
            covered.add(int(match.group(1)))

        doc = getattr(getattr(item, "function", None), "__doc__", None) or ""
        for match in _PROPERTY_REF_RE.finditer(doc):
            covered.add(int(match.group(1)))

        path_attr = getattr(item, "path", None) or getattr(item, "fspath", None)
        if path_attr is None:
            continue
        path = Path(str(path_attr))
        if path in seen_files or not path.exists():
            continue
        seen_files.add(path)
        try:
            source = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for match in _PROPERTY_MARKER_RE.finditer(source):
            covered.add(int(match.group(1)))

    return covered


def _format_coverage_summary(present: set[int], missing: list[int]) -> str:
    if present:
        present_str = ", ".join(f"P{n}" for n in sorted(present))
    else:
        present_str = "(none)"
    if missing:
        missing_str = ", ".join(f"P{n}" for n in missing)
    else:
        missing_str = "(none)"
    return (
        "[binchecker property coverage] "
        f"present={present_str} | missing={missing_str} "
        f"({len(present)}/{len(_EXPECTED_PROPERTY_RANGE)})"
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Scan for ``Property N`` coverage and warn or fail accordingly.

    Off by default; set ``BINCHECKER_STRICT_PROPERTY_COVERAGE=1`` to enforce.
    Always prints a coverage summary so contributors can see which property
    numbers are still unimplemented.
    """
    strict = os.environ.get("BINCHECKER_STRICT_PROPERTY_COVERAGE", "").strip() == "1"

    expected = set(_EXPECTED_PROPERTY_RANGE)
    covered = _scan_property_test_dir() | _scan_collected_items(items)
    missing = sorted(expected - covered)
    summary = _format_coverage_summary(covered & expected, missing)

    # Always surface the summary on the terminal (writeln if a reporter exists).
    reporter = config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter.write_line(summary)
    else:  # pragma: no cover - reporter missing in some embedded contexts
        print(summary)

    if not missing:
        return

    message = (
        "Property coverage gap: the following design properties have no "
        "matching test in tests/property/.\n"
        "Each property must be tagged with '# Property N' (and may also "
        "include a longer title comment).\n"
        f"Missing: {', '.join(f'Property {n}' for n in missing)}"
    )
    if strict:
        raise pytest.UsageError(message)
    # Surface the gap on the terminal but do *not* call ``warnings.warn``:
    # ``pytest.ini`` configures ``filterwarnings = error`` which would
    # promote that warning into a fatal INTERNALERROR during collection
    # and prevent any property test from running. Printing keeps the
    # design intent (visibility) without breaking the inner loop.
    if reporter is not None:
        reporter.write_line(message)
    else:  # pragma: no cover
        print(message, file=sys.stderr)
