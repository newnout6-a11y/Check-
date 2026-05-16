"""Test suite for the `webrecon` package.

Layout (mirrors `tests/` for the `binchecker` package):

- ``tests/webrecon/unit``         Example-based unit tests (mock all I/O).
- ``tests/webrecon/integration``  End-to-end tests with the real SQLite
                                  backend and `httpx.MockTransport`.
- ``tests/webrecon/property``     Hypothesis property-based tests.
- ``tests/webrecon/fixtures``     Shared fixtures, sample HTML / API
                                  payloads, and corpora.

The webrecon suite is deliberately namespaced under its own directory so
property-coverage enforcement (`tests/conftest.py`) and pytest collection
remain scoped to the `binchecker` design properties without false
positives from webrecon tests.
"""
