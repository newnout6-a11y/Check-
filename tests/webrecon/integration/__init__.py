"""Integration tests for `webrecon`.

These tests exercise multiple modules together (e.g. discovery → asset
database → export) using the real SQLite backend pointed at
``tmp_path`` and `httpx.MockTransport` for HTTP boundaries
(Requirement 11.5).
"""
