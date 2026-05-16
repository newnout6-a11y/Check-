"""Local fixtures for `webrecon` integration tests.

Integration tests use the real SQLite backend (pointed at ``tmp_path``
via the ``sqlite_db_path`` fixture) and the shared ``mock_http_transport``
fixture inherited from ``tests/webrecon/conftest.py`` for the HTTP
boundary.
"""
