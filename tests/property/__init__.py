"""Property-based tests.

Each test module corresponds to a numbered property in
``.kiro/specs/project-enhancement/design.md`` (Properties 1-31).

Every property test must carry a tag comment of the form::

    # Feature: project-enhancement, Property N: <description>

The collector hook in ``tests/conftest.py`` enforces that every ``Property N``
from the design has at least one matching test.
"""
