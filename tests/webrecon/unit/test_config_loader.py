"""Unit tests for :mod:`webrecon.config.loader`.

Coverage matrix (mirrors the implementation guidance for task 3.2):

* Defaults-only path: no .env, no env vars, no CLI -> every leaf
  attributes to :attr:`ConfigSource.DEFAULT`.
* ``./.env`` overrides ``~/.env``.
* Process environment overrides ``./.env``.
* CLI overrides override process environment.
* The resolution dict correctly attributes every non-default field.
* :class:`ConfigLoadError` is raised on bad input and lists every
  violation in its message.
* :class:`MissingOptionalConfigWarning` is emitted once per missing
  optional API key (and never re-emitted on a subsequent load).

The tests strip ``WEBRECON_*`` from the environment and pass explicit
``cwd`` / ``home`` directories to :func:`load_config` so they stay
hermetic against the developer's working tree.
"""

from __future__ import annotations

import os
import warnings
from pathlib import Path

import pytest

from webrecon.config import loader as loader_module
from webrecon.config.loader import (
    ConfigLoadError,
    ConfigSource,
    LoadedConfig,
    MissingOptionalConfigWarning,
    ResolvedField,
    load_config,
    merge_dicts,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Strip ``WEBRECON_*`` env vars and reset the missing-warning cache.

    Without this fixture, a leaking ``WEBRECON_*`` value from the
    developer shell could silently mutate the resolution dict, and the
    process-lifetime warning cache would let the first test in the
    module race the others.
    """
    for env_key in [k for k in os.environ if k.startswith("WEBRECON_")]:
        monkeypatch.delenv(env_key, raising=False)
    monkeypatch.setattr(loader_module, "_warned_missing_paths", set())
    # Also chdir to an empty dir so any direct AppConfig() call in
    # supporting code doesn't accidentally pick up the project's .env.
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def empty_dirs(tmp_path: Path) -> tuple[Path, Path]:
    """Return (cwd, home) directories with no ``.env`` files."""
    cwd = tmp_path / "work"
    home = tmp_path / "home"
    cwd.mkdir()
    home.mkdir()
    return cwd, home


def _write_env_file(directory: Path, body: str) -> Path:
    """Write a ``.env`` file in ``directory`` and return the resulting path."""
    path = directory / ".env"
    path.write_text(body, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# merge_dicts
# ---------------------------------------------------------------------------


class TestMergeDicts:
    """Deep-merge helper used by the loader."""

    def test_overlay_wins_at_leaf(self) -> None:
        result = merge_dicts({"a": 1}, {"a": 2})
        assert result == {"a": 2}

    def test_recursive_merge(self) -> None:
        result = merge_dicts(
            {"a": {"x": 1, "y": 2}},
            {"a": {"y": 99, "z": 3}},
        )
        assert result == {"a": {"x": 1, "y": 99, "z": 3}}

    def test_inputs_not_mutated(self) -> None:
        base = {"a": {"x": 1}}
        overlay = {"a": {"y": 2}}
        merge_dicts(base, overlay)
        assert base == {"a": {"x": 1}}
        assert overlay == {"a": {"y": 2}}

    def test_overlay_none_overrides(self) -> None:
        # Explicit ``None`` from an overlay should replace the base value;
        # the loader relies on this for "explicit unset" semantics.
        result = merge_dicts({"a": "kept"}, {"a": None})
        assert result == {"a": None}

    def test_non_mapping_replaces_mapping(self) -> None:
        result = merge_dicts({"a": {"x": 1}}, {"a": "scalar"})
        assert result == {"a": "scalar"}


# ---------------------------------------------------------------------------
# Defaults-only path
# ---------------------------------------------------------------------------


class TestDefaultsOnly:
    """No ``.env`` files, no env vars, no CLI -> defaults everywhere."""

    def test_returns_loaded_config(self, empty_dirs: tuple[Path, Path]) -> None:
        cwd, home = empty_dirs
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", MissingOptionalConfigWarning)
            loaded = load_config(cwd=cwd, home=home)
        assert isinstance(loaded, LoadedConfig)

    def test_defaults_match_schema_defaults(
        self, empty_dirs: tuple[Path, Path]
    ) -> None:
        cwd, home = empty_dirs
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", MissingOptionalConfigWarning)
            loaded = load_config(cwd=cwd, home=home)
        cfg = loaded.config
        assert cfg.log_level == "INFO"
        assert cfg.concurrency.max_connections == 20
        assert cfg.rate_limiting.requests_per_second == pytest.approx(10.0)
        assert cfg.api_keys.shodan is None
        assert cfg.safety.test_mode is True

    def test_resolution_attributes_every_leaf_to_default(
        self, empty_dirs: tuple[Path, Path]
    ) -> None:
        cwd, home = empty_dirs
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", MissingOptionalConfigWarning)
            loaded = load_config(cwd=cwd, home=home)
        # Every entry in resolution must be attributed to DEFAULT.
        assert loaded.resolution
        assert all(
            source is ConfigSource.DEFAULT for source in loaded.resolution.values()
        )
        # And it must cover the well-known leaves.
        for path in (
            "log_level",
            "concurrency.max_connections",
            "api_keys.shodan",
            "database.path",
            "safety.test_mode",
        ):
            assert loaded.resolution[path] is ConfigSource.DEFAULT


# ---------------------------------------------------------------------------
# Layer precedence
# ---------------------------------------------------------------------------


class TestLayerPrecedence:
    """The chain defaults < home .env < cwd .env < env vars < CLI."""

    def test_cwd_env_wins_over_home_env(
        self, empty_dirs: tuple[Path, Path]
    ) -> None:
        cwd, home = empty_dirs
        _write_env_file(home, "WEBRECON_LOG_LEVEL=warning\n")
        _write_env_file(cwd, "WEBRECON_LOG_LEVEL=debug\n")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", MissingOptionalConfigWarning)
            loaded = load_config(cwd=cwd, home=home)
        assert loaded.config.log_level == "DEBUG"
        assert loaded.resolution["log_level"] is ConfigSource.ENV_FILE_CWD

    def test_home_env_used_when_no_cwd_env(
        self, empty_dirs: tuple[Path, Path]
    ) -> None:
        cwd, home = empty_dirs
        _write_env_file(home, "WEBRECON_LOG_LEVEL=error\n")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", MissingOptionalConfigWarning)
            loaded = load_config(cwd=cwd, home=home)
        assert loaded.config.log_level == "ERROR"
        assert loaded.resolution["log_level"] is ConfigSource.ENV_FILE_HOME

    def test_env_vars_override_env_file(
        self,
        empty_dirs: tuple[Path, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cwd, home = empty_dirs
        _write_env_file(cwd, "WEBRECON_LOG_LEVEL=debug\n")
        monkeypatch.setenv("WEBRECON_LOG_LEVEL", "warning")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", MissingOptionalConfigWarning)
            loaded = load_config(cwd=cwd, home=home)
        assert loaded.config.log_level == "WARNING"
        assert loaded.resolution["log_level"] is ConfigSource.ENV_VARS

    def test_cli_overrides_env_vars(
        self,
        empty_dirs: tuple[Path, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cwd, home = empty_dirs
        monkeypatch.setenv("WEBRECON_LOG_LEVEL", "warning")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", MissingOptionalConfigWarning)
            loaded = load_config(
                cwd=cwd,
                home=home,
                cli_overrides={"log_level": "ERROR"},
            )
        assert loaded.config.log_level == "ERROR"
        assert loaded.resolution["log_level"] is ConfigSource.CLI_ARGS


# ---------------------------------------------------------------------------
# Resolution attribution for nested fields
# ---------------------------------------------------------------------------


class TestResolutionAttribution:
    """The resolution dict must correctly attribute non-default leaves."""

    def test_nested_api_key_via_env_file(
        self, empty_dirs: tuple[Path, Path]
    ) -> None:
        cwd, home = empty_dirs
        _write_env_file(cwd, "WEBRECON_API_KEYS__SHODAN=shodan-secret\n")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", MissingOptionalConfigWarning)
            loaded = load_config(cwd=cwd, home=home)
        assert loaded.config.api_keys.shodan == "shodan-secret"
        assert loaded.resolution["api_keys.shodan"] is ConfigSource.ENV_FILE_CWD
        # Sibling fields keep their default attribution.
        assert loaded.resolution["api_keys.serper"] is ConfigSource.DEFAULT

    def test_nested_concurrency_via_env_var(
        self,
        empty_dirs: tuple[Path, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cwd, home = empty_dirs
        monkeypatch.setenv("WEBRECON_CONCURRENCY__MAX_CONNECTIONS", "42")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", MissingOptionalConfigWarning)
            loaded = load_config(cwd=cwd, home=home)
        assert loaded.config.concurrency.max_connections == 42
        assert loaded.resolution["concurrency.max_connections"] is ConfigSource.ENV_VARS

    def test_cli_override_nested_dict(
        self, empty_dirs: tuple[Path, Path]
    ) -> None:
        cwd, home = empty_dirs
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", MissingOptionalConfigWarning)
            loaded = load_config(
                cwd=cwd,
                home=home,
                cli_overrides={"api_keys": {"serper": "serper-tok"}},
            )
        assert loaded.config.api_keys.serper == "serper-tok"
        assert loaded.resolution["api_keys.serper"] is ConfigSource.CLI_ARGS


# ---------------------------------------------------------------------------
# Validation failures
# ---------------------------------------------------------------------------


class TestValidationFailures:
    """Bad input should produce :class:`ConfigLoadError` with all violations."""

    def test_bad_log_level_raises_config_load_error(
        self,
        empty_dirs: tuple[Path, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cwd, home = empty_dirs
        monkeypatch.setenv("WEBRECON_LOG_LEVEL", "trace")
        with pytest.raises(ConfigLoadError) as exc_info:
            load_config(cwd=cwd, home=home)
        assert "log_level" in str(exc_info.value)

    def test_multiple_violations_listed(self, empty_dirs: tuple[Path, Path]) -> None:
        cwd, home = empty_dirs
        with pytest.raises(ConfigLoadError) as exc_info:
            load_config(
                cwd=cwd,
                home=home,
                cli_overrides={
                    "log_level": "trace",
                    "concurrency": {"max_connections": 999},
                    "safety": {"test_mode": False, "require_confirmation": False},
                },
            )
        message = str(exc_info.value)
        # Each violation is on its own line, prefixed with "- ".
        assert message.count("\n  - ") >= 2
        assert "log_level" in message
        assert "max_connections" in message

    def test_pydantic_error_chained_as_cause(
        self, empty_dirs: tuple[Path, Path]
    ) -> None:
        cwd, home = empty_dirs
        with pytest.raises(ConfigLoadError) as exc_info:
            load_config(
                cwd=cwd,
                home=home,
                cli_overrides={"log_level": "nope"},
            )
        # The original ValidationError must be chained so structured
        # CLI handlers can still reach ``error.errors()``.
        from pydantic import ValidationError

        assert isinstance(exc_info.value.__cause__, ValidationError)


# ---------------------------------------------------------------------------
# Missing-optional warnings
# ---------------------------------------------------------------------------


class TestMissingOptionalWarnings:
    """Optional-key absences must warn once and only on default fall-back."""

    def test_warns_for_missing_api_keys(self, empty_dirs: tuple[Path, Path]) -> None:
        cwd, home = empty_dirs
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always", MissingOptionalConfigWarning)
            load_config(cwd=cwd, home=home)
        warning_messages = [
            str(w.message) for w in captured
            if issubclass(w.category, MissingOptionalConfigWarning)
        ]
        # All five optional API-key paths should warn on a fresh load.
        assert any("api_keys.fofa" in m for m in warning_messages)
        assert any("api_keys.shodan" in m for m in warning_messages)
        assert any("api_keys.serper" in m for m in warning_messages)
        assert any("api_keys.github" in m for m in warning_messages)
        assert any("api_keys.stripe" in m for m in warning_messages)

    def test_no_warning_when_key_explicitly_set(
        self, empty_dirs: tuple[Path, Path]
    ) -> None:
        cwd, home = empty_dirs
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always", MissingOptionalConfigWarning)
            load_config(
                cwd=cwd,
                home=home,
                cli_overrides={
                    "api_keys": {
                        "shodan": "shodan-tok",
                        "serper": "serper-tok",
                        "github": "ghp_" + "a" * 36,
                        "stripe": "sk_test_abc",
                        "fofa": {"email": "u@example.com", "key": "k"},
                    }
                },
            )
        for warning in captured:
            assert "api_keys.shodan" not in str(warning.message)
            assert "api_keys.serper" not in str(warning.message)

    def test_warning_emitted_once_per_path(
        self, empty_dirs: tuple[Path, Path]
    ) -> None:
        cwd, home = empty_dirs
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always", MissingOptionalConfigWarning)
            load_config(cwd=cwd, home=home)
            load_config(cwd=cwd, home=home)
        # Per-path dedup: each missing optional path warns at most once
        # across the two loads.
        seen_paths: list[str] = []
        for warning in captured:
            if not issubclass(warning.category, MissingOptionalConfigWarning):
                continue
            message = str(warning.message)
            for path in (
                "api_keys.fofa",
                "api_keys.shodan",
                "api_keys.serper",
                "api_keys.github",
                "api_keys.stripe",
            ):
                if path in message:
                    seen_paths.append(path)
        assert len(seen_paths) == len(set(seen_paths))


# ---------------------------------------------------------------------------
# ResolvedField (smoke)
# ---------------------------------------------------------------------------


class TestResolvedField:
    """:class:`ResolvedField` is a small public dataclass; smoke-test only."""

    def test_construction_and_attributes(self) -> None:
        field = ResolvedField(name="log_level", value="INFO", source=ConfigSource.DEFAULT)
        assert field.name == "log_level"
        assert field.value == "INFO"
        assert field.source is ConfigSource.DEFAULT

    def test_is_frozen(self) -> None:
        field = ResolvedField(name="x", value=1, source=ConfigSource.DEFAULT)
        with pytest.raises((AttributeError, TypeError)):
            field.value = 2  # type: ignore[misc]
