"""
Configuration loading and validation.

The audit config is JSON. Credentials are NEVER stored in the config —
the config names environment variables, and values are read from the
environment at runtime. This way, an accidentally committed config file
does not leak credentials.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class ConfigError(Exception):
    """Raised when the audit config is missing fields, has wrong types, or
    references an environment variable that is not set."""


# Required top-level keys and the type each must be.
_REQUIRED_TOP_LEVEL = {
    "audit_name": str,
    "target": dict,
    "audit_rules": dict,
}

# Required keys inside the "target" block.
_REQUIRED_TARGET_KEYS_LIVE = {"name": str, "host": str}
_REQUIRED_TARGET_KEYS_FILE = {"name": str, "config_file": str}


def load_config(path: str | Path) -> dict[str, Any]:
    """Load and validate the audit config.

    Returns the config dict with credentials resolved from environment
    variables. Raises ConfigError with a clear message on any problem.
    """
    path = Path(path)
    log.info("Loading config from %s", path)

    if not path.is_file():
        raise ConfigError(f"Config file not found: {path}")

    try:
        with path.open("r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Config file {path} is not valid JSON: {exc}") from exc

    _validate_top_level(cfg)
    _validate_target(cfg["target"])
    _resolve_credentials(cfg["target"])

    log.debug("Config loaded successfully: %s", cfg["audit_name"])
    return cfg


def _validate_top_level(cfg: dict[str, Any]) -> None:
    for key, expected_type in _REQUIRED_TOP_LEVEL.items():
        if key not in cfg:
            raise ConfigError(f"Config missing required key: '{key}'")
        if not isinstance(cfg[key], expected_type):
            raise ConfigError(
                f"Config key '{key}' must be {expected_type.__name__}, "
                f"got {type(cfg[key]).__name__}"
            )


def _validate_target(target: dict[str, Any]) -> None:
    mode = target.get("mode", "live")
    if mode not in ("live", "file"):
        raise ConfigError(
            f"target.mode must be 'live' or 'file', got '{mode}'"
        )

    required = _REQUIRED_TARGET_KEYS_LIVE if mode == "live" else _REQUIRED_TARGET_KEYS_FILE
    for key, expected_type in required.items():
        if key not in target:
            raise ConfigError(f"target missing required key for mode={mode}: '{key}'")
        if not isinstance(target[key], expected_type):
            raise ConfigError(
                f"target.{key} must be {expected_type.__name__}, "
                f"got {type(target[key]).__name__}"
            )


def _resolve_credentials(target: dict[str, Any]) -> None:
    """Replace credential references with values from environment variables.

    The config can name credentials with these keys:
      - api_key_env: name of env var holding the Palo Alto XML API key
      - password_env: name of env var holding an SSH password (CLI fallback)

    After this runs, the target dict gains 'api_key' and/or 'password'
    keys with the actual values. We deliberately do not log the values.
    """
    if target.get("mode") == "file":
        # File mode does not need credentials.
        return

    api_key_env = target.get("api_key_env")
    password_env = target.get("password_env")

    if not api_key_env and not password_env:
        raise ConfigError(
            "target must specify either 'api_key_env' or 'password_env' "
            "(naming the env var that holds the credential)"
        )

    if api_key_env:
        value = os.environ.get(api_key_env)
        if not value:
            raise ConfigError(
                f"Environment variable '{api_key_env}' is not set or empty. "
                f"Set it before running: export {api_key_env}=<your-api-key>"
            )
        target["api_key"] = value
        log.debug("Resolved API key from env var %s", api_key_env)

    if password_env:
        value = os.environ.get(password_env)
        if not value:
            raise ConfigError(
                f"Environment variable '{password_env}' is not set or empty."
            )
        target["password"] = value
        log.debug("Resolved password from env var %s", password_env)
