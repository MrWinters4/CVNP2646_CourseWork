"""Tests for config loading and validation."""
from __future__ import annotations

import json
import os

import pytest

from src.config import ConfigError, load_config


def write_config(tmp_path, data) -> str:
    p = tmp_path / "config.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def test_missing_file_raises_config_error(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "does_not_exist.json")


def test_invalid_json_raises_config_error(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not valid", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid JSON"):
        load_config(str(p))


def test_missing_required_top_level_key_raises(tmp_path):
    path = write_config(tmp_path, {"audit_name": "x"})
    with pytest.raises(ConfigError, match="target"):
        load_config(path)


def test_file_mode_does_not_require_credentials(tmp_path):
    cfg = {
        "audit_name": "test",
        "target": {
            "name": "fw1",
            "mode": "file",
            "config_file": "data/samples/policy_export.xml",
        },
        "audit_rules": {},
    }
    path = write_config(tmp_path, cfg)
    loaded = load_config(path)
    assert loaded["target"]["mode"] == "file"


def test_live_mode_requires_credential_env_var(tmp_path):
    cfg = {
        "audit_name": "test",
        "target": {"name": "fw1", "mode": "live", "host": "192.0.2.1"},
        "audit_rules": {},
    }
    path = write_config(tmp_path, cfg)
    with pytest.raises(ConfigError, match="api_key_env"):
        load_config(path)


def test_live_mode_resolves_api_key_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_TEST_KEY", "secret-value")
    cfg = {
        "audit_name": "test",
        "target": {
            "name": "fw1", "mode": "live", "host": "192.0.2.1",
            "api_key_env": "MY_TEST_KEY",
        },
        "audit_rules": {},
    }
    path = write_config(tmp_path, cfg)
    loaded = load_config(path)
    assert loaded["target"]["api_key"] == "secret-value"


def test_unset_env_var_raises_with_helpful_message(tmp_path, monkeypatch):
    monkeypatch.delenv("MISSING_KEY", raising=False)
    cfg = {
        "audit_name": "test",
        "target": {
            "name": "fw1", "mode": "live", "host": "192.0.2.1",
            "api_key_env": "MISSING_KEY",
        },
        "audit_rules": {},
    }
    path = write_config(tmp_path, cfg)
    with pytest.raises(ConfigError, match="MISSING_KEY"):
        load_config(path)


def test_invalid_mode_raises(tmp_path):
    cfg = {
        "audit_name": "test",
        "target": {"name": "fw1", "mode": "telepathic", "host": "x"},
        "audit_rules": {},
    }
    path = write_config(tmp_path, cfg)
    with pytest.raises(ConfigError, match="mode"):
        load_config(path)
