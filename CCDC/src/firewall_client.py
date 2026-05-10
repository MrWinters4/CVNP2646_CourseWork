"""
Network client for fetching Palo Alto security policy.

Two transport options:

1. XML API (preferred): HTTPS to /api/?type=op&cmd=... with an API key.
   Returns structured XML that the parser handles cleanly.

2. SSH/CLI (fallback): paramiko to the firewall, run 'show running
   security-policy', capture stdout. This matches the reference inject
   script TOOL26T but produces messier output.

This module deliberately does NO parsing — it returns raw bytes/text.
That keeps a clean separation: client = network, parser = format.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import requests
import urllib3

log = logging.getLogger(__name__)

# Palo Alto management interfaces typically use self-signed certs.
# We disable the urllib3 warning to avoid spamming logs, but we make
# the SSL choice explicit (and configurable) per call.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FirewallError(Exception):
    """Raised when we cannot fetch policy from the firewall."""


def fetch_policy(target: dict[str, Any], save_raw_to: Path | None = None) -> str:
    """Fetch the security policy from the configured target.

    Returns the policy as a string (XML for API mode, text for SSH mode,
    or raw file contents for file mode).

    If save_raw_to is provided, also writes the raw response there for
    audit traceability.
    """
    mode = target.get("mode", "live")

    if mode == "file":
        return _fetch_from_file(target, save_raw_to)
    if "api_key" in target:
        return _fetch_via_api(target, save_raw_to)
    if "password" in target:
        return _fetch_via_ssh(target, save_raw_to)

    raise FirewallError(
        "Target has no usable transport (no api_key, password, or file mode)"
    )


def _fetch_from_file(target: dict[str, Any], save_raw_to: Path | None) -> str:
    path = Path(target["config_file"])
    log.info("Reading policy from file: %s", path)
    if not path.is_file():
        raise FirewallError(f"Policy file not found: {path}")
    text = path.read_text(encoding="utf-8")
    if save_raw_to:
        save_raw_to.write_text(text, encoding="utf-8")
    return text


def _fetch_via_api(target: dict[str, Any], save_raw_to: Path | None) -> str:
    """Fetch policy via the Palo Alto XML API.

    The 'op' command runs a CLI-equivalent operational command and returns
    XML. We ask for the running security policy.
    """
    host = target["host"]
    api_key = target["api_key"]
    verify_tls = target.get("verify_tls", False)
    timeout = target.get("timeout_seconds", 30)

    # Operational command to retrieve the security rulebase. The XML
    # response wraps each rule as an <entry>.
    cmd = "<show><running><security-policy></security-policy></running></show>"
    params = {
        "type": "op",
        "cmd": cmd,
        "key": api_key,
    }
    url = f"https://{host}/api/?{urlencode(params)}"

    log.info("Fetching policy via XML API from %s", host)
    if not verify_tls:
        log.warning(
            "TLS verification disabled for %s (set target.verify_tls=true "
            "in config to enable)", host
        )

    try:
        resp = requests.get(url, verify=verify_tls, timeout=timeout)
    except requests.exceptions.ConnectionError as exc:
        raise FirewallError(f"Cannot connect to {host}: {exc}") from exc
    except requests.exceptions.Timeout as exc:
        raise FirewallError(f"Connection to {host} timed out after {timeout}s") from exc

    if resp.status_code != 200:
        raise FirewallError(
            f"API returned HTTP {resp.status_code}: {resp.text[:200]}"
        )

    # The API returns 200 even on logical errors, with status="error"
    # in the XML root. We do a quick check here so we fail fast with a
    # better message than the parser would give.
    if 'status="error"' in resp.text or "<msg>" in resp.text and "Invalid credential" in resp.text:
        raise FirewallError(f"API returned an error response: {resp.text[:300]}")

    if save_raw_to:
        save_raw_to.write_text(resp.text, encoding="utf-8")
        log.debug("Saved raw policy XML to %s", save_raw_to)

    return resp.text


def _fetch_via_ssh(target: dict[str, Any], save_raw_to: Path | None) -> str:
    """Fetch policy via SSH using paramiko.

    Imported lazily so paramiko is only required when SSH is actually used.
    Note: paramiko.AutoAddPolicy() is INSECURE — it accepts any host key.
    For real competition use, populate a known_hosts file and use
    RejectPolicy or a custom verification policy.
    """
    try:
        import paramiko  # type: ignore[import-not-found]
    except ImportError as exc:
        raise FirewallError(
            "paramiko is required for SSH mode. Install with: pip install paramiko"
        ) from exc

    host = target["host"]
    username = target["username"]
    password = target["password"]
    timeout = target.get("timeout_seconds", 30)
    known_hosts = target.get("known_hosts_file")

    log.info("Fetching policy via SSH from %s as %s", host, username)
    if not known_hosts:
        log.warning(
            "No known_hosts_file configured — host key will be auto-accepted. "
            "This is insecure; configure known_hosts_file for production use."
        )

    client = paramiko.SSHClient()
    if known_hosts:
        client.load_host_keys(known_hosts)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            host,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=timeout,
        )
    except paramiko.AuthenticationException as exc:
        raise FirewallError(f"SSH authentication failed for {username}@{host}") from exc
    except (paramiko.SSHException, OSError) as exc:
        raise FirewallError(f"SSH connection to {host} failed: {exc}") from exc

    try:
        stdin, stdout, stderr = client.exec_command(
            "show running security-policy", timeout=timeout
        )
        output = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        if err.strip():
            log.warning("SSH command produced stderr: %s", err.strip()[:200])
    finally:
        client.close()

    if save_raw_to:
        save_raw_to.write_text(output, encoding="utf-8")

    return output
