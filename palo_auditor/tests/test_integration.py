"""End-to-end integration test using the bundled sample policy."""
from __future__ import annotations

import json
from pathlib import Path

from src.main import main

REPO_ROOT = Path(__file__).parent.parent


def test_full_pipeline_against_sample(tmp_path):
    """Run the full CLI pipeline in offline mode and verify the report."""
    config = REPO_ROOT / "data" / "samples" / "audit_config_offline.json"
    sample = REPO_ROOT / "data" / "samples" / "policy_export.xml"
    output = tmp_path / "report.json"

    rc = main([
        "--config", str(config),
        "--offline", str(sample),
        "--output", str(output),
    ])
    assert rc == 0
    assert output.is_file()

    report = json.loads(output.read_text())
    assert report["audit_name"] == "Sample Offline Audit"
    assert report["summary"]["total_rules_analyzed"] == 6
    assert report["summary"]["total_findings"] > 0

    # The Permissive_Catchall rule should produce a high-severity finding.
    high_findings = [f for f in report["findings"] if f["severity"] == "high"]
    assert any(f["rule_name"] == "Permissive_Catchall" for f in high_findings)

    # The Legacy_Telnet_Mgmt rule should produce a risky_services finding.
    risky = [f for f in report["findings"] if f["check"] == "risky_services"]
    assert any(f["rule_name"] == "Legacy_Telnet_Mgmt" for f in risky)

    # Markdown summary should be written alongside.
    md_path = output.with_suffix(".md")
    assert md_path.is_file()
    md_content = md_path.read_text()
    assert "Sample Offline Audit" in md_content


def test_dry_run_does_not_write_report(tmp_path):
    config = REPO_ROOT / "data" / "samples" / "audit_config_offline.json"
    output = tmp_path / "report.json"

    rc = main([
        "--config", str(config),
        "--output", str(output),
        "--dry-run",
    ])
    assert rc == 0
    assert not output.exists()
