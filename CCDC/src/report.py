"""
Audit report generation in multiple formats.

Outputs:
  - JSON: machine-readable, suitable for the CCDC scoring engine, further
    processing, or diffing between runs
  - Markdown: human-readable summary, paste-able into chat/email/inject
    submission

The raw policy export is saved separately by firewall_client (not here),
which preserves the unmodified original for auditors.
"""
from __future__ import annotations

import json
import logging
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .policy_rule import PolicyRule

log = logging.getLogger(__name__)


class AuditReport:
    """Holds audit results and writes them in multiple formats."""

    def __init__(
        self,
        audit_name: str,
        auditor: str,
        firewall_name: str,
        rules: list[PolicyRule],
        findings: list[dict[str, Any]],
        checks_run: list[str],
    ):
        self.audit_name = audit_name
        self.auditor = auditor
        self.firewall_name = firewall_name
        self.rules = rules
        self.findings = findings
        self.checks_run = checks_run
        self.generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # --- Summary ----------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        """Build the summary block included in every output format."""
        sev_counts = Counter(f["severity"] for f in self.findings)
        return {
            "total_rules_analyzed": len(self.rules),
            "total_findings": len(self.findings),
            "findings_by_severity": {
                "high": sev_counts.get("high", 0),
                "medium": sev_counts.get("medium", 0),
                "low": sev_counts.get("low", 0),
            },
            "checks_run": self.checks_run,
        }

    # --- JSON output ------------------------------------------------------

    def to_dict(self, include_rules: bool = False) -> dict[str, Any]:
        """Build the full JSON-serializable report.

        If include_rules is True, also embed the parsed rules. This makes
        the report self-contained for re-analysis without going back to
        the firewall, at the cost of a much larger file.
        """
        report: dict[str, Any] = {
            "audit_name": self.audit_name,
            "auditor": self.auditor,
            "firewall": self.firewall_name,
            "generated_at": self.generated_at,
            "summary": self.summary(),
            "findings": self.findings,
        }
        if include_rules:
            report["rules"] = [r.to_dict() for r in self.rules]
        return report

    def write_json(self, path: Path, include_rules: bool = False) -> None:
        """Write the JSON report. Severity-orders findings high→low."""
        # Sort findings so the most serious issues appear first.
        sev_order = {"high": 0, "medium": 1, "low": 2}
        self.findings.sort(
            key=lambda f: (sev_order.get(f["severity"], 99), f["rule_position"])
        )

        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            json.dump(self.to_dict(include_rules=include_rules), fh, indent=2)
        log.info("JSON report written to %s", path)

    # --- Markdown output --------------------------------------------------

    def write_markdown(self, path: Path) -> None:
        """Write a human-readable Markdown summary.

        Structured for quick scan: TL;DR up top, findings grouped by
        severity, raw recommendations at the end.
        """
        s = self.summary()
        lines: list[str] = []
        lines.append(f"# Firewall Audit: {self.audit_name}")
        lines.append("")
        lines.append(f"**Firewall:** {self.firewall_name}  ")
        lines.append(f"**Auditor:** {self.auditor}  ")
        lines.append(f"**Generated:** {self.generated_at}  ")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- Rules analyzed: **{s['total_rules_analyzed']}**")
        lines.append(f"- Total findings: **{s['total_findings']}**")
        lines.append(f"  - High: {s['findings_by_severity']['high']}")
        lines.append(f"  - Medium: {s['findings_by_severity']['medium']}")
        lines.append(f"  - Low: {s['findings_by_severity']['low']}")
        lines.append(f"- Checks run: {', '.join(self.checks_run)}")
        lines.append("")

        for severity in ("high", "medium", "low"):
            sev_findings = [f for f in self.findings if f["severity"] == severity]
            if not sev_findings:
                continue
            lines.append(f"## {severity.title()} severity ({len(sev_findings)})")
            lines.append("")
            for f in sev_findings:
                lines.append(
                    f"### {f['finding_id']}: {f['rule_name']} "
                    f"(position {f['rule_position']})"
                )
                lines.append(f"**Check:** `{f['check']}`")
                lines.append("")
                lines.append(f"{f['description']}")
                lines.append("")
                lines.append(f"*Recommendation:* {f['recommendation']}")
                lines.append("")

        if not self.findings:
            lines.append("## No findings")
            lines.append("")
            lines.append("No issues detected by the configured checks.")
            lines.append("")

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines), encoding="utf-8")
        log.info("Markdown report written to %s", path)
