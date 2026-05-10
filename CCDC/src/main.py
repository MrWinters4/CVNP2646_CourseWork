"""
CLI entry point for the Palo Alto firewall policy auditor.

Pipeline:
  1. Parse args
  2. Configure logging
  3. Load and validate config
  4. Fetch policy (live API, SSH, or file)
  5. Save raw export for traceability
  6. Parse policy into PolicyRule objects
  7. Run audit checks
  8. Write JSON report and Markdown summary

Each stage logs its progress and converts internal exceptions into clean
error messages with non-zero exit codes.
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .auditor import PolicyAuditor
from .config import ConfigError, load_config
from .firewall_client import FirewallError, fetch_policy
from .parser import ParseError, parse_policy_xml
from .report import AuditReport

# Exit codes that the CCDC scoring engine (or a wrapping shell script)
# can branch on.
EXIT_OK = 0
EXIT_CONFIG_ERROR = 2
EXIT_FIREWALL_ERROR = 3
EXIT_PARSE_ERROR = 4
EXIT_UNEXPECTED_ERROR = 10


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="palo-auditor",
        description=(
            "Export and audit Palo Alto firewall security policy. "
            "Produces a JSON audit report, a Markdown summary, and a "
            "preserved raw policy export."
        ),
    )
    p.add_argument(
        "--config", required=True, type=Path,
        help="Path to audit config JSON (see docs/CONFIG.md)",
    )
    p.add_argument(
        "--output", type=Path, default=Path("reports/audit_report.json"),
        help="Path for the JSON audit report (default: reports/audit_report.json)",
    )
    p.add_argument(
        "--summary", type=Path, default=None,
        help="Path for the Markdown summary (default: <output>.md alongside JSON)",
    )
    p.add_argument(
        "--raw-export", type=Path, default=None,
        help="Path to save the raw policy export (default: reports/raw_policy.xml)",
    )
    p.add_argument(
        "--offline", type=Path, default=None,
        help="Force file mode using the given policy export path "
             "(overrides target.mode in config)",
    )
    p.add_argument(
        "--include-rules", action="store_true",
        help="Embed all parsed rules in the JSON report (large output)",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Validate config and exit without connecting to the firewall",
    )
    p.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable DEBUG-level logging",
    )
    return p


def configure_logging(verbose: bool, log_file: Path | None = None) -> None:
    """Configure root logging to stderr and (optionally) a file.

    We use stderr so that any future stdout-formatted output (e.g. JSON
    piped to another tool) is not mixed with log lines.
    """
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(level=level, format=fmt, handlers=handlers, force=True)


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    configure_logging(args.verbose, log_file=Path("reports/auditor.log"))
    log = logging.getLogger("main")

    # 1. Load config.
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        log.error("Config error: %s", exc)
        return EXIT_CONFIG_ERROR

    # If --offline is given, override the target mode and config_file.
    # This is convenient for re-running an audit against a saved export.
    if args.offline is not None:
        log.info("Forcing offline mode using %s", args.offline)
        cfg["target"]["mode"] = "file"
        cfg["target"]["config_file"] = str(args.offline)
        # File mode does not need credentials, so blank them out.
        cfg["target"].pop("api_key", None)
        cfg["target"].pop("password", None)

    if args.dry_run:
        log.info(
            "Dry run: config OK. Audit '%s' against firewall '%s' "
            "(mode=%s)",
            cfg["audit_name"],
            cfg["target"]["name"],
            cfg["target"].get("mode", "live"),
        )
        return EXIT_OK

    # 2. Fetch raw policy.
    raw_export_path = args.raw_export or Path("reports/raw_policy.xml")
    try:
        raw_text = fetch_policy(cfg["target"], save_raw_to=raw_export_path)
    except FirewallError as exc:
        log.error("Firewall error: %s", exc)
        return EXIT_FIREWALL_ERROR

    # 3. Parse.
    try:
        rules = parse_policy_xml(raw_text)
    except ParseError as exc:
        log.error("Parse error: %s", exc)
        log.error(
            "Raw export was saved to %s — inspect it to debug the parser",
            raw_export_path,
        )
        return EXIT_PARSE_ERROR

    if not rules:
        log.warning(
            "Parser produced zero rules. The policy may genuinely be empty, "
            "or the response format may differ from what the parser expects. "
            "Check %s.", raw_export_path,
        )

    # 4. Audit.
    auditor = PolicyAuditor(rules, cfg["audit_rules"])
    findings = auditor.run_all()

    # 5. Build and write the report.
    report = AuditReport(
        audit_name=cfg["audit_name"],
        auditor=cfg.get("auditor", "unknown"),
        firewall_name=cfg["target"]["name"],
        rules=rules,
        findings=findings,
        checks_run=auditor.checks_enabled(),
    )

    report.write_json(args.output, include_rules=args.include_rules)

    summary_path = args.summary or args.output.with_suffix(".md")
    report.write_markdown(summary_path)

    # 6. Print a one-line summary to stdout for shell-pipeline use.
    s = report.summary()
    print(
        f"Audit complete: {s['total_findings']} findings "
        f"(high={s['findings_by_severity']['high']}, "
        f"medium={s['findings_by_severity']['medium']}, "
        f"low={s['findings_by_severity']['low']}) "
        f"across {s['total_rules_analyzed']} rules. "
        f"Report: {args.output}"
    )
    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted.\n")
        sys.exit(130)
    except Exception as exc:  # pragma: no cover - last-resort safety net
        logging.exception("Unexpected error: %s", exc)
        sys.exit(EXIT_UNEXPECTED_ERROR)
