"""Tests for the audit checks."""
from __future__ import annotations

from src.auditor import PolicyAuditor
from src.policy_rule import PolicyRule


def make_rule(**kwargs) -> PolicyRule:
    """Convenience builder with sane defaults."""
    defaults = dict(
        name="test_rule",
        position=1,
        source_zones=["trust"],
        source_addresses=["10.0.0.0/8"],
        destination_zones=["untrust"],
        destination_addresses=["any"],
        services=["application-default"],
        applications=["web-browsing"],
        action="allow",
        log_setting="default-logging",
        log_end=True,
        disabled=False,
    )
    defaults.update(kwargs)
    return PolicyRule(**defaults)


# --- check_overly_permissive ---------------------------------------------

def test_overly_permissive_flags_any_any_allow():
    rule = make_rule(
        name="catchall",
        source_addresses=["any"],
        destination_addresses=["any"],
        services=["any"],
        applications=["any"],
    )
    auditor = PolicyAuditor([rule], {"flag_any_any_allow": True})
    findings = auditor.check_overly_permissive()
    assert len(findings) == 1
    assert findings[0]["check"] == "overly_permissive"
    assert findings[0]["severity"] == "high"


def test_overly_permissive_does_not_flag_specific_rule():
    rule = make_rule()  # specific source, specific service
    auditor = PolicyAuditor([rule], {"flag_any_any_allow": True})
    assert auditor.check_overly_permissive() == []


def test_overly_permissive_does_not_flag_deny_rule():
    rule = make_rule(
        action="deny",
        source_addresses=["any"],
        destination_addresses=["any"],
        services=["any"],
        applications=["any"],
    )
    auditor = PolicyAuditor([rule], {"flag_any_any_allow": True})
    # Deny-any-any is fine; that's the standard final cleanup rule.
    assert auditor.check_overly_permissive() == []


def test_overly_permissive_does_not_flag_disabled_rule():
    rule = make_rule(
        disabled=True,
        source_addresses=["any"],
        destination_addresses=["any"],
        services=["any"],
        applications=["any"],
    )
    auditor = PolicyAuditor([rule], {"flag_any_any_allow": True})
    # Disabled rules are not active; flagged by check_disabled_rules instead.
    assert auditor.check_overly_permissive() == []


def test_overly_permissive_treats_empty_list_as_any():
    # Some PA outputs use empty list to mean 'any'; we treat it the same.
    rule = make_rule(
        source_addresses=[],
        destination_addresses=[],
        services=[],
        applications=[],
    )
    auditor = PolicyAuditor([rule], {"flag_any_any_allow": True})
    findings = auditor.check_overly_permissive()
    assert len(findings) == 1


# --- check_missing_logging -----------------------------------------------

def test_missing_logging_flags_allow_with_no_logging():
    rule = make_rule(log_setting=None, log_start=False, log_end=False)
    auditor = PolicyAuditor([rule], {"flag_missing_logging": True})
    findings = auditor.check_missing_logging()
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"


def test_missing_logging_satisfied_by_log_end():
    rule = make_rule(log_setting=None, log_start=False, log_end=True)
    auditor = PolicyAuditor([rule], {"flag_missing_logging": True})
    assert auditor.check_missing_logging() == []


def test_missing_logging_satisfied_by_log_setting():
    rule = make_rule(log_setting="forwarder", log_start=False, log_end=False)
    auditor = PolicyAuditor([rule], {"flag_missing_logging": True})
    assert auditor.check_missing_logging() == []


# --- check_risky_services -------------------------------------------------

def test_risky_services_flags_telnet():
    rule = make_rule(services=["telnet"], applications=["telnet"])
    auditor = PolicyAuditor([rule], {"risky_services": ["telnet", "ftp"]})
    findings = auditor.check_risky_services()
    assert len(findings) == 1
    assert "telnet" in findings[0]["description"].lower()


def test_risky_services_case_insensitive():
    rule = make_rule(services=["TELNET"])
    auditor = PolicyAuditor([rule], {"risky_services": ["telnet"]})
    assert len(auditor.check_risky_services()) == 1


def test_risky_services_no_match_returns_empty():
    rule = make_rule(services=["https"], applications=["ssl"])
    auditor = PolicyAuditor([rule], {"risky_services": ["telnet", "ftp"]})
    assert auditor.check_risky_services() == []


def test_risky_services_empty_config_skips_check():
    rule = make_rule(services=["telnet"])
    auditor = PolicyAuditor([rule], {"risky_services": []})
    assert auditor.check_risky_services() == []


# --- check_disabled_rules -------------------------------------------------

def test_disabled_rules_flags_disabled():
    rule = make_rule(disabled=True)
    auditor = PolicyAuditor([rule], {"flag_disabled_rules": True})
    findings = auditor.check_disabled_rules()
    assert len(findings) == 1
    assert findings[0]["severity"] == "low"


# --- run_all integration --------------------------------------------------

def test_run_all_combines_all_enabled_checks():
    rules = [
        make_rule(  # triggers overly_permissive AND missing_logging
            name="bad",
            source_addresses=["any"], destination_addresses=["any"],
            services=["any"], applications=["any"],
            log_setting=None, log_end=False,
        ),
        make_rule(name="ok"),  # clean rule
    ]
    cfg = {
        "flag_any_any_allow": True,
        "flag_missing_logging": True,
        "flag_disabled_rules": True,
        "risky_services": ["telnet"],
    }
    findings = PolicyAuditor(rules, cfg).run_all()
    checks = {f["check"] for f in findings}
    assert "overly_permissive" in checks
    assert "missing_logging" in checks


def test_run_all_skips_disabled_checks():
    rule = make_rule(
        source_addresses=["any"], destination_addresses=["any"],
        services=["any"], applications=["any"],
    )
    cfg = {"flag_any_any_allow": False}  # check disabled
    findings = PolicyAuditor([rule], cfg).run_all()
    assert findings == []
