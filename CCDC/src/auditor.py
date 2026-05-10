"""
Audit checks against parsed PolicyRule objects.

Each check is a method that returns a list of finding dicts. Checks are
pure (no I/O, no global state) which makes them trivial to unit test.

Severity scheme:
  high   — actively dangerous policy that an auditor will flag immediately
  medium — meaningful weakness, should be addressed but not emergency
  low    — hygiene issue, address in next change window
"""
from __future__ import annotations

import logging
from typing import Any

from .policy_rule import PolicyRule

log = logging.getLogger(__name__)

# Type alias for finding dicts. Kept as a dict (not a class) because the
# whole point is to serialize them straight to JSON.
Finding = dict[str, Any]


class PolicyAuditor:
    """Runs configured audit checks against a list of policy rules."""

    def __init__(self, rules: list[PolicyRule], audit_rules_config: dict[str, Any]):
        """
        rules: parsed PolicyRule objects to audit
        audit_rules_config: the 'audit_rules' block from the audit config,
            controlling which checks run and their parameters
        """
        self.rules = rules
        self.cfg = audit_rules_config
        self._finding_counter = 0

    # --- Public API -------------------------------------------------------

    def run_all(self) -> list[Finding]:
        """Run every enabled check and return the combined finding list."""
        findings: list[Finding] = []

        # The check methods are listed explicitly (rather than discovered
        # via reflection) so it is obvious from this file what runs and
        # in what order.
        check_map = [
            ("flag_any_any_allow", self.check_overly_permissive),
            ("flag_missing_logging", self.check_missing_logging),
            ("flag_disabled_rules", self.check_disabled_rules),
            ("risky_services", self.check_risky_services),
        ]

        for cfg_key, check_fn in check_map:
            if cfg_key not in self.cfg:
                continue
            # For boolean flags, skip if False. For list configs (like
            # risky_services), skip if empty.
            value = self.cfg[cfg_key]
            if isinstance(value, bool) and not value:
                continue
            if isinstance(value, list) and not value:
                continue
            log.debug("Running check: %s", check_fn.__name__)
            findings.extend(check_fn())

        log.info("Audit complete: %d findings across %d rules",
                 len(findings), len(self.rules))
        return findings

    def checks_enabled(self) -> list[str]:
        """Return the list of check identifiers that will actually run."""
        enabled = []
        if self.cfg.get("flag_any_any_allow"):
            enabled.append("overly_permissive")
        if self.cfg.get("flag_missing_logging"):
            enabled.append("missing_logging")
        if self.cfg.get("flag_disabled_rules"):
            enabled.append("disabled_rules")
        if self.cfg.get("risky_services"):
            enabled.append("risky_services")
        return enabled

    # --- Individual checks ------------------------------------------------

    def check_overly_permissive(self) -> list[Finding]:
        """Flag rules that allow any-source to any-destination on any service.

        These 'any/any/allow' rules are the textbook audit finding — they
        defeat the purpose of having a firewall at all if used carelessly.
        We only flag rules with action=allow; deny-any-any is fine and
        common as a final cleanup rule.
        """
        findings = []
        for rule in self.rules:
            if rule.disabled or rule.action.lower() != "allow":
                continue
            if (rule.is_any("source_addresses")
                    and rule.is_any("destination_addresses")
                    and rule.is_any("services")
                    and rule.is_any("applications")):
                findings.append(self._make_finding(
                    rule=rule,
                    check="overly_permissive",
                    severity="high",
                    description=(
                        "Rule permits any source to any destination on any "
                        "service/application with action=allow"
                    ),
                    recommendation=(
                        "Restrict at least one of source, destination, or "
                        "service to specific values, or remove the rule"
                    ),
                ))
        return findings

    def check_missing_logging(self) -> list[Finding]:
        """Flag allow-rules with no logging configured.

        For audit and incident response, allow-rules without logs are
        invisible — there is no record of what traffic actually used the
        rule. We require either log-end OR a log-setting (forwarding
        profile). Deny-rules can also lack logging but that is lower
        severity; this check focuses on allow.
        """
        findings = []
        for rule in self.rules:
            if rule.disabled or rule.action.lower() != "allow":
                continue
            has_logging = rule.log_end or rule.log_start or bool(rule.log_setting)
            if not has_logging:
                findings.append(self._make_finding(
                    rule=rule,
                    check="missing_logging",
                    severity="medium",
                    description=(
                        "Allow-rule has no logging enabled "
                        "(log-start, log-end, and log-setting are all unset)"
                    ),
                    recommendation=(
                        "Enable log-end at minimum, or attach a log "
                        "forwarding profile via log-setting"
                    ),
                ))
        return findings

    def check_disabled_rules(self) -> list[Finding]:
        """Flag rules that are disabled but still present in policy.

        Disabled rules are not active, but they clutter the policy and
        suggest incomplete change management. Auditors flag them as a
        hygiene issue.
        """
        findings = []
        for rule in self.rules:
            if rule.disabled:
                findings.append(self._make_finding(
                    rule=rule,
                    check="disabled_rules",
                    severity="low",
                    description="Rule is disabled but still present in the policy",
                    recommendation=(
                        "Remove disabled rules during the next change window, "
                        "or document why the rule is being kept disabled"
                    ),
                ))
        return findings

    def check_risky_services(self) -> list[Finding]:
        """Flag rules that permit services on the configured risky list.

        'Risky services' are typically cleartext or unauthenticated
        legacy protocols (telnet, ftp, rsh, tftp). The list comes from
        config so the team can tune it per engagement.

        We match against both the services list AND the applications list,
        because Palo Alto can express the same protocol either way.
        """
        risky = {s.lower() for s in self.cfg.get("risky_services", [])}
        if not risky:
            return []

        findings = []
        for rule in self.rules:
            if rule.disabled or rule.action.lower() != "allow":
                continue
            matched = []
            for svc in rule.services:
                if svc.lower() in risky:
                    matched.append(svc)
            for app in rule.applications:
                if app.lower() in risky and app not in matched:
                    matched.append(app)

            if matched:
                findings.append(self._make_finding(
                    rule=rule,
                    check="risky_services",
                    severity="medium",
                    description=(
                        f"Rule permits risky service(s)/application(s): "
                        f"{', '.join(matched)}"
                    ),
                    recommendation=(
                        "Replace cleartext/legacy protocols with secure "
                        "alternatives (SSH for telnet, SFTP for FTP), or "
                        "scope the rule to specific source/destination IPs"
                    ),
                ))
        return findings

    # --- Helpers ----------------------------------------------------------

    def _make_finding(
        self,
        rule: PolicyRule,
        check: str,
        severity: str,
        description: str,
        recommendation: str,
    ) -> Finding:
        """Build a finding dict with a sequential ID."""
        self._finding_counter += 1
        return {
            "finding_id": f"F{self._finding_counter:03d}",
            "rule_name": rule.name,
            "rule_position": rule.position,
            "check": check,
            "severity": severity,
            "description": description,
            "recommendation": recommendation,
        }
