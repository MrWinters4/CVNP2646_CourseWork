"""Tests for the XML policy parser."""
from __future__ import annotations

from pathlib import Path

import pytest

from src.parser import ParseError, parse_policy_xml

SAMPLE_XML = Path(__file__).parent.parent / "data" / "samples" / "policy_export.xml"


def test_parse_sample_returns_six_rules():
    rules = parse_policy_xml(SAMPLE_XML.read_text())
    assert len(rules) == 6


def test_parse_assigns_sequential_positions_starting_at_one():
    rules = parse_policy_xml(SAMPLE_XML.read_text())
    assert [r.position for r in rules] == [1, 2, 3, 4, 5, 6]


def test_parse_extracts_rule_name_from_attribute():
    rules = parse_policy_xml(SAMPLE_XML.read_text())
    assert rules[0].name == "Allow_Internal_to_Internet"
    assert rules[1].name == "Permissive_Catchall"


def test_parse_extracts_zones_and_addresses_as_lists():
    rules = parse_policy_xml(SAMPLE_XML.read_text())
    rule = rules[0]
    assert rule.source_zones == ["trust"]
    assert rule.destination_zones == ["untrust"]
    assert rule.source_addresses == ["10.0.0.0/8"]
    assert rule.destination_addresses == ["any"]


def test_parse_extracts_multiple_applications():
    rules = parse_policy_xml(SAMPLE_XML.read_text())
    rule = rules[0]
    assert rule.applications == ["web-browsing", "ssl"]


def test_parse_yes_no_to_bool_for_disabled():
    rules = parse_policy_xml(SAMPLE_XML.read_text())
    # Old_VPN_Rule has <disabled>yes</disabled>
    old_vpn = next(r for r in rules if r.name == "Old_VPN_Rule")
    assert old_vpn.disabled is True
    # Allow_Internal_to_Internet has <disabled>no</disabled>
    allow_internal = next(r for r in rules if r.name == "Allow_Internal_to_Internet")
    assert allow_internal.disabled is False


def test_parse_missing_log_setting_yields_none():
    rules = parse_policy_xml(SAMPLE_XML.read_text())
    # Permissive_Catchall has no <log-setting> element
    catchall = next(r for r in rules if r.name == "Permissive_Catchall")
    assert catchall.log_setting is None


def test_parse_invalid_xml_raises_parse_error():
    with pytest.raises(ParseError):
        parse_policy_xml("<not-valid-xml")


def test_parse_empty_rulebase_returns_empty_list():
    xml = '<response status="success"><result><rules></rules></result></response>'
    rules = parse_policy_xml(xml)
    assert rules == []
