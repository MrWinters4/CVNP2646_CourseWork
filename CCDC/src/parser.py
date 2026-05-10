"""
Parser for Palo Alto security policy XML output.

The Palo Alto XML API returns security policy in a structure roughly like:

  <response status="success">
    <result>
      <rules>
        <entry name="Rule_1">
          <from><member>trust</member></from>
          <to><member>untrust</member></to>
          <source><member>any</member></source>
          <destination><member>any</member></destination>
          <service><member>application-default</member></service>
          <application><member>any</member></application>
          <action>allow</action>
          <log-setting>default-logging</log-setting>
          <log-start>no</log-start>
          <log-end>yes</log-end>
          <disabled>no</disabled>
          <description>Allow internal users to internet</description>
        </entry>
        ...
      </rules>
    </result>
  </response>

This module turns that XML into a list of PolicyRule objects.
"""
from __future__ import annotations

import logging
import xml.etree.ElementTree as ET

from .policy_rule import PolicyRule

log = logging.getLogger(__name__)


class ParseError(Exception):
    """Raised when policy XML/text cannot be parsed."""


def parse_policy_xml(xml_text: str) -> list[PolicyRule]:
    """Parse Palo Alto security policy XML into PolicyRule objects.

    Position numbering starts at 1 to match how Palo Alto displays rule
    order in its UI (humans count from 1; auditors expect that).
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ParseError(f"Invalid XML: {exc}") from exc

    # Find every <entry> that represents a rule. We use './/entry' to
    # search recursively because the exact path varies depending on
    # whether the XML came from the running config or a candidate
    # config query.
    entries = root.findall(".//rules/entry")
    if not entries:
        # Some PAN-OS responses wrap rules differently; try a looser match.
        entries = root.findall(".//entry")
        log.warning(
            "No <rules>/<entry> found, falling back to all <entry> elements (%d found)",
            len(entries),
        )

    rules: list[PolicyRule] = []
    for position, entry in enumerate(entries, start=1):
        try:
            rules.append(_entry_to_rule(entry, position))
        except Exception as exc:
            # One bad rule should not abort the whole audit — log it
            # and keep going. The auditor sees a count mismatch in the
            # report which they can investigate.
            log.error(
                "Failed to parse rule at position %d: %s", position, exc
            )

    log.info("Parsed %d rules from policy XML", len(rules))
    return rules


def _entry_to_rule(entry: ET.Element, position: int) -> PolicyRule:
    """Convert a single <entry> element into a PolicyRule."""
    name = entry.attrib.get("name", f"unnamed_rule_{position}")

    rule = PolicyRule(
        name=name,
        position=position,
        source_zones=_members(entry, "from"),
        destination_zones=_members(entry, "to"),
        source_addresses=_members(entry, "source"),
        destination_addresses=_members(entry, "destination"),
        services=_members(entry, "service"),
        applications=_members(entry, "application"),
        action=_text(entry, "action", default="allow"),
        log_setting=_text(entry, "log-setting", default=None) or None,
        log_start=_yes_no(entry, "log-start", default=False),
        log_end=_yes_no(entry, "log-end", default=False),
        disabled=_yes_no(entry, "disabled", default=False),
        description=_text(entry, "description", default=""),
        raw=ET.tostring(entry, encoding="unicode"),
    )
    return rule


def _members(parent: ET.Element, child_tag: str) -> list[str]:
    """Extract <member> texts from a child element, e.g.
       <source><member>10.0.0.0/8</member><member>any</member></source>
       -> ['10.0.0.0/8', 'any']
    """
    child = parent.find(child_tag)
    if child is None:
        return []
    return [m.text.strip() for m in child.findall("member") if m.text]


def _text(parent: ET.Element, tag: str, default: str | None = "") -> str | None:
    """Extract the text content of a direct child element, with a default."""
    el = parent.find(tag)
    if el is None or el.text is None:
        return default
    return el.text.strip()


def _yes_no(parent: ET.Element, tag: str, default: bool = False) -> bool:
    """Palo Alto uses 'yes'/'no' strings for booleans. Convert to bool."""
    text = _text(parent, tag, default=None)
    if text is None:
        return default
    return text.strip().lower() == "yes"
