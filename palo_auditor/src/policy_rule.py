"""
Normalized representation of a single firewall security policy rule.

The parser produces these from raw Palo Alto output; everything downstream
(audit checks, report writer) consumes these and never touches the raw
format. That keeps a single conversion point and makes the audit logic
trivial to unit test.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class PolicyRule:
    """One Palo Alto security policy rule, normalized.

    Field naming follows Palo Alto's own terminology so engineers reading
    the code can map back to the firewall UI/CLI without translation.

    Lists default to empty lists (not None) so audit checks can iterate
    without None-guards. The 'raw' field preserves the original XML/text
    snippet so an auditor can ask "where exactly did this finding come from?"
    """
    name: str
    position: int
    source_zones: list[str] = field(default_factory=list)
    source_addresses: list[str] = field(default_factory=list)
    destination_zones: list[str] = field(default_factory=list)
    destination_addresses: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    applications: list[str] = field(default_factory=list)
    action: str = "allow"
    log_setting: str | None = None
    log_start: bool = False
    log_end: bool = False
    disabled: bool = False
    description: str = ""
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize for inclusion in JSON reports.

        Excludes the 'raw' field by default — it is large and only useful
        for traceability. Use to_dict_full() if you want it included.
        """
        d = asdict(self)
        d.pop("raw", None)
        return d

    def to_dict_full(self) -> dict[str, Any]:
        """Serialize including the raw original text/XML."""
        return asdict(self)

    def is_any(self, field_name: str) -> bool:
        """True if the named list-field is empty or contains 'any'.

        Palo Alto represents 'any' either as the literal string 'any' in
        the list or, in some output formats, as an empty list. Both mean
        'matches anything', so audit checks need to treat them the same.
        """
        value = getattr(self, field_name)
        if not isinstance(value, list):
            raise ValueError(f"is_any() only works on list fields, not '{field_name}'")
        return len(value) == 0 or "any" in (v.lower() for v in value)
