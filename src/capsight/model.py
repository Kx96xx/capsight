"""Core data model shared by the decoder, correlator and rule engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


@dataclass(frozen=True)
class Packet:
    """One decoded frame, reduced to the fields capsight cares about."""

    number: int
    time: float
    protocols: tuple[str, ...]
    fields: dict[str, list[str]] = field(default_factory=dict)

    def has(self, protocol: str) -> bool:
        return protocol in self.protocols

    def first(self, name: str) -> str | None:
        values = self.fields.get(name)
        return values[0] if values else None


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    FAILURE = "failure"


@dataclass(frozen=True)
class Finding:
    """A diagnosis produced by a rule. Every finding cites its evidence packets."""

    rule_id: str
    severity: Severity
    verdict: str
    why: str
    evidence: tuple[int, ...]
    fix: str = ""
