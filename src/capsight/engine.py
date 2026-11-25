"""Glue: decode a capture, correlate, run rules."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from capsight import (
    fields,
    rules_5g,  # noqa: F401  (registers 5G rules)
)
from capsight.correlate import correlate_diameter, correlate_gtpv2, correlate_pfcp
from capsight.decode import read_packets
from capsight.identity import ngap_imsi_map, s1ap_imsi_map
from capsight.model import Finding, Packet
from capsight.rules import Context, run_rules

CORE_PROTOCOLS = (
    "diameter",
    "gtpv2",
    "radius",
    "nas-eps",
    "s1ap",
    "ngap",
    "nas-5gs",
    "pfcp",
    "gtp",
    "sip",
)


@dataclass
class Report:
    capture: str
    packets: int
    duration_s: float
    core_protocols: dict[str, int]
    transactions: dict[str, int]
    findings: list[Finding] = field(default_factory=list)


def analyze_packets(capture: str, packets: list[Packet], answer_timeout: float = 5.0) -> Report:
    counts: Counter[str] = Counter()
    for packet in packets:
        for proto in set(packet.protocols) & set(CORE_PROTOCOLS):
            counts[proto] += 1
    diameter = correlate_diameter(packets)
    gtpv2 = correlate_gtpv2(packets)
    pfcp = correlate_pfcp(packets)
    start = packets[0].time if packets else 0.0
    end = packets[-1].time if packets else 0.0
    ctx = Context(
        packets,
        diameter,
        gtpv2,
        capture_end=end,
        answer_timeout=answer_timeout,
        inferred_imsi={**s1ap_imsi_map(packets), **ngap_imsi_map(packets)},
        pfcp=pfcp,
    )
    return Report(
        capture=capture,
        packets=len(packets),
        duration_s=round(end - start, 3),
        core_protocols={p: counts[p] for p in CORE_PROTOCOLS if counts[p]},
        transactions={"diameter": len(diameter), "gtpv2": len(gtpv2), "pfcp": len(pfcp)},
        findings=run_rules(ctx),
    )


def analyze(capture: Path, answer_timeout: float = 5.0) -> Report:
    packets = list(read_packets(capture, fields.ALL, prefs=fields.PREFERENCES))
    return analyze_packets(str(capture), packets, answer_timeout)
