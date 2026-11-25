"""Glue: decode a capture, correlate, run rules."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from capsight import (
    fields,
    rules_5g,  # noqa: F401  (registers 5G rules)
)
from capsight.correlate import DiameterCorrelator, Gtpv2Correlator, PfcpCorrelator
from capsight.decode import read_packets
from capsight.identity import ngap_imsi_map, s1ap_imsi_map
from capsight.model import Finding, Packet
from capsight.rules import Context, UserPlane, run_rules
from capsight.timeline import (
    Step,
    findings_for,
    normalize_imsi,
    subscriber_timeline,
    subscribers_seen,
)

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
    subscriber: str | None = None
    timeline: list[Step] | None = None
    subscribers_seen: list[str] | None = None


# Packets the rules read one by one; everything else is reduced while streaming.
SIGNALLING = frozenset(("nas-eps", "s1ap", "radius", "ngap", "nas-5gs"))


class Collector:
    """Consumes packets one at a time and keeps only what the rules need.

    Diameter, GTPv2-C and PFCP become (slimmed) transactions, user-plane packets become
    flow counters, and only signalling packets are kept whole. Memory therefore grows with
    the number of procedures, not with the number of packets.
    """

    def __init__(self) -> None:
        self.count = 0
        self.start: float | None = None
        self.end = 0.0
        self.protocols: Counter[str] = Counter()
        self.kept: list[Packet] = []
        self.flows = UserPlane()
        self.diameter = DiameterCorrelator()
        self.gtpv2 = Gtpv2Correlator()
        self.pfcp = PfcpCorrelator()

    def feed(self, packet: Packet) -> None:
        self.count += 1
        if self.start is None:
            self.start = packet.time
        self.end = packet.time
        protos = set(CORE_SET.intersection(packet.protocols))
        if "gtpv2" in protos:
            protos.discard("gtp")  # tshark lists GTPv2-C under gtp too; count it once
        for proto in protos:
            self.protocols[proto] += 1
        self.flows.feed(packet)
        self.diameter.feed(packet)
        self.gtpv2.feed(packet)
        self.pfcp.feed(packet)
        if not SIGNALLING.isdisjoint(packet.protocols):
            self.kept.append(packet)


CORE_SET = frozenset(CORE_PROTOCOLS)


def analyze_packets(
    capture: str,
    packets: Iterable[Packet],
    answer_timeout: float = 5.0,
    imsi: str | None = None,
) -> Report:
    collector = Collector()
    for packet in packets:
        collector.feed(packet)
    diameter = collector.diameter.finish()
    gtpv2 = collector.gtpv2.finish()
    pfcp = collector.pfcp.finish()
    kept = collector.kept
    start = collector.start or 0.0
    end = collector.end
    counts = collector.protocols
    ctx = Context(
        kept,
        diameter,
        gtpv2,
        capture_end=end,
        answer_timeout=answer_timeout,
        inferred_imsi={**s1ap_imsi_map(kept), **ngap_imsi_map(kept)},
        pfcp=pfcp,
        flows=collector.flows,
    )
    report = Report(
        capture=capture,
        packets=collector.count,
        duration_s=round(end - start, 3),
        core_protocols={p: counts[p] for p in CORE_PROTOCOLS if counts[p]},
        transactions={"diameter": len(diameter), "gtpv2": len(gtpv2), "pfcp": len(pfcp)},
        findings=run_rules(ctx),
    )
    if imsi is not None:
        wanted = normalize_imsi(imsi)
        steps = subscriber_timeline(ctx, wanted)
        report.subscriber = wanted
        report.timeline = steps
        report.findings = findings_for(report.findings, wanted, steps)
        if not steps:
            report.subscribers_seen = subscribers_seen(ctx)
    return report


def analyze(capture: Path, answer_timeout: float = 5.0, imsi: str | None = None) -> Report:
    packets = read_packets(capture, fields.ALL, prefs=fields.PREFERENCES)
    return analyze_packets(str(capture), packets, answer_timeout, imsi)
