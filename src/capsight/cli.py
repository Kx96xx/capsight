"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from capsight import __version__
from capsight.decode import TsharkError, read_packets

# Protocols capsight will diagnose, in display order.
CORE_PROTOCOLS = (
    "diameter",
    "gtpv2",
    "gtp",
    "nas-eps",
    "s1ap",
    "ngap",
    "nas-5gs",
    "pfcp",
    "http2",
    "sip",
)


def summarize(capture: Path) -> dict:
    counts: Counter[str] = Counter()
    total = 0
    first = last = None
    for packet in read_packets(capture):
        total += 1
        first = packet.time if first is None else first
        last = packet.time
        for proto in set(packet.protocols) & set(CORE_PROTOCOLS):
            counts[proto] += 1
    return {
        "capture": str(capture),
        "packets": total,
        "duration_s": round((last or 0) - (first or 0), 3),
        "core_protocols": {p: counts[p] for p in CORE_PROTOCOLS if counts[p]},
        "findings": [],
    }


def render_text(summary: dict) -> str:
    lines = [
        f"capture   {summary['capture']}",
        f"packets   {summary['packets']}  ({summary['duration_s']} s)",
    ]
    protos = summary["core_protocols"]
    if protos:
        lines.append("protocols " + ", ".join(f"{p}={n}" for p, n in protos.items()))
    else:
        lines.append("protocols no mobile-core signalling found")
    lines.append("findings  none yet (rule engine lands in phase 1)")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="capsight", description=__doc__)
    parser.add_argument("--version", action="version", version=f"capsight {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="analyze a capture file")
    analyze.add_argument("capture", type=Path)
    analyze.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)

    try:
        summary = summarize(args.capture)
    except TsharkError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2) if args.format == "json" else render_text(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
