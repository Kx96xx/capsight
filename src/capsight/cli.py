"""capsight: plain-English diagnosis of mobile-core packet captures."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from capsight import __version__
from capsight.decode import TsharkError
from capsight.engine import Report, analyze


def render_text(report: Report) -> str:
    lines = [
        f"capture   {report.capture}",
        f"packets   {report.packets}  ({report.duration_s} s)",
    ]
    protos = report.core_protocols
    lines.append(
        "protocols "
        + (
            ", ".join(f"{p}={n}" for p, n in protos.items())
            if protos
            else "no mobile-core signalling found"
        )
    )
    problems = [f for f in report.findings if f.severity != "info"]
    if not problems:
        lines += ["", "No known failure patterns found."]
    if not report.findings:
        return "\n".join(lines)
    for finding in report.findings:
        lines += ["", f"{finding.severity.upper():<9} {finding.verdict}"]
        lines.append(f"{'WHY':<9} {finding.why}")
        if finding.subscribers:
            shown = ", ".join(finding.subscribers[:3])
            more = (
                f" (+{len(finding.subscribers) - 3} more)" if len(finding.subscribers) > 3 else ""
            )
            lines.append(f"{'WHO':<9} {shown}{more}")
        lines.append(f"{'WHERE':<9} packets " + ", ".join(f"#{n}" for n in finding.evidence))
        if finding.fix:
            lines.append(f"{'FIX':<9} {finding.fix}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="capsight", description=__doc__)
    parser.add_argument("--version", action="version", version=f"capsight {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze_cmd = sub.add_parser("analyze", help="analyze a capture file")
    analyze_cmd.add_argument("capture", type=Path)
    analyze_cmd.add_argument("--format", choices=("text", "json"), default="text")
    analyze_cmd.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="seconds without an answer before a request counts as unanswered (default 5)",
    )
    args = parser.parse_args(argv)

    try:
        report = analyze(args.capture, answer_timeout=args.timeout)
    except TsharkError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(asdict(report), indent=2) if args.format == "json" else render_text(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
