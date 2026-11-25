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
from capsight.summary import build_summary, render_summary

SUMMARY_HINT_OCCURRENCES = 100


def render_text(report: Report, summary: dict | None = None) -> str:
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
    if report.subscriber is not None:
        lines += render_timeline(report)
        if not report.timeline:
            return "\n".join(lines)
    if summary is not None:
        return "\n".join(lines + render_summary(summary))
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
    if sum(f.count for f in problems) >= SUMMARY_HINT_OCCURRENCES:
        lines += ["", "tip: add --summary for top problems, most affected subscribers and timing."]
    return "\n".join(lines)


STATUS_MARK = {"ok": "ok", "failed": "FAILED", "no answer": "NO ANSWER", "info": "note"}


def render_timeline(report: Report) -> list[str]:
    lines = ["", f"subscriber {report.subscriber}"]
    steps = report.timeline or []
    if not steps:
        lines.append("  not found in this capture.")
        seen = report.subscribers_seen or []
        if seen:
            shown = ", ".join(seen[:10])
            more = f" (+{len(seen) - 10} more)" if len(seen) > 10 else ""
            lines.append(f"  subscribers in this capture: {shown}{more}")
        else:
            lines.append("  no subscriber identities were found in this capture.")
        return lines
    t0 = steps[0].time
    for step in steps:
        where = "#" + ",#".join(str(n) for n in step.packets)
        mark = STATUS_MARK.get(step.status, step.status)
        line = f"  +{step.time - t0:8.3f}s  {where:<11} {step.protocol:<9} {step.name:<44} {mark}"
        if step.detail:
            line += f"  {step.detail}"
        lines.append(line.rstrip())
    broken = next((s for s in steps if s.status in ("failed", "no answer")), None)
    if broken is None:
        lines.append("  every step above completed.")
    else:
        lines.append(
            f"  stopped at: {broken.name} (packet #{broken.packets[-1]})"
            + (f", {broken.detail}" if broken.detail else "")
        )
    return lines


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
    analyze_cmd.add_argument(
        "--imsi",
        help="show one subscriber's steps in order and only the findings about it",
    )
    analyze_cmd.add_argument(
        "--summary",
        action="store_true",
        help="busy captures: top problems, most affected subscribers, problems over time",
    )
    analyze_cmd.add_argument(
        "--fail-on",
        choices=("failure", "warning", "never"),
        default="never",
        help="exit with code 1 if a finding at this severity or worse is found (for CI/scripts)",
    )
    args = parser.parse_args(argv)

    try:
        report = analyze(args.capture, answer_timeout=args.timeout, imsi=args.imsi)
    except TsharkError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    summary = build_summary(report) if args.summary else None
    if args.format == "json":
        doc = asdict(report)
        if summary is not None:
            doc["summary"] = summary
        print(json.dumps(doc, indent=2))
    else:
        print(render_text(report, summary))
    return 1 if _should_fail(report, args.fail_on) else 0


def _should_fail(report: Report, fail_on: str) -> bool:
    if fail_on == "never":
        return False
    levels = {"failure"} if fail_on == "failure" else {"failure", "warning"}
    return any(f.severity in levels for f in report.findings)


if __name__ == "__main__":
    sys.exit(main())
