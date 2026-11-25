"""Summary mode: the shape of a busy capture in one screen.

Top problems by occurrences, the most affected subscribers, and problems over time.
Built from the findings, so it never says more than the rules found.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from capsight.engine import Report

TOP_PROBLEMS = 10
TOP_SUBSCRIBERS = 10
MAX_ROWS = 24
BUCKETS = (1, 2, 5, 10, 15, 30, 60, 120, 240, 360, 720, 1440)  # minutes
BAR = 40


def build_summary(report: Report) -> dict:
    problems = [f for f in report.findings if f.severity != "info"]
    problems.sort(key=lambda f: (f.severity != "failure", -f.count))
    subscribers: set[str] = set()
    per_sub: Counter[str] = Counter()
    per_sub_problems: dict[str, list[str]] = {}
    minutes: Counter[int] = Counter()
    for finding in problems:
        subscribers.update(finding.subscribers)
        for imsi, n in finding.by_subscriber:
            per_sub[imsi] += n
            per_sub_problems.setdefault(imsi, []).append(finding.verdict)
        for minute, n in finding.per_minute:
            minutes[minute] += n
    bucket = _bucket(minutes)
    timeline: Counter[int] = Counter()
    for minute, n in minutes.items():
        timeline[minute - minute % (bucket * 60)] += n
    return {
        "problems": len(problems),
        "occurrences": sum(f.count for f in problems),
        "subscribers_affected": len(subscribers),
        "top_problems": [
            {
                "severity": str(f.severity),
                "verdict": f.verdict,
                "count": f.count,
                "subscribers": len(f.subscribers),
                "first": _clock(f.first_time),
                "last": _clock(f.last_time),
                "rule_id": f.rule_id,
            }
            for f in problems[:TOP_PROBLEMS]
        ],
        "top_subscribers": [
            {"imsi": imsi, "count": n, "problems": per_sub_problems[imsi]}
            for imsi, n in per_sub.most_common(TOP_SUBSCRIBERS)
        ],
        "bucket_minutes": bucket,
        "over_time": [(_clock(t, seconds=False), n) for t, n in sorted(timeline.items())],
    }


def _bucket(minutes: Counter[int]) -> int:
    if not minutes:
        return 1
    first, last = min(minutes), max(minutes)
    for b in BUCKETS:
        size = b * 60
        rows = (last - last % size - (first - first % size)) // size + 1
        if rows <= MAX_ROWS:
            return b
    return BUCKETS[-1]


def _clock(epoch: float | None, seconds: bool = True) -> str | None:
    if epoch is None:
        return None
    fmt = "%Y-%m-%d %H:%M:%S" if seconds else "%Y-%m-%d %H:%M"
    return datetime.fromtimestamp(epoch, UTC).strftime(fmt)


def render_summary(summary: dict) -> list[str]:
    lines = [""]
    if not summary["problems"]:
        lines.append("summary   no problems found.")
        return lines
    lines.append(
        f"summary   {summary['problems']} problem{'s' if summary['problems'] != 1 else ''}, "
        f"{summary['occurrences']:,} occurrence{'s' if summary['occurrences'] != 1 else ''}, "
        f"{summary['subscribers_affected']:,} "
        f"subscriber{'s' if summary['subscribers_affected'] != 1 else ''} affected"
    )
    lines += ["", "TOP PROBLEMS"]
    for i, p in enumerate(summary["top_problems"], 1):
        when = p["first"][11:] if p["first"] else "?"
        if p["last"] and p["last"] != p["first"]:
            when += f" - {p['last'][11:]}"
        n = p["subscribers"]
        subs = f", {n:,} subscriber{'s' if n != 1 else ''}" if n else ""
        lines.append(f"  {i:>2}. {p['severity'].upper():<8} {p['count']:>8,}x  {p['verdict']}")
        lines.append(f"      {'':<8} {'':>9}  {when} UTC{subs}")
    if summary["top_subscribers"]:
        lines += ["", "MOST AFFECTED SUBSCRIBERS"]
        for s in summary["top_subscribers"]:
            first = s["problems"][0]
            more = f" (+{len(s['problems']) - 1} more)" if len(s["problems"]) > 1 else ""
            lines.append(f"  {s['imsi']:<16} {s['count']:>8,}x  {first}{more}")
    rows = summary["over_time"]
    if len(rows) > 1:
        peak = max(n for _, n in rows)
        lines += ["", f"OVER TIME (UTC, per {summary['bucket_minutes']} min)"]
        for label, n in rows:
            bar = "#" * max(1, round(BAR * n / peak))
            lines.append(f"  {label}  {bar} {n:,}")
    return lines
