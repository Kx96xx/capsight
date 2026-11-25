"""Render real `capsight analyze` output on the demo captures into docs/img/demo.svg.

    uv run python scripts/make_demo_svg.py

The SVG is a static terminal screenshot built from actual output, so it never drifts from
what the tool prints.
"""

from __future__ import annotations

import html
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "img" / "demo.svg"
DEMOS = ["attach-user-unknown.pcap", "radius-accept-then-reject.pcap"]

COLORS = {
    "FAILURE": "#ff6b6b",
    "WARNING": "#ffd166",
    "INFO": "#8ecae6",
    "WHY": "#a0a0a0",
    "WHO": "#a0a0a0",
    "WHERE": "#a0a0a0",
    "FIX": "#06d6a0",
}
WIDTH_CHARS = 96
LINE_H = 18
CHAR_W = 8.2


def wrap(line: str) -> list[str]:
    if len(line) <= WIDTH_CHARS:
        return [line]
    out, rest = [], line
    while len(rest) > WIDTH_CHARS:
        cut = rest.rfind(" ", 0, WIDTH_CHARS)
        cut = cut if cut > 20 else WIDTH_CHARS
        out.append(rest[:cut])
        rest = " " * 10 + rest[cut:].lstrip()
    out.append(rest)
    return out


def main() -> None:
    lines: list[tuple[str, str]] = []
    for name in DEMOS:
        rel = f"samples/synthetic/{name}"
        lines.append(("#7aa2f7", f"$ capsight analyze {rel}"))
        result = subprocess.run(
            [sys.executable, "-m", "capsight.cli", "analyze", str(ROOT / rel)],
            capture_output=True,
            text=True,
            check=True,
        )
        for raw in result.stdout.splitlines():
            raw = raw.replace(str(ROOT) + "/", "")
            color = COLORS.get(raw.split(" ", 1)[0], "#e0e0e0")
            for part in wrap(raw):
                lines.append((color, part))
        lines.append(("#e0e0e0", ""))
    width = int(WIDTH_CHARS * CHAR_W + 40)
    height = len(lines) * LINE_H + 50
    rows = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        f'<rect width="{width}" height="{height}" rx="8" fill="#1a1b26"/>',
        '<circle cx="18" cy="16" r="5" fill="#ff5f56"/>',
        '<circle cx="34" cy="16" r="5" fill="#ffbd2e"/>',
        '<circle cx="50" cy="16" r="5" fill="#27c93f"/>',
        '<g font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="13">',
    ]
    for i, (color, text) in enumerate(lines):
        y = 44 + i * LINE_H
        rows.append(
            f'<text x="20" y="{y}" fill="{color}" xml:space="preserve">{html.escape(text)}</text>'
        )
    rows += ["</g>", "</svg>"]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(rows) + "\n")
    print(OUT.relative_to(ROOT), len(lines), "lines")


if __name__ == "__main__":
    main()
