"""capsight web demo for Streamlit Community Cloud.

Deploy: share.streamlit.io -> Create app -> repo Kx96xx/capsight, branch main,
main file web/streamlit_app.py. Python dependencies come from web/requirements.txt and
the tshark system package from packages.txt at the repository root.

Run locally:  pip install streamlit -e . && streamlit run web/streamlit_app.py
"""

from __future__ import annotations

import html
import json
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path

import streamlit as st

# Always use the capsight source next to this file, never a stale installed copy:
# the hosting platform caches pip installs between deploys.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from capsight.cli import render_text
from capsight.redact import Redactor
from capsight.summary import build_summary
from capsight.web import ALLOWED, MAX_BYTES, analyze_upload

SAMPLES = Path(__file__).resolve().parent.parent / "samples" / "synthetic"
REPO = "https://github.com/Kx96xx/capsight"

SAMPLE_LABELS = {
    "attach-user-unknown.pcap": "4G attach: subscriber unknown in the HSS",
    "wrong-apn.pcap": "4G session: wrong APN",
    "ipv4v6-rejected.pcap": "4G session: IPv4v6 not allowed on the APN",
    "radius-accept-then-reject.pcap": "4G session: RADIUS accepts, gateway still rejects",
}

SEVERITY = {
    "failure": ("Failure", "#ef4444", "#fef2f2", "✕"),
    "warning": ("Warning", "#f59e0b", "#fffbeb", "!"),
    "info": ("Note", "#3b82f6", "#eff6ff", "i"),
}

CSS = """
<style>
#MainMenu, footer, header [data-testid="stToolbar"] {visibility: hidden;}
.block-container {padding-top: 2.2rem; max-width: 880px;}
html, body, [class*="css"] {font-family: Inter, -apple-system, "Segoe UI", Roboto, sans-serif;}
.cs-hero {background: linear-gradient(135deg, #0f172a 0%, #1e3a8a 60%, #2563eb 100%);
  border-radius: 18px; padding: 30px 32px 26px; color: #fff; margin-bottom: 22px;
  box-shadow: 0 10px 30px rgba(15, 23, 42, .25);}
.cs-hero h1 {font-size: 2.3rem; font-weight: 800; margin: 0 0 6px; letter-spacing: -.02em;
  color: #fff;}
.cs-hero p {font-size: 1.05rem; opacity: .9; margin: 0 0 14px; line-height: 1.5;}
.cs-chips span {display: inline-block; font-size: .78rem; font-weight: 600; padding: 4px 10px;
  margin: 0 6px 6px 0; border-radius: 999px; background: rgba(255,255,255,.14);
  border: 1px solid rgba(255,255,255,.22);}
.cs-hero a {color: #bfdbfe; font-weight: 600; text-decoration: none;}
.cs-stats {display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 6px 0 18px;}
.cs-stat {background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 14px; padding: 14px 16px;}
.cs-stat .k {font-size: .72rem; text-transform: uppercase; letter-spacing: .06em; color: #64748b;
  font-weight: 700;}
.cs-stat .v {font-size: 1.45rem; font-weight: 800; color: #0f172a; margin-top: 2px;}
.cs-proto {display:inline-block; font-size:.78rem; font-weight:600; color:#334155;
  background:#f1f5f9;
  border:1px solid #e2e8f0; border-radius:8px; padding:3px 9px; margin:0 6px 6px 0;}
.cs-verdict {border-radius: 16px; padding: 18px 20px; margin: 4px 0 18px; display:flex; gap:14px;
  align-items:center;}
.cs-verdict .icon {flex: 0 0 44px; height:44px; border-radius: 12px; display:flex;
  align-items:center; justify-content:center; font-weight:900; font-size:1.3rem; color:#fff;}
.cs-verdict .t {font-size: 1.15rem; font-weight: 800; color:#0f172a;}
.cs-verdict .s {font-size: .92rem; color:#475569; margin-top:2px;}
.cs-card {border: 1px solid #e2e8f0; border-left: 6px solid var(--c); border-radius: 14px;
  padding: 16px 18px 12px; margin: 0 0 14px; background: #fff;
  box-shadow: 0 1px 3px rgba(15,23,42,.06);}
.cs-card .head {display:flex; align-items:center; gap:10px; margin-bottom: 8px; flex-wrap: wrap;}
.cs-badge {font-size:.7rem; font-weight:800; letter-spacing:.06em; text-transform:uppercase;
  color: var(--c); background: var(--bg); border-radius: 999px; padding: 3px 10px;}
.cs-count {font-size:.75rem; font-weight:700; color:#475569; background:#f1f5f9;
  border-radius:999px;
  padding:3px 10px;}
.cs-card .title {font-size: 1.08rem; font-weight: 750; color:#0f172a; margin: 0 0 10px;}
.cs-row {display:grid; grid-template-columns: 64px 1fr; gap: 10px; margin: 0 0 8px;
  font-size: .93rem; line-height: 1.5; color:#334155;}
.cs-row .lbl {font-size:.72rem; font-weight:800; letter-spacing:.06em; color:#64748b;
  text-transform:uppercase; padding-top: 3px;}
.cs-fix {background:#f0fdf4; border:1px solid #bbf7d0; border-radius:10px; padding:10px 12px;
  color:#14532d;}
.cs-pkt {font-family: ui-monospace, Menlo, monospace; font-size:.8rem; background:#f1f5f9;
  border-radius:6px; padding:1px 6px; margin-right:4px; color:#0f172a;}
.cs-mono {font-family: ui-monospace, Menlo, monospace; font-size:.86rem;}
.cs-foot {text-align:center; color:#94a3b8; font-size:.82rem; margin-top: 28px;}
.cs-foot a {color:#64748b;}
@media (max-width: 640px) {
  .cs-stats {grid-template-columns: repeat(2, 1fr);}
  .cs-hero h1 {font-size: 1.8rem;}
}
</style>
"""


def esc(text: object) -> str:
    return html.escape(str(text))


def hero() -> None:
    st.markdown(
        f"""
<div class="cs-hero">
  <h1>📡 capsight</h1>
  <p>Drop in a 4G/5G packet capture and get a plain-English diagnosis of why a device
  couldn't attach, register or get data.</p>
  <div class="cs-chips">
    <span>Diameter S6a</span><span>GTPv2-C</span><span>EPS NAS</span><span>RADIUS</span>
    <span>NGAP</span><span>5G NAS</span><span>PFCP</span><span>GTP-U</span>
  </div>
  <p style="margin:8px 0 0;font-size:.9rem">Open source · runs on tshark ·
  <a href="{REPO}">GitHub ↗</a></p>
</div>
""",
        unsafe_allow_html=True,
    )


def fmt_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 120:
        return f"{seconds:.1f} s"
    if seconds < 7200:
        return f"{seconds / 60:.1f} min"
    return f"{seconds / 3600:.1f} h"


def stats(report, redactor) -> None:
    problems = [f for f in report.findings if f.severity != "info"]
    tx = sum(report.transactions.values())
    cells = [
        ("Packets", f"{report.packets:,}"),
        ("Duration", fmt_duration(report.duration_s)),
        ("Transactions", f"{tx:,}"),
        ("Problems", f"{len(problems)}"),
    ]
    st.markdown(
        '<div class="cs-stats">'
        + "".join(
            f'<div class="cs-stat"><div class="k">{k}</div><div class="v">{v}</div></div>'
            for k, v in cells
        )
        + "</div>",
        unsafe_allow_html=True,
    )
    if report.core_protocols:
        chips = "".join(
            f'<span class="cs-proto">{esc(p)} · {n:,}</span>'
            for p, n in report.core_protocols.items()
        )
        st.markdown(chips, unsafe_allow_html=True)


def verdict_banner(report) -> None:
    fails = [f for f in report.findings if f.severity == "failure"]
    warns = [f for f in report.findings if f.severity == "warning"]
    if len(fails) + len(warns) == 1 and report.core_protocols:
        return  # the single finding card below already says it
    if not report.core_protocols:
        sev, title, sub = (
            "info",
            "No mobile-core signalling found",
            (
                "capsight reads Diameter, GTP, NAS, S1AP/NGAP, PFCP and RADIUS. "
                "Check the capture point and filter."
            ),
        )
    elif fails:
        sev = "failure"
        title = f"{len(fails) + len(warns)} problems found"
        sub = f"Most important: {fails[0].verdict}"
    elif warns:
        sev, title, sub = "warning", f"{len(warns)} warnings", "No hard failure, but worth a look."
    else:
        sev, title, sub = (
            "ok",
            "No known failure patterns found",
            ("Every request that capsight could pair was answered successfully."),
        )
    color, bg, icon = {
        "failure": ("#ef4444", "#fef2f2", "✕"),
        "warning": ("#f59e0b", "#fffbeb", "!"),
        "info": ("#3b82f6", "#eff6ff", "i"),
        "ok": ("#10b981", "#ecfdf5", "✓"),
    }[sev]
    st.markdown(
        f'<div class="cs-verdict" style="background:{bg};border:1px solid {color}33">'
        f'<div class="icon" style="background:{color}">{icon}</div>'
        f'<div><div class="t">{esc(title)}</div><div class="s">{esc(sub)}</div></div></div>',
        unsafe_allow_html=True,
    )


def finding_card(f) -> None:
    label, color, bg, _ = SEVERITY.get(str(f.severity), SEVERITY["info"])
    rows = [("Why", esc(f.why))]
    if f.subscribers:
        shown = ", ".join(f'<span class="cs-mono">{esc(s)}</span>' for s in f.subscribers[:3])
        if len(f.subscribers) > 3:
            shown += f" <span style='color:#64748b'>+{len(f.subscribers) - 3} more</span>"
        rows.append(("Who", shown))
    if f.evidence:
        rows.append(("Where", "".join(f'<span class="cs-pkt">#{n}</span>' for n in f.evidence)))
    if f.fix:
        rows.append(("Fix", f'<div class="cs-fix">{esc(f.fix)}</div>'))
    count = f'<span class="cs-count">{f.count:,}×</span>' if f.count > 1 else ""
    body = "".join(
        f'<div class="cs-row"><div class="lbl">{k}</div><div>{v}</div></div>' for k, v in rows
    )
    st.markdown(
        f'<div class="cs-card" style="--c:{color};--bg:{bg}">'
        f'<div class="head"><span class="cs-badge">{label}</span>{count}</div>'
        f'<div class="title">{esc(f.verdict)}</div>{body}</div>',
        unsafe_allow_html=True,
    )


def overview(report) -> None:
    summary = build_summary(report)
    if summary["top_subscribers"]:
        st.markdown("**Most affected subscribers**")
        st.dataframe(
            [
                {"Subscriber": s["imsi"], "Occurrences": s["count"], "Problem": s["problems"][0]}
                for s in summary["top_subscribers"]
            ],
            hide_index=True,
            use_container_width=True,
        )
    rows = summary["over_time"]
    if len(rows) > 1:
        st.markdown(f"**Problems over time** (UTC, per {summary['bucket_minutes']} min)")
        st.bar_chart({t[11:] if len(t) > 11 else t: n for t, n in rows}, color="#ef4444")


def main() -> None:
    st.set_page_config(
        page_title="capsight · 4G/5G capture diagnosis", page_icon="📡", layout="centered"
    )
    st.markdown(CSS, unsafe_allow_html=True)
    hero()

    tab_up, tab_demo = st.tabs(["⬆️  Upload a capture", "🧪  Try a demo capture"])
    source = None
    with tab_up:
        upload = st.file_uploader(
            "pcap or pcapng, up to 20 MB",
            type=[s.lstrip(".") for s in ALLOWED],
            label_visibility="visible",
        )
        st.caption(
            "🔒 Analyzed in a temporary folder and deleted right away; nothing is stored. "
            "For real subscriber traffic, prefer running capsight locally."
        )
        if upload is not None:
            source = ("upload", upload.name, upload.getvalue())
    with tab_demo:
        samples = sorted(SAMPLES.glob("*.pcap"))
        cols = st.columns(2)
        for i, sample in enumerate(samples):
            with cols[i % 2]:
                selected = st.session_state.get("demo") == sample.name
                if st.button(
                    ("✓  " if selected else "") + SAMPLE_LABELS.get(sample.name, sample.name),
                    key=sample.name,
                    use_container_width=True,
                    type="primary" if selected else "secondary",
                ):
                    st.session_state["demo"] = sample.name
                    st.rerun()
        if "demo" in st.session_state and upload is None:
            name = st.session_state["demo"]
            source = ("demo", name, (SAMPLES / name).read_bytes())

    redact = st.toggle("Redact subscriber numbers, IPs and hosts in the results", value=False)

    if source is None:
        st.markdown(
            f'<div class="cs-foot">capsight is open source · <a href="{REPO}">'
            "github.com/Kx96xx/capsight</a></div>",
            unsafe_allow_html=True,
        )
        return

    _, name, data = source
    if len(data) > MAX_BYTES:
        st.error("File is larger than 20 MB. Run capsight locally for big captures.")
        return
    with st.spinner(f"Decoding {name} with tshark…"):
        with tempfile.NamedTemporaryFile(suffix=Path(name).suffix.lower(), delete=False) as h:
            h.write(data)
        report, error = analyze_upload(h.name, display_name=name)
    if error:
        st.error(error)
        return

    redactor = Redactor() if redact else None
    if redactor is not None:
        doc = redactor.data(asdict(report))
        report.capture = "capture" + Path(name).suffix
        for i, f in enumerate(report.findings):
            d = doc["findings"][i]
            report.findings[i] = type(f)(
                **{
                    **asdict(f),
                    **{k: d[k] for k in ("verdict", "why", "fix")},
                    "subscribers": tuple(d["subscribers"]),
                    "by_subscriber": tuple(tuple(x) for x in d["by_subscriber"]),
                }
            )

    st.markdown(f"#### Results for `{esc(report.capture)}`")
    stats(report, redactor)
    verdict_banner(report)

    ordered = sorted(
        report.findings,
        key=lambda f: ({"failure": 0, "warning": 1}.get(str(f.severity), 2), -f.count),
    )
    for f in ordered:
        finding_card(f)

    if sum(f.count for f in report.findings) >= 20:
        with st.expander("📊 Overview: most affected subscribers and timing"):
            overview(report)

    text = render_text(report)
    doc = asdict(report)
    if redactor is not None:
        text = redactor.text(text)
        doc = redactor.data(doc)
    c1, c2 = st.columns(2)
    c1.download_button(
        "⬇️ Download report (.txt)",
        text,
        file_name=f"{Path(name).stem}-capsight.txt",
        use_container_width=True,
    )
    c2.download_button(
        "⬇️ Download report (.json)",
        json.dumps(doc, indent=2),
        file_name=f"{Path(name).stem}-capsight.json",
        use_container_width=True,
    )
    with st.expander("Plain-text report (same as the CLI)"):
        st.code(text, language=None)
    st.markdown(
        f'<div class="cs-foot">Same engine as the CLI: <span class="cs-mono">'
        f'pip install capsight</span> · <a href="{REPO}">GitHub</a></div>',
        unsafe_allow_html=True,
    )


main()
