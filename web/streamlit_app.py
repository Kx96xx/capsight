"""capsight web demo for Streamlit Community Cloud.

Deploy: share.streamlit.io -> Create app -> repo Kx96xx/capsight, branch main,
main file web/streamlit_app.py. Python dependencies come from web/requirements.txt and
the tshark system package from packages.txt at the repository root.

Run locally:  pip install streamlit -e . && streamlit run web/streamlit_app.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import streamlit as st

from capsight.web import ALLOWED, MAX_BYTES, diagnose

SAMPLES = Path(__file__).resolve().parent.parent / "samples" / "synthetic"

st.set_page_config(page_title="capsight", page_icon="📡", layout="centered")
st.title("capsight")
st.write(
    "Drop in a 4G/5G packet capture (`.pcap` / `.pcapng`, up to 20 MB) and get a "
    "plain-English diagnosis of why a device couldn't attach, register or get data."
)
st.caption(
    "The file is analyzed and deleted right away; nothing is stored. Do not upload captures "
    "with real subscriber data to a public demo: run capsight locally for those. "
    "[Source on GitHub](https://github.com/Kx96xx/capsight)"
)

upload = st.file_uploader("Capture", type=[s.lstrip(".") for s in ALLOWED])
samples = sorted(SAMPLES.glob("*.pcap"))
choice = st.selectbox(
    "...or try a demo capture",
    ["(none)"] + [p.name for p in samples],
)


def run_on_bytes(name: str, data: bytes) -> str:
    if len(data) > MAX_BYTES:
        return "File is larger than 20 MB. Run capsight locally for big captures."
    suffix = Path(name).suffix.lower()
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as handle:
        handle.write(data)
    return diagnose(handle.name).replace(Path(handle.name).name, name)


result = None
if upload is not None:
    result = run_on_bytes(upload.name, upload.getvalue())
elif choice != "(none)":
    sample = SAMPLES / choice
    result = run_on_bytes(sample.name, sample.read_bytes())

if result:
    st.code(result, language=None)
