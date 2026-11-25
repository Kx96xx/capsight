"""Upload-a-capture web demo (Gradio). Install with: pip install "capsight[web]".

    capsight-web            # http://127.0.0.1:7860

Uploads are analyzed in a temporary directory and deleted right after the request.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from capsight.cli import render_text
from capsight.decode import TsharkError
from capsight.engine import analyze

MAX_BYTES = 20 * 1024 * 1024
ALLOWED = (".pcap", ".pcapng", ".cap")
# Demo captures: from a source checkout, or CAPSIGHT_SAMPLES when installed (e.g. Docker).
SAMPLES = Path(
    os.environ.get(
        "CAPSIGHT_SAMPLES",
        Path(__file__).resolve().parent.parent.parent / "samples" / "synthetic",
    )
)

INTRO = """# capsight
Drop in a 4G/5G packet capture (`.pcap` / `.pcapng`, up to 20 MB) and get a plain-English
diagnosis of why a device couldn't attach, register or get data.

The file is analyzed and deleted right away; nothing is stored. Do not upload captures with
real subscriber data to a public demo: run capsight locally for those.
"""


def diagnose(path: str | None) -> str:
    """Analyze an uploaded file and return the text report (or a readable error)."""
    if not path:
        return "Upload a capture first."
    src = Path(path)
    if src.suffix.lower() not in ALLOWED:
        return f"Unsupported file type {src.suffix!r}. Use .pcap or .pcapng."
    if src.stat().st_size > MAX_BYTES:
        return "File is larger than 20 MB. Run capsight locally for big captures."
    workdir = Path(tempfile.mkdtemp(prefix="capsight-"))
    try:
        copy = workdir / f"upload{src.suffix.lower()}"
        shutil.copyfile(src, copy)
        report = analyze(copy)
        report.capture = src.name
        return render_text(report)
    except TsharkError as exc:
        return f"Could not read this capture: {exc}"
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
        if not _is_sample(src):
            src.unlink(missing_ok=True)


def _is_sample(path: Path) -> bool:
    """Example files (or the copy the web framework makes of them) are never deleted."""
    if path.parent == SAMPLES:
        return True
    original = SAMPLES / path.name
    return original.is_file() and original.stat().st_size == path.stat().st_size


def build_app():
    import gradio as gr

    examples = [[str(p)] for p in sorted(SAMPLES.glob("*.pcap"))]
    with gr.Blocks(title="capsight") as app:
        gr.Markdown(INTRO)
        upload = gr.File(label="Capture", file_types=list(ALLOWED), type="filepath")
        button = gr.Button("Diagnose", variant="primary")
        output = gr.Code(label="Diagnosis", language=None, lines=18)
        button.click(diagnose, inputs=upload, outputs=output)
        if examples:
            gr.Examples(examples, inputs=upload, label="Try a demo capture")
    return app


def main() -> None:
    build_app().launch()


if __name__ == "__main__":
    main()
