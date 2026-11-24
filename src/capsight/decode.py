"""Thin wrapper around tshark. capsight never writes its own dissectors."""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Iterator, Sequence
from pathlib import Path

from capsight.model import Packet

BASE_FIELDS = ("frame.number", "frame.time_epoch", "frame.protocols")


class TsharkError(RuntimeError):
    pass


def find_tshark() -> str:
    path = shutil.which("tshark")
    if path is None:
        raise TsharkError("tshark not found on PATH. Install Wireshark 4.x.")
    return path


def build_command(
    tshark: str, capture: Path, extra_fields: Sequence[str] = (), display_filter: str = ""
) -> list[str]:
    cmd = [tshark, "-r", str(capture), "-n", "-T", "ek"]
    for name in (*BASE_FIELDS, *extra_fields):
        cmd += ["-e", name]
    if display_filter:
        cmd += ["-Y", display_filter]
    return cmd


def parse_ek_line(line: str, field_names: Sequence[str] = ()) -> Packet | None:
    """Parse one line of `tshark -T ek` output. Index lines return None.

    ek output replaces dots with underscores in field names, which is lossy for fields
    that contain a real underscore (e.g. ``nas_eps.emm.cause``). Passing the requested
    ``field_names`` restores the exact names.
    """
    line = line.strip()
    if not line:
        return None
    doc = json.loads(line)
    layers = doc.get("layers")
    if layers is None:
        return None
    names = {n.replace(".", "_"): n for n in (*BASE_FIELDS, *field_names)}
    fields = {
        names.get(k, k.replace("_", ".")): v if isinstance(v, list) else [v]
        for k, v in layers.items()
    }
    number = int(fields.pop("frame.number")[0])
    time = float(fields.pop("frame.time_epoch")[0])
    protocols = tuple(fields.pop("frame.protocols", [""])[0].split(":"))
    return Packet(number=number, time=time, protocols=protocols, fields=fields)


def read_packets(
    capture: Path, extra_fields: Sequence[str] = (), display_filter: str = ""
) -> Iterator[Packet]:
    """Stream packets from a capture file without loading it all into memory."""
    if not capture.is_file():
        raise TsharkError(f"capture not found: {capture}")
    cmd = build_command(find_tshark(), capture, extra_fields, display_filter)
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as proc:
        assert proc.stdout is not None
        for line in proc.stdout:
            packet = parse_ek_line(line, extra_fields)
            if packet is not None:
                yield packet
        stderr = proc.stderr.read() if proc.stderr else ""
    if proc.returncode != 0:
        raise TsharkError(stderr.strip() or f"tshark exited with {proc.returncode}")
