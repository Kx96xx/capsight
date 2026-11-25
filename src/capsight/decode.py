"""Thin wrapper around tshark. capsight never writes its own dissectors."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections.abc import Iterator, Mapping, Sequence
from functools import lru_cache
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


@lru_cache(maxsize=4)
def known_fields(tshark: str) -> frozenset[str]:
    """Field names this tshark build knows. Unknown -e fields make tshark abort."""
    out = subprocess.run([tshark, "-G", "fields"], capture_output=True, text=True).stdout
    return frozenset(
        parts[2]
        for parts in (line.split("\t") for line in out.splitlines())
        if len(parts) > 2 and parts[0] == "F"
    )


@lru_cache(maxsize=4)
def known_prefs(tshark: str) -> frozenset[str]:
    out = subprocess.run([tshark, "-G", "defaultprefs"], capture_output=True, text=True).stdout
    names = set()
    for line in out.splitlines():
        line = line.lstrip("#").strip()
        if ":" in line and not line.startswith(" "):
            names.add(line.split(":", 1)[0].strip())
    return frozenset(names)


def build_command(
    tshark: str,
    capture: Path,
    extra_fields: Sequence[str] = (),
    display_filter: str = "",
    prefs: Mapping[str, str] | None = None,
) -> list[str]:
    cmd = [tshark, "-r", str(capture), "-n", "-T", "ek"]
    for key, value in (prefs or {}).items():
        cmd += ["-o", f"{key}:{value}"]
    for name in (*BASE_FIELDS, *extra_fields):
        cmd += ["-e", name]
    if display_filter:
        cmd += ["-Y", display_filter]
    return cmd


# Fields kept for packets outside the core protocols: just enough for user-plane rules.
NON_CORE_KEEP = ("ip.src", "ip.dst")
CORE = frozenset(
    ("diameter", "gtpv2", "gtp", "radius", "nas-eps", "s1ap", "ngap", "nas-5gs", "pfcp", "sip")
)
INTERN_MAX = 40  # values shorter than this repeat a lot (IMSIs, causes, hosts): share them

_protocol_cache: dict[str, tuple[str, ...]] = {}


def _protocols(value: str) -> tuple[str, ...]:
    cached = _protocol_cache.get(value)
    if cached is None:
        cached = tuple(sys.intern(p) for p in value.split(":"))
        _protocol_cache[value] = cached
    return cached


def _values(v: object) -> list[str]:
    items = v if isinstance(v, list) else [v]
    return [sys.intern(x) if isinstance(x, str) and len(x) < INTERN_MAX else x for x in items]


def parse_ek_line(line: str, field_names: Sequence[str] = ()) -> Packet | None:
    """Parse one line of `tshark -T ek` output. Index lines return None.

    ek output replaces dots with underscores in field names, which is lossy for fields
    that contain a real underscore (e.g. ``nas_eps.emm.cause``). Passing the requested
    ``field_names`` restores the exact names.

    Packets outside the core protocols keep only their IP addresses, and repeated short
    values are interned, so large captures fit in memory.
    """
    line = line.strip()
    if not line:
        return None
    doc = json.loads(line)
    layers = doc.get("layers")
    if layers is None:
        return None
    names = _name_map(tuple(field_names))
    fields = {sys.intern(names.get(k, k.replace("_", "."))): v for k, v in layers.items()}
    number = int(_first(fields.pop("frame.number")))
    time = float(_first(fields.pop("frame.time_epoch")))
    protocols = _protocols(_first(fields.pop("frame.protocols", "")))
    if CORE.isdisjoint(protocols):
        fields = {k: fields[k] for k in NON_CORE_KEEP if k in fields}
    return Packet(
        number=number,
        time=time,
        protocols=protocols,
        fields={k: _values(v) for k, v in fields.items()},
    )


def _first(v: object) -> str:
    return v[0] if isinstance(v, list) else v  # type: ignore[return-value]


_name_maps: dict[tuple[str, ...], dict[str, str]] = {}


def _name_map(field_names: tuple[str, ...]) -> dict[str, str]:
    cached = _name_maps.get(field_names)
    if cached is None:
        cached = {n.replace(".", "_"): n for n in (*BASE_FIELDS, *field_names)}
        _name_maps[field_names] = cached
    return cached


def read_packets(
    capture: Path,
    extra_fields: Sequence[str] = (),
    display_filter: str = "",
    prefs: Mapping[str, str] | None = None,
) -> Iterator[Packet]:
    """Stream packets from a capture file without loading it all into memory.

    Fields and preferences this tshark version does not know are skipped instead of failing,
    so capsight works across Wireshark versions.
    """
    if not capture.is_file():
        raise TsharkError(f"capture not found: {capture}")
    tshark = find_tshark()
    available = known_fields(tshark)
    if available:
        extra_fields = [f for f in extra_fields if f in available]
    if prefs:
        supported = known_prefs(tshark)
        prefs = {k: v for k, v in prefs.items() if k in supported}
    cmd = build_command(tshark, capture, extra_fields, display_filter, prefs)
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as proc:
        assert proc.stdout is not None
        for line in proc.stdout:
            packet = parse_ek_line(line, extra_fields)
            if packet is not None:
                yield packet
        stderr = proc.stderr.read() if proc.stderr else ""
    if proc.returncode != 0:
        raise TsharkError(stderr.strip() or f"tshark exited with {proc.returncode}")
