"""--redact: make capsight output safe to paste into a ticket or chat.

Subscriber numbers (IMSI, MSISDN), IP addresses and host / realm names are replaced with
stable placeholders. The same value always maps to the same placeholder within one run, so
"which subscribers are the same" survives; the original values never appear.

IMSIs keep their first 5 digits (MCC + 2-digit MNC) because the home network is often the
point of the diagnosis (roaming, partner). Use --redact-all to hide those too.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

DIGITS = re.compile(r"(?<![\w.])\d{10,15}(?![\w.])")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
# host names / Diameter realms: three or more labels, last one alphabetic (not file names)
HOST = re.compile(
    r"(?<![\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){2,}[A-Za-z]{2,24}(?![\w-])"
)
FILE_SUFFIXES = (".pcap", ".pcapng", ".cap", ".json", ".txt")


class Redactor:
    def __init__(self, keep_plmn: bool = True) -> None:
        self.keep_plmn = keep_plmn
        self.maps: dict[str, dict[str, str]] = {"sub": {}, "ip": {}, "host": {}}

    def _label(self, kind: str, value: str, make) -> str:
        table = self.maps[kind]
        if value not in table:
            table[value] = make(len(table) + 1)
        return table[value]

    def _sub(self, match: re.Match[str]) -> str:
        value = match.group(0)
        if self.keep_plmn and len(value) >= 14:
            return self._label("sub", value, lambda n: f"{value[:5]}-sub{n}")
        return self._label("sub", value, lambda n: f"sub{n}")

    def _ip(self, match: re.Match[str]) -> str:
        value = match.group(0)
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return value
        return self._label("ip", value, lambda n: f"ip{n}")

    def _host(self, match: re.Match[str]) -> str:
        value = match.group(0)
        if value.lower().endswith(FILE_SUFFIXES) or value.lower().startswith(("e.g", "i.e")):
            return value
        return self._label("host", value.lower(), lambda n: f"host{n}.invalid")

    def text(self, value: str) -> str:
        value = IPV4.sub(self._ip, value)
        value = IPV6.sub(self._ip, value)
        value = HOST.sub(self._host, value)
        return DIGITS.sub(self._sub, value)

    def data(self, value: Any) -> Any:
        """Redact every string in a JSON-like structure (keys included)."""
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {self.data(k): self.data(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.data(v) for v in value]
        return value

    def counts(self) -> str:
        m = self.maps
        return (
            f"redacted  {len(m['sub'])} subscriber numbers, {len(m['ip'])} IP addresses, "
            f"{len(m['host'])} host/realm names"
        )
