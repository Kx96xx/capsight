"""Roaming helpers: which network the device is visiting, read only from the capture.

The visited network is taken from fields that carry it explicitly: the Serving Network IE
in GTPv2-C and the Visited-PLMN-Id AVP in S6a. It is never guessed from host names, realms
or IP addresses, and it is shown as MCC/MNC, not as an operator name.
"""

from __future__ import annotations

from capsight.model import Packet

# GTPv2 F-TEID interface type 6 = S5/S8 SGW GTP-C (TS 29.274 8.22). A Create Session
# Request from an SGW on S5 or S8 carries it; S8 vs S5 is told apart by the serving network.
S5_S8_SGW_GTPC = "6"


def decode_plmn(raw: str | None) -> tuple[str, str] | None:
    """3-octet PLMN identity in hex (e.g. "00f120") -> ("001", "02")."""
    if not raw:
        return None
    try:
        b = bytes.fromhex(raw.replace(":", ""))
    except ValueError:
        return None
    if len(b) != 3:
        return None
    digits = [b[0] & 0xF, b[0] >> 4, b[1] & 0xF, b[1] >> 4, b[2] & 0xF, b[2] >> 4]
    mcc = "".join(str(d) for d in digits[:3])
    mnc = f"{digits[4]}{digits[5]}" + ("" if digits[3] == 0xF else str(digits[3]))
    if not (mcc + mnc).isdigit():
        return None
    return mcc, mnc


def serving_plmn(packet: Packet | None) -> tuple[str, str] | None:
    if packet is None:
        return None
    mcc, mnc = packet.first("e212.serv_net.mcc"), packet.first("e212.serv_net.mnc")
    return (mcc, mnc) if mcc and mnc else None


def is_visiting(imsi: str | None, visited: tuple[str, str] | None) -> bool:
    """True when the IMSI does not belong to the visited PLMN (roaming).

    Unknown either way means False: never claim roaming without both values.
    """
    if not imsi or visited is None:
        return False
    return not imsi.startswith(visited[0] + visited[1])


def came_from_sgw(packet: Packet | None) -> bool:
    return packet is not None and S5_S8_SGW_GTPC in packet.fields.get(
        "gtpv2.f_teid_interface_type", []
    )


def plmn_text(plmn: tuple[str, str]) -> str:
    return f"MCC {plmn[0]} MNC {plmn[1]}"
