"""Attach a subscriber identity to NAS messages that do not carry one.

After the first message of an attach, NAS stops carrying the IMSI. S1AP keeps one
eNB-UE-S1AP-ID per UE connection, so the IMSI seen at the start of a connection is
carried forward to later messages with the same ID. IDs are reused over time, so a new
IMSI on the same ID replaces the old one.
"""

from __future__ import annotations

from collections.abc import Iterable

from capsight.model import Packet


def s1ap_imsi_map(packets: Iterable[Packet]) -> dict[int, str]:
    """Return {packet number: IMSI} for S1AP/NAS packets, inferred by eNB-UE-S1AP-ID."""
    current: dict[str, str] = {}
    result: dict[int, str] = {}
    for packet in packets:
        if not packet.has("s1ap"):
            continue
        enb_ids = packet.fields.get("s1ap.ENB_UE_S1AP_ID", [])
        if not enb_ids:
            continue
        imsi = packet.first("e212.imsi")
        if imsi and len(enb_ids) == 1:
            current[enb_ids[0]] = imsi
        known = imsi or (current.get(enb_ids[0]) if len(enb_ids) == 1 else None)
        if known:
            result[packet.number] = known
    return result


def _supi_from_suci(packet: Packet) -> str | None:
    """SUPI (IMSI) from a SUCI that uses the null protection scheme; None if concealed."""
    msin = packet.first("nas-5gs.mm.suci.msin")
    if not msin:
        return None
    scheme = packet.first("nas-5gs.mm.suci.scheme_id")
    mcc, mnc = packet.first("e212.mcc"), packet.first("e212.mnc")
    if scheme not in (None, "0") or not mcc or not mnc:
        return None
    return f"{mcc}{mnc}{msin}"


def ngap_imsi_map(packets: Iterable[Packet]) -> dict[int, str]:
    """Return {packet number: IMSI} for NGAP/NAS-5GS packets, inferred by RAN-UE-NGAP-ID.

    Only a SUCI with the null scheme reveals the IMSI. A concealed SUCI stays unknown.
    """
    current: dict[str, str] = {}
    result: dict[int, str] = {}
    for packet in packets:
        if not packet.has("ngap"):
            continue
        ids = set(packet.fields.get("ngap.RAN_UE_NGAP_ID", []))
        if len(ids) != 1:
            continue
        ue = ids.pop()
        supi = _supi_from_suci(packet)
        if supi:
            current[ue] = supi
        if ue in current:
            result[packet.number] = current[ue]
    return result
