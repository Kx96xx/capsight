"""MAP (2G/3G core signalling over SS7) and TCAP code tables.

Sources: 3GPP TS 29.002 (MAP operations 17.5, errors 17.6, parameters 17.7) and
ITU-T Q.773 (TCAP abort and reject causes).
"""

from __future__ import annotations

from capsight.codes import Code

# Operation code -> name and the node that answers it.
MAP_OPERATIONS: dict[int, tuple[str, str]] = {
    2: ("UpdateLocation", "HLR"),
    3: ("CancelLocation", "VLR"),
    4: ("ProvideRoamingNumber", "VLR"),
    5: ("NoteSubscriberDataModified", "gsmSCF"),
    7: ("InsertSubscriberData", "VLR/SGSN"),
    8: ("DeleteSubscriberData", "VLR/SGSN"),
    10: ("RegisterSS", "HLR"),
    11: ("EraseSS", "HLR"),
    12: ("ActivateSS", "HLR"),
    13: ("DeactivateSS", "HLR"),
    14: ("InterrogateSS", "HLR"),
    15: ("AuthenticationFailureReport", "HLR"),
    22: ("SendRoutingInfo", "HLR"),
    23: ("UpdateGprsLocation", "HLR"),
    24: ("SendRoutingInfoForGprs", "HLR"),
    33: ("ProcessAccessSignalling", "MSC"),
    37: ("Reset", "VLR/SGSN"),
    50: ("ActivateTraceMode", "VLR/SGSN"),
    51: ("DeactivateTraceMode", "VLR/SGSN"),
    55: ("SendIdentification", "previous VLR"),
    43: ("CheckIMEI", "EIR"),
    44: ("MT-ForwardSM", "MSC/SGSN"),
    45: ("SendRoutingInfoForSM", "HLR"),
    46: ("MO-ForwardSM", "SMSC (via IWMSC)"),
    47: ("ReportSM-DeliveryStatus", "HLR"),
    56: ("SendAuthenticationInfo", "HLR"),
    57: ("RestoreData", "HLR"),
    58: ("SendIMSI", "HLR"),
    59: ("ProcessUnstructuredSS-Request", "HLR"),
    60: ("UnstructuredSS-Request", "VLR"),
    63: ("InformServiceCentre", "SMSC (via GMSC)"),
    64: ("AlertServiceCentre", "SMSC (via IWMSC)"),
    65: ("AnyTimeModification", "HLR"),
    66: ("ReadyForSM", "HLR"),
    67: ("PurgeMS", "HLR"),
    70: ("ProvideSubscriberInfo", "VLR/SGSN"),
    68: ("PrepareHandover", "MSC"),
    69: ("PrepareSubsequentHandover", "MSC"),
    71: ("AnyTimeInterrogation", "HLR"),
    83: ("ProvideSubscriberLocation", "MSC/SGSN"),
    85: ("SendRoutingInfoForLCS", "HLR"),
    86: ("SubscriberLocationReport", "GMLC"),
    89: ("NoteMM-Event", "gsmSCF"),
}

# Errors that describe the subscriber's state rather than a network fault.
SUBSCRIBER_STATE_ERRORS = frozenset({6, 27, 31, 45, 46})

MAP_ERRORS: dict[int, Code] = {
    1: Code(
        "unknown subscriber",
        "The HLR has no subscription for this IMSI: not provisioned, deleted, or the IMSI's "
        "range is routed (SCCP global title) to the wrong HLR.",
    ),
    3: Code("unknown MSC", "The MSC address in the request is not known to the receiver."),
    5: Code(
        "unidentified subscriber",
        "The VLR/MSC does not know the subscriber: the HLR's location for it is out of date "
        "(the device moved, or the VLR lost its record).",
    ),
    6: Code(
        "subscriber absent for SMS",
        "The device could not be reached for SMS (switched off, detached, no paging "
        "response). Normal: the HLR keeps a message-waiting flag and alerts the SMSC when "
        "the device comes back.",
    ),
    8: Code(
        "roaming not allowed",
        "The HLR refused this subscriber in the visited network. Check the roaming agreement "
        "and the subscriber's roaming profile.",
    ),
    9: Code("illegal subscriber", "Authentication of the subscriber failed in the network."),
    10: Code("bearer service not provisioned", "The subscription does not include it."),
    11: Code(
        "teleservice not provisioned",
        "The subscription does not include this service (for SMS: no SMS in the profile).",
    ),
    12: Code("illegal equipment", "The device (IMEI) is blacklisted or not allowed."),
    13: Code(
        "call barred",
        "A barring is active for this subscriber (barring service or operator barring).",
    ),
    21: Code(
        "facility not supported",
        "The receiving node does not support this operation or feature (e.g. MAP version or "
        "an optional service). Check what it supports.",
    ),
    27: Code(
        "subscriber absent",
        "The device is not reachable (detached, no paging response, purged).",
    ),
    31: Code(
        "subscriber busy for MT SMS",
        "The device is busy with another SMS or procedure; usually transient, the SMSC retries.",
    ),
    32: Code(
        "SMS delivery failure",
        "The short message could not be delivered; the delivery failure cause says why.",
    ),
    33: Code("message waiting list full", "The HLR's message-waiting list is full."),
    34: Code(
        "system failure",
        "A node failed while handling the request. Check the logs of the node named in the "
        "error, or of the responder.",
    ),
    35: Code(
        "data missing",
        "A parameter the receiver needs was missing. Compare with a working request: "
        "usually a MAP version or vendor interworking difference.",
    ),
    36: Code(
        "unexpected data value",
        "The receiver rejected a parameter value. Compare with a working request: usually a "
        "MAP version or vendor interworking difference.",
    ),
    44: Code("number changed", "The called number has changed."),
    45: Code("busy subscriber", "The subscriber is busy."),
    46: Code("no subscriber reply", "The subscriber did not answer."),
    49: Code(
        "AnyTimeInterrogation not allowed",
        "The HLR does not allow this requester to interrogate it.",
    ),
    51: Code("resource limitation", "The receiving node is overloaded or out of resources."),
    52: Code("unauthorized requesting network", "The requester is not allowed to ask."),
    62: Code("information not available", "The requested information is not available."),
    71: Code("unknown alphabet", "The USSD string uses an alphabet the network cannot read."),
    72: Code("USSD busy", "Another USSD session is in progress for this subscriber."),
}

# Diagnostics carried inside error parameters, keyed by tshark field.
MAP_DIAGNOSTICS: dict[str, tuple[str, dict[int, str]]] = {
    "gsm_map.er.unknownSubscriberDiagnostic": (
        "diagnostic",
        {
            0: "IMSI unknown",
            1: "IMSI known, but no GPRS/EPS subscription",
            2: "number portability database mismatch",
        },
    ),
    "gsm_map.er.roamingNotAllowedCause": (
        "cause",
        {0: "PLMN roaming not allowed", 3: "operator determined barring"},
    ),
    "gsm_map.er.additionalRoamingNotAllowedCause": (
        "additional cause",
        {0: "supported RAT types not allowed"},
    ),
    "gsm_map.er.absentSubscriberDiagnosticSM": (
        "diagnostic",
        {
            0: "no paging response (MSC)",
            1: "IMSI detached",
            2: "roaming restriction",
            3: "deregistered in HLR (non-GPRS)",
            4: "MS purged (non-GPRS)",
            5: "no paging response (SGSN)",
            6: "GPRS detached",
            7: "deregistered in HLR (GPRS)",
            8: "MS purged (GPRS)",
            9: "unidentified subscriber (MSC)",
            10: "unidentified subscriber (SGSN)",
            11: "deregistered in HSS/HLR for IMS",
            12: "no response via the IP-SM-GW",
            13: "temporarily unavailable",
        },
    ),
    "gsm_map.er.absentSubscriberReason": (
        "reason",
        {
            0: "IMSI detached",
            1: "restricted area",
            2: "no page response",
            3: "purged MS",
            4: "MT roaming retry",
            5: "busy subscriber",
        },
    ),
    "gsm_map.er.sm_EnumeratedDeliveryFailureCause": (
        "cause",
        {
            0: "memory capacity exceeded (device storage full)",
            1: "equipment protocol error",
            2: "equipment not SM-equipped",
            3: "unknown service centre",
            4: "service centre congestion",
            5: "invalid SME address",
            6: "subscriber not an SC subscriber",
        },
    ),
    "gsm_map.er.callBarringCause": (
        "cause",
        {0: "barring service active", 1: "operator barring"},
    ),
    "gsm_map.er.networkResource": (
        "failed node",
        {
            0: "PLMN",
            1: "HLR",
            2: "VLR",
            3: "previous VLR",
            4: "controlling MSC",
            5: "VMSC",
            6: "EIR",
            7: "RSS",
        },
    ),
}

# Operation-specific readings of an error, where the generic hint is not enough.
MAP_ERROR_HINTS: dict[tuple[int, int], str] = {
    (56, 1): "The HLR does not know this IMSI, so no authentication vectors: the device "
    "cannot attach. Check the IMSI is provisioned in the HLR, and that its range is routed "
    "(SCCP global title) to the right HLR.",
    (2, 1): "The HLR does not know this IMSI, so location update fails and the device "
    "cannot register. Check provisioning and global title routing for the IMSI range.",
    (23, 1): "The HLR does not know this IMSI for packet data (GPRS) location update. If "
    "the diagnostic says no GPRS subscription, add data to the profile.",
    (2, 8): "The HLR refused registration in this visited network: check the roaming "
    "agreement with that network and the subscriber's roaming profile or barring.",
    (23, 8): "The HLR refused packet data (GPRS) registration in this visited network: check "
    "the roaming agreement for data and the subscriber's profile.",
    (45, 1): "SMS routing failed: the HLR does not know the destination number (MSISDN). "
    "The number is not provisioned, ported, or routed to the wrong HLR.",
    (45, 11): "The destination's subscription has no SMS service.",
    (45, 13): "SMS to this destination is barred in the HLR.",
    (44, 5): "The MSC/SGSN the HLR pointed to does not know the subscriber: stale "
    "location in the HLR. The device usually re-registers and the SMSC retries.",
    (46, 32): "The SMSC refused the mobile-originated SMS; the cause says why (e.g. unknown "
    "service centre = the SMSC address set on the device is wrong).",
    (46, 36): "The SMSC rejected a parameter of the mobile-originated SMS, often the "
    "destination address format.",
    (7, 36): "The VLR/SGSN rejected subscriber data the HLR sent (InsertSubscriberData). "
    "Check which service or parameter it does not support.",
    (7, 21): "The VLR/SGSN does not support a service in the subscriber data the HLR sent.",
}

TCAP_P_ABORT: dict[int, Code] = {
    0: Code("unrecognized message type", "The peer could not parse the TCAP message."),
    1: Code(
        "unrecognized transaction ID",
        "The peer no longer knows this dialogue: it timed out on the peer side, the peer "
        "restarted, or the answer was routed to a different node instance than the one "
        "that started the dialogue (load-shared global titles or point codes). Check that "
        "routing is symmetric for both directions.",
    ),
    2: Code("badly formatted transaction portion", "Encoding problem in the TCAP header."),
    3: Code("incorrect transaction portion", "Encoding problem in the TCAP header."),
    4: Code("resource limitation", "The peer's TCAP layer is overloaded."),
}

MAP_USER_ABORT: dict[str, Code] = {
    "gsm_map.dialogue.userSpecificReason_element": Code(
        "user specific reason",
        "The peer's MAP application aborted without a standard reason (vendor specific). "
        "Check the peer's logs for this subscriber and time; some HLRs abort instead of "
        "returning an error.",
    ),
    "gsm_map.dialogue.userResourceLimitation_element": Code(
        "user resource limitation", "The peer application is overloaded."
    ),
}

MAP_RESOURCE_UNAVAILABLE = {0: "short term", 1: "long term"}

MAP_PROCEDURE_CANCELLATION = {
    0: "handover cancellation",
    1: "radio channel release",
    2: "network path release",
    3: "call release",
    4: "associated procedure failure",
    5: "tandem dialogue release",
    6: "remote operations failure",
}

DIALOGUE_SERVICE_USER = {
    0: "null",
    1: "no reason given",
    2: "application context name not supported",
}

TCAP_REJECT_PROBLEMS: dict[str, dict[int, str]] = {
    "gsm_old.generalProblem": {
        0: "unrecognized component",
        1: "mistyped component",
        2: "badly structured component",
    },
    "gsm_old.invokeProblem": {
        0: "duplicate invoke ID",
        1: "unrecognized operation",
        2: "mistyped parameter",
        3: "resource limitation",
        4: "initiating release",
        5: "unrecognized linked ID",
        6: "linked response unexpected",
        7: "unexpected linked operation",
    },
    "gsm_old.returnResultProblem": {
        0: "unrecognized invoke ID",
        1: "return result unexpected",
        2: "mistyped parameter",
    },
    "gsm_old.returnErrorProblem": {
        0: "unrecognized invoke ID",
        1: "return error unexpected",
        2: "unrecognized error",
        3: "unexpected error",
        4: "mistyped parameter",
    },
}


def operation_name(opcode: int | None) -> str:
    if opcode is None:
        return "MAP operation"
    entry = MAP_OPERATIONS.get(opcode)
    return entry[0] if entry else f"MAP operation {opcode}"


def responder(opcode: int | None) -> str:
    entry = MAP_OPERATIONS.get(opcode) if opcode is not None else None
    return entry[1] if entry else "peer"
