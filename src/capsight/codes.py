"""Protocol code tables: names plus a short, actionable hint.

Sources: RFC 6733 (Diameter base), 3GPP TS 29.272 (S6a/S6d), TS 29.274 (GTPv2-C),
TS 24.301 (EPS NAS).
"""

from __future__ import annotations

from typing import NamedTuple


class Code(NamedTuple):
    name: str
    hint: str = ""


DIAMETER_COMMANDS: dict[int, tuple[str, str]] = {
    # code: (request abbreviation, answer abbreviation)
    257: ("CER", "CEA"),
    280: ("DWR", "DWA"),
    282: ("DPR", "DPA"),
    316: ("ULR", "ULA"),
    317: ("CLR", "CLA"),
    318: ("AIR", "AIA"),
    319: ("IDR", "IDA"),
    320: ("DSR", "DSA"),
    321: ("PUR", "PUA"),
    322: ("RSR", "RSA"),
    323: ("NOR", "NOA"),
    272: ("CCR", "CCA"),
    265: ("AAR", "AAA"),
    258: ("RAR", "RAA"),
    275: ("STR", "STA"),
    300: ("UAR", "UAA"),
    301: ("SAR", "SAA"),
    302: ("LIR", "LIA"),
    303: ("MAR", "MAA"),
    304: ("RTR", "RTA"),
    305: ("PPR", "PPA"),
    306: ("UDR", "UDA"),
    307: ("PUR", "PUA"),
    308: ("SNR", "SNA"),
    309: ("PNR", "PNA"),
    8388620: ("PLR", "PLA"),
    8388622: ("LRR", "LRA"),
}

# Base protocol Result-Code values (RFC 6733, RFC 4006).
DIAMETER_RESULT: dict[int, Code] = {
    2001: Code("DIAMETER_SUCCESS"),
    3001: Code("DIAMETER_COMMAND_UNSUPPORTED", "The peer does not support this command."),
    3002: Code(
        "DIAMETER_UNABLE_TO_DELIVER",
        "No route to the destination. Check Destination-Realm/Host and the routing agent's "
        "peer and realm table.",
    ),
    3003: Code("DIAMETER_REALM_NOT_SERVED", "The destination realm is not configured on the peer."),
    3004: Code("DIAMETER_TOO_BUSY", "The peer is overloaded. Check its load and retry policy."),
    3005: Code("DIAMETER_LOOP_DETECTED", "Routing loop between agents. Check Route-Record AVPs."),
    3006: Code(
        "DIAMETER_REDIRECT_INDICATION", "A redirect agent answered; the sender must re-route."
    ),
    3007: Code("DIAMETER_APPLICATION_UNSUPPORTED", "The peer does not support this application."),
    3008: Code("DIAMETER_INVALID_HDR_BITS", "Invalid bits in the Diameter header."),
    3009: Code("DIAMETER_INVALID_AVP_BITS", "An AVP has invalid flag bits."),
    3010: Code("DIAMETER_UNKNOWN_PEER", "The peer has no connection configured for the sender."),
    4001: Code("DIAMETER_AUTHENTICATION_REJECTED", "Authentication of the user failed."),
    4002: Code("DIAMETER_OUT_OF_SPACE", "The peer could not store the request (accounting)."),
    4003: Code("ELECTION_LOST", "Connection election lost; the other peer's connection is kept."),
    4010: Code("DIAMETER_END_USER_SERVICE_DENIED", "Charging/policy denied service to the user."),
    4012: Code("DIAMETER_CREDIT_LIMIT_REACHED", "The user has no credit left."),
    5001: Code("DIAMETER_AVP_UNSUPPORTED", "A mandatory AVP is not understood by the peer."),
    5002: Code("DIAMETER_UNKNOWN_SESSION_ID", "The peer has no session with this Session-Id."),
    5003: Code("DIAMETER_AUTHORIZATION_REJECTED", "The user is not authorized for this request."),
    5004: Code("DIAMETER_INVALID_AVP_VALUE", "An AVP value was rejected. See the Failed-AVP."),
    5005: Code("DIAMETER_MISSING_AVP", "A required AVP is missing. See the Failed-AVP."),
    5006: Code("DIAMETER_RESOURCES_EXCEEDED", "The peer refused: resource limits exceeded."),
    5007: Code(
        "DIAMETER_CONTRADICTING_AVPS", "Two AVPs contradict each other. See the Failed-AVP."
    ),
    5008: Code(
        "DIAMETER_AVP_NOT_ALLOWED",
        "The request carries an AVP the peer does not allow in this message. See the "
        "Failed-AVP, and compare the sender's AVP set with what the peer's dictionary expects.",
    ),
    5009: Code("DIAMETER_AVP_OCCURS_TOO_MANY_TIMES", "An AVP is repeated too often."),
    5010: Code("DIAMETER_NO_COMMON_APPLICATION", "The peers share no application (CER/CEA)."),
    5011: Code("DIAMETER_UNSUPPORTED_VERSION", "Unsupported Diameter version."),
    5012: Code("DIAMETER_UNABLE_TO_COMPLY", "Generic failure on the peer. Check its logs."),
    5013: Code("DIAMETER_INVALID_BIT_IN_HEADER", "Invalid bit in the Diameter header."),
    5014: Code("DIAMETER_INVALID_AVP_LENGTH", "An AVP has an invalid length (encoding)."),
    5015: Code("DIAMETER_INVALID_MESSAGE_LENGTH", "The message length is invalid (encoding)."),
    5016: Code("DIAMETER_INVALID_AVP_BIT_COMBO", "An AVP has an invalid flag combination."),
    5017: Code("DIAMETER_NO_COMMON_SECURITY", "The peers share no security mechanism."),
    5030: Code("DIAMETER_USER_UNKNOWN", "The charging/policy server does not know this user."),
}

# 3GPP Experimental-Result-Code values (TS 29.272, TS 29.229).
DIAMETER_EXPERIMENTAL: dict[int, Code] = {
    2001: Code("DIAMETER_FIRST_REGISTRATION"),
    2002: Code("DIAMETER_SUBSEQUENT_REGISTRATION"),
    4181: Code(
        "DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE",
        "The HSS could not produce authentication vectors. Check the subscriber's keys.",
    ),
    5001: Code(
        "DIAMETER_ERROR_USER_UNKNOWN",
        "The subscriber is not provisioned in the HSS/UDM, or the IMSI on the SIM does not "
        "match the provisioned one.",
    ),
    5002: Code("DIAMETER_ERROR_IDENTITIES_DONT_MATCH", "IMPI and IMPU are not associated."),
    5003: Code("DIAMETER_ERROR_IDENTITY_NOT_REGISTERED", "The IMS identity is not registered."),
    5004: Code(
        "DIAMETER_ERROR_ROAMING_NOT_ALLOWED",
        "The subscription does not allow roaming in the visited network.",
    ),
    5420: Code(
        "DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION",
        "The subscriber exists but has no EPS (4G) subscription data.",
    ),
    5421: Code(
        "DIAMETER_ERROR_RAT_NOT_ALLOWED",
        "The subscription does not allow the radio access type in use.",
    ),
    5422: Code("DIAMETER_ERROR_EQUIPMENT_UNKNOWN", "The device IMEI is unknown or blocked."),
    5423: Code("DIAMETER_ERROR_UNKOWN_SERVING_NODE", "The serving node is not known to the HSS."),
}

# GTPv2-C Cause values (TS 29.274 section 8.4). 16-63 are acceptance causes.
GTPV2_CAUSE: dict[int, Code] = {
    16: Code("Request accepted"),
    17: Code("Request accepted partially"),
    64: Code("Context Not Found", "The receiver has no session for this TEID."),
    65: Code("Invalid Message Format"),
    66: Code("Version not supported by next peer"),
    67: Code("Invalid length"),
    68: Code("Service not supported"),
    69: Code("Mandatory IE incorrect", "An IE was present but its value was rejected."),
    70: Code("Mandatory IE missing", "The sender omitted a required IE."),
    72: Code("System failure", "Internal failure on the responding node. Check its logs."),
    73: Code("No resources available", "The gateway is out of capacity."),
    78: Code(
        "Missing or unknown APN",
        "The APN requested by the device is not configured on the gateway or not resolvable.",
    ),
    83: Code("Preferred PDN Type not supported", "Check the device's IPv4/IPv6 setting."),
    84: Code("All dynamic addresses are occupied", "The IP pool for this APN is exhausted."),
    89: Code("Service denied"),
    92: Code("User authentication failed", "The PGW (or its AAA) rejected the user."),
    93: Code(
        "APN access denied - no subscription",
        "The subscriber is not subscribed to this APN.",
    ),
    94: Code("Request rejected (reason not specified)"),
    96: Code("IMSI/IMEI not known"),
    100: Code("Remote peer not responding", "A downstream node (often the PGW) did not answer."),
    110: Code("Temporarily rejected due to handover/TAU/RAU procedure in progress"),
    113: Code("APN Congestion"),
}

GTPV2_MESSAGES: dict[int, str] = {
    1: "Echo Request",
    2: "Echo Response",
    32: "Create Session Request",
    33: "Create Session Response",
    34: "Modify Bearer Request",
    35: "Modify Bearer Response",
    36: "Delete Session Request",
    37: "Delete Session Response",
    95: "Create Bearer Request",
    96: "Create Bearer Response",
    97: "Update Bearer Request",
    98: "Update Bearer Response",
    99: "Delete Bearer Request",
    100: "Delete Bearer Response",
    170: "Release Access Bearers Request",
    171: "Release Access Bearers Response",
    176: "Downlink Data Notification",
    177: "Downlink Data Notification Acknowledge",
}

# request type -> response type
GTPV2_PAIRS: dict[int, int] = {
    1: 2,
    32: 33,
    34: 35,
    36: 37,
    95: 96,
    97: 98,
    99: 100,
    170: 171,
    176: 177,
}

# EPS Mobility Management message types (TS 24.301 table 9.8.1).
EMM_MESSAGES: dict[int, str] = {
    0x41: "Attach Request",
    0x42: "Attach Accept",
    0x43: "Attach Complete",
    0x44: "Attach Reject",
    0x45: "Detach Request",
    0x46: "Detach Accept",
    0x48: "Tracking Area Update Request",
    0x49: "Tracking Area Update Accept",
    0x4A: "Tracking Area Update Complete",
    0x4B: "Tracking Area Update Reject",
    0x4C: "Extended Service Request",
    0x4E: "Service Reject",
    0x50: "GUTI Reallocation Command",
    0x51: "GUTI Reallocation Complete",
    0x52: "Authentication Request",
    0x53: "Authentication Response",
    0x54: "Authentication Reject",
    0x55: "Identity Request",
    0x56: "Identity Response",
    0x5C: "Authentication Failure",
    0x5D: "Security Mode Command",
    0x5E: "Security Mode Complete",
    0x5F: "Security Mode Reject",
    0x60: "EMM Status",
    0x61: "EMM Information",
    0x62: "Downlink NAS Transport",
    0x63: "Uplink NAS Transport",
}

EMM_REJECTS = {0x44, 0x4B, 0x4E}

# EMM cause values (TS 24.301 section 9.9.3.9).
EMM_CAUSE: dict[int, Code] = {
    3: Code("Illegal UE", "The network failed to authenticate the SIM. Check its keys."),
    6: Code("Illegal ME", "The device (IMEI) is blocked."),
    7: Code("EPS services not allowed", "The subscription has no 4G service."),
    8: Code(
        "EPS services and non-EPS services not allowed",
        "The subscriber is unknown or barred in the home network.",
    ),
    9: Code(
        "UE identity cannot be derived by the network",
        "The GUTI is stale; the device should re-attach with its IMSI.",
    ),
    10: Code("Implicitly detached"),
    11: Code("PLMN not allowed", "The subscription does not allow this network."),
    12: Code("Tracking area not allowed"),
    13: Code("Roaming not allowed in this tracking area"),
    14: Code("EPS services not allowed in this PLMN"),
    15: Code("No suitable cells in tracking area"),
    17: Code("Network failure", "A core node failed during the procedure. Check the HSS/MME."),
    19: Code("ESM failure", "The default bearer could not be created. See the ESM cause."),
    22: Code("Congestion"),
    111: Code("Protocol error, unspecified"),
}

# Authentication Failure causes sent by the UE.
AUTH_FAILURE_CAUSE: dict[int, Code] = {
    20: Code(
        "MAC failure",
        "The SIM could not verify the network: the keys (Ki/OPc) in the HSS do not match the SIM.",
    ),
    21: Code(
        "Synch failure",
        "Sequence numbers are out of sync. Normally self-healing via re-synchronisation; "
        "repeated failures point at the HSS SQN handling.",
    ),
    26: Code("Non-EPS authentication unacceptable"),
}

# ESM cause values (TS 24.301 section 9.9.4.4).
ESM_CAUSE: dict[int, Code] = {
    26: Code("Insufficient resources"),
    27: Code("Missing or unknown APN", "The APN set on the device is not valid on this network."),
    28: Code("Unknown PDN type"),
    29: Code("User authentication failed"),
    30: Code("Request rejected by Serving GW or PDN GW"),
    31: Code("Request rejected, unspecified"),
    32: Code("Service option not supported"),
    33: Code("Requested service option not subscribed", "The APN is not in the subscription."),
    38: Code("Network failure"),
    50: Code("PDN type IPv4 only allowed"),
    51: Code("PDN type IPv6 only allowed"),
    55: Code("Multiple PDN connections for a given APN not allowed"),
}


def lookup(table: dict[int, Code], value: int) -> Code:
    return table.get(value, Code(f"code {value}"))
