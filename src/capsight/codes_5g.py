"""5G SA code tables: NGAP, 5GMM/5GSM (TS 24.501), PFCP (TS 29.244)."""

from __future__ import annotations

from capsight.codes import Code

# ---- 5GMM ------------------------------------------------------------------------------

MM_MESSAGES: dict[int, str] = {
    0x41: "Registration Request",
    0x42: "Registration Accept",
    0x43: "Registration Complete",
    0x44: "Registration Reject",
    0x45: "Deregistration Request",
    0x47: "Deregistration Request (network)",
    0x4C: "Service Request",
    0x4D: "Service Reject",
    0x4E: "Service Accept",
    0x54: "Configuration Update Command",
    0x56: "Authentication Request",
    0x57: "Authentication Response",
    0x58: "Authentication Reject",
    0x59: "Authentication Failure",
    0x5D: "Security Mode Command",
    0x5E: "Security Mode Complete",
    0x5F: "Security Mode Reject",
    0x64: "5GMM Status",
    0x67: "UL NAS Transport",
    0x68: "DL NAS Transport",
}

MM_REGISTRATION_REQUEST = 0x41
MM_REGISTRATION_ACCEPT = 0x42
MM_REJECTS = {0x44, 0x4D, 0x5F}
MM_AUTH_RESPONSE = 0x57
MM_AUTH_REJECT = 0x58
MM_AUTH_FAILURE = 0x59
MM_STATUS = 0x64
MM_DL_NAS_TRANSPORT = 0x68

# 5GMM cause (TS 24.501 section 9.11.3.2).
MM_CAUSE: dict[int, Code] = {
    3: Code("Illegal UE", "The network could not authenticate the SIM. Check its keys."),
    5: Code("PEI not accepted", "The device identity (IMEI) was rejected."),
    6: Code("Illegal ME", "The device (IMEI) is blocked."),
    7: Code("5GS services not allowed", "The subscription has no 5G service."),
    9: Code(
        "UE identity cannot be derived by the network",
        "The 5G-GUTI is stale; the device should register again with its SUCI.",
    ),
    10: Code("Implicitly de-registered"),
    11: Code("PLMN not allowed", "The subscription does not allow this network."),
    12: Code("Tracking area not allowed"),
    13: Code("Roaming not allowed in this tracking area"),
    15: Code("No suitable cells in tracking area"),
    20: Code(
        "MAC failure",
        "The SIM could not verify the network: the keys (K/OPc) in the UDM do not match the SIM.",
    ),
    21: Code("Synch failure", "Sequence numbers are out of sync between SIM and UDM."),
    22: Code("Congestion"),
    23: Code("UE security capabilities mismatch"),
    24: Code("Security mode rejected, unspecified"),
    26: Code("Non-5G authentication unacceptable"),
    27: Code("N1 mode not allowed"),
    28: Code("Restricted service area"),
    31: Code("Redirection to EPC required"),
    62: Code(
        "No network slices available",
        "None of the requested slices (S-NSSAI) are allowed. Check the subscription's "
        "slices and the AMF's supported slice list.",
    ),
    65: Code("Maximum number of PDU sessions reached"),
    67: Code("Insufficient resources for specific slice and DNN"),
    69: Code("Insufficient resources for specific slice"),
    71: Code("ngKSI already in use"),
    73: Code(
        "Serving network not authorized",
        "The home network refused authentication for this serving network name.",
    ),
    90: Code(
        "Payload was not forwarded",
        "The AMF could not forward the session request to an SMF. Check SMF selection "
        "(NRF, slice and DNN configuration).",
    ),
    91: Code(
        "DNN not supported or not subscribed in the slice",
        "The DNN (APN) the device asked for is not subscribed for this subscriber in this "
        "slice, or not configured on the core. Fix the device's DNN or add it to the "
        "subscription.",
    ),
    92: Code("Insufficient user-plane resources for the PDU session"),
    95: Code("Semantically incorrect message"),
    96: Code("Invalid mandatory information"),
    97: Code("Message type non-existent or not implemented"),
    111: Code("Protocol error, unspecified"),
}

# ---- 5GSM ------------------------------------------------------------------------------

SM_ESTABLISHMENT_REQUEST = 0xC1
SM_ESTABLISHMENT_ACCEPT = 0xC2
SM_REJECTS: dict[int, str] = {
    0xC3: "PDU Session Establishment Reject",
    0xCB: "PDU Session Modification Reject",
    0xD2: "PDU Session Release Reject",
}

# 5GSM cause (TS 24.501 section 9.11.4.2).
SM_CAUSE: dict[int, Code] = {
    8: Code("Operator determined barring"),
    26: Code("Insufficient resources"),
    27: Code("Missing or unknown DNN", "The DNN set on the device is not valid on this network."),
    28: Code("Unknown PDU session type"),
    29: Code(
        "User authentication or authorization failed",
        "The SMF or its AAA/DN-AAA refused the session.",
    ),
    31: Code("Request rejected, unspecified"),
    32: Code("Service option not supported"),
    33: Code("Requested service option not subscribed", "The DNN is not in the subscription."),
    38: Code("Network failure"),
    43: Code("Invalid PDU session identity"),
    46: Code("Out of LADN service area"),
    50: Code("PDU session type IPv4 only allowed"),
    51: Code("PDU session type IPv6 only allowed"),
    54: Code("PDU session does not exist"),
    57: Code("PDU session type IPv4v6 only allowed"),
    59: Code("Unsupported 5QI value"),
    67: Code("Insufficient resources for specific slice and DNN"),
    68: Code("Not supported SSC mode"),
    69: Code("Insufficient resources for specific slice"),
    70: Code(
        "Missing or unknown DNN in a slice",
        "The DNN is not configured for the requested slice (S-NSSAI).",
    ),
    111: Code("Protocol error, unspecified"),
}

# ---- NGAP ------------------------------------------------------------------------------

NGAP_PROCEDURES: dict[int, str] = {
    0: "AMF Configuration Update",
    4: "Downlink NAS Transport",
    12: "Handover Preparation",
    13: "Handover Resource Allocation",
    14: "Initial Context Setup",
    15: "Initial UE Message",
    20: "NG Reset",
    21: "NG Setup",
    25: "Path Switch Request",
    26: "PDU Session Resource Modify",
    28: "PDU Session Resource Release",
    29: "PDU Session Resource Setup",
    35: "RAN Configuration Update",
    40: "UE Context Modification",
    41: "UE Context Release",
    42: "UE Context Release Request",
    46: "Uplink NAS Transport",
}

NGAP_UNSUCCESSFUL_OUTCOME = 2
NGAP_CAUSE_GROUPS = ("radioNetwork", "transport", "nas", "protocol", "misc")

NGAP_CAUSE: dict[str, dict[int, Code]] = {
    "misc": {
        0: Code("control-processing-overload", "The AMF is overloaded."),
        1: Code("not-enough-user-plane-processing-resources"),
        2: Code("hardware-failure"),
        3: Code("om-intervention"),
        4: Code(
            "unknown-PLMN-or-SNPN",
            "The AMF does not serve what the gNB announced: check that the gNB's PLMN "
            "(MCC/MNC) and its tracking area codes (TAC) are in the AMF's served PLMN and "
            "TAI lists, and that the slice list matches.",
        ),
        5: Code("unspecified"),
    },
    "nas": {
        0: Code("normal-release"),
        1: Code("authentication-failure"),
        2: Code("deregister"),
        3: Code("unspecified"),
    },
    "transport": {
        0: Code("transport-resource-unavailable"),
        1: Code("unspecified"),
    },
    "protocol": {
        0: Code("transfer-syntax-error"),
        1: Code("abstract-syntax-error-reject"),
        2: Code("abstract-syntax-error-ignore-and-notify"),
        3: Code("message-not-compatible-with-receiver-state"),
        4: Code("semantic-error"),
        5: Code("abstract-syntax-error-falsely-constructed-message"),
        6: Code("unspecified"),
    },
    "radioNetwork": {
        0: Code("unspecified"),
        21: Code("radio-connection-with-ue-lost"),
        26: Code("unknown-PDU-session-ID"),
        27: Code("unknown-qos-flow-ID"),
        30: Code("multiple-PDU-session-ID-instances"),
        41: Code("slice-not-supported", "The gNB or AMF does not support the requested slice."),
    },
}

# ---- PFCP ------------------------------------------------------------------------------

PFCP_MESSAGES: dict[int, str] = {
    1: "Heartbeat Request",
    2: "Heartbeat Response",
    5: "Association Setup Request",
    6: "Association Setup Response",
    7: "Association Update Request",
    8: "Association Update Response",
    9: "Association Release Request",
    10: "Association Release Response",
    12: "Node Report Request",
    13: "Node Report Response",
    50: "Session Establishment Request",
    51: "Session Establishment Response",
    52: "Session Modification Request",
    53: "Session Modification Response",
    54: "Session Deletion Request",
    55: "Session Deletion Response",
    56: "Session Report Request",
    57: "Session Report Response",
}

PFCP_PAIRS: dict[int, int] = {1: 2, 5: 6, 7: 8, 9: 10, 12: 13, 50: 51, 52: 53, 54: 55, 56: 57}

# PFCP Cause (TS 29.244 section 8.2.1). 1 = Request accepted.
PFCP_CAUSE: dict[int, Code] = {
    1: Code("Request accepted"),
    64: Code("Request rejected (reason not specified)"),
    65: Code("Session context not found", "The UPF has no session for this SEID."),
    66: Code("Mandatory IE missing"),
    67: Code("Conditional IE missing"),
    68: Code("Invalid length"),
    69: Code("Mandatory IE incorrect"),
    70: Code("Invalid Forwarding Policy"),
    71: Code("Invalid F-TEID allocation option"),
    72: Code(
        "No established PFCP Association",
        "The SMF and UPF have no PFCP association. Check that the association setup "
        "succeeded and heartbeats are answered.",
    ),
    73: Code(
        "Rule creation/modification Failure",
        "The UPF could not install a PDR/FAR/QER. Check the rule contents and the UPF logs.",
    ),
    74: Code("PFCP entity in congestion"),
    75: Code("No resources available", "The UPF is out of capacity (e.g. TEIDs or UE IPs)."),
    76: Code("Service not supported"),
    77: Code("System failure", "Internal failure on the UPF. Check its logs."),
    78: Code("Redirection Requested"),
}
