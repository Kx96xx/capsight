"""tshark fields capsight requests. Field names verified against Wireshark 4.x."""

DIAMETER = (
    "diameter.flags.request",
    "diameter.cmd.code",
    "diameter.applicationId",
    "diameter.hopbyhopid",
    "diameter.endtoendid",
    "diameter.Session-Id",
    "diameter.User-Name",
    "diameter.Result-Code",
    "diameter.Experimental-Result-Code",
    # Gx / Gy (policy and charging)
    "diameter.Auth-Application-Id",
    "diameter.CC-Request-Type",
    "diameter.Subscription-Id-Type",
    "diameter.Subscription-Id-Data",
    "diameter.Called-Station-Id",
    "diameter.Rating-Group",
    "diameter.Final-Unit-Action",
    "diameter.Charging-Rule-Name",
    "diameter.PCC-Rule-Status",
    "diameter.Rule-Failure-Code",
    # roaming
    "diameter.Visited-PLMN-Id",
)

GTPV2 = (
    "gtpv2.message_type",
    "gtpv2.seq",
    "gtpv2.teid",
    "gtpv2.cause",
    "gtpv2.apn",
    "gtpv2.cs",
    "gtpv2.pdn_type",
    # roaming (S8): where the device is and which interface the request came in on
    "gtpv2.f_teid_interface_type",
    "gtpv2.rat_type",
    "e212.serv_net.mcc",
    "e212.serv_net.mnc",
)

RADIUS = ("radius.code", "radius.id")

NAS_EPS = (
    "nas-eps.nas_msg_emm_type",
    "nas-eps.nas_msg_esm_type",
    "nas-eps.emm.cause",
    "nas-eps.esm.cause",
)

IDENTITY = ("e212.imsi", "s1ap.ENB_UE_S1AP_ID", "s1ap.MME_UE_S1AP_ID")

NGAP = (
    "ngap.procedureCode",
    "ngap.NGAP_PDU",
    "ngap.Cause",
    "ngap.radioNetwork",
    "ngap.transport",
    "ngap.nas",
    "ngap.protocol",
    "ngap.misc",
    "ngap.RAN_UE_NGAP_ID",
)

NAS_5GS = (
    "nas-5gs.mm.message_type",
    "nas-5gs.sm.message_type",
    "nas-5gs.mm.5gmm_cause",
    "nas-5gs.sm.5gsm_cause",
    "nas-5gs.cmn.dnn",
    # ciphering: header type 2/4 = ciphered; the selected algorithm is in Security Mode Command
    "nas-5gs.security_header_type",
    "nas-5gs.mm.nas_sec_algo_enc",
    "nas-5gs.mm.suci.scheme_id",
    "nas-5gs.mm.suci.msin",
    "e212.mcc",
    "e212.mnc",
)

PFCP = (
    "pfcp.msg_type",
    "pfcp.seqno",
    "pfcp.cause",
    "pfcp.seid",
    "pfcp.ue_ip_addr_ipv4",
    "pfcp.ue_ip_addr_ipv6",
    "pfcp.network_instance",
    "pfcp.srreq_flags.psdbu",
)

# MAP over TCAP (2G/3G core over SS7/SIGTRAN). Element fields mark which TCAP message and
# which component a value belongs to; see correlate_map.py.
MAP = (
    "tcap.begin_element",
    "tcap.continue_element",
    "tcap.end_element",
    "tcap.abort_element",
    "tcap.tid",
    "tcap.otid",
    "tcap.dtid",
    "tcap.components",
    "tcap.p_abortCause",
    "tcap.result",
    "tcap.dialogue_service_user",
    "gsm_map.old.Component",
    "gsm_old.invokeID",
    "gsm_old.derivable",
    "gsm_old.localValue",
    "gsm_old.generalProblem",
    "gsm_old.invokeProblem",
    "gsm_old.returnResultProblem",
    "gsm_old.returnErrorProblem",
    "gsm_map.er.unknownSubscriberDiagnostic",
    "gsm_map.er.roamingNotAllowedCause",
    "gsm_map.er.additionalRoamingNotAllowedCause",
    "gsm_map.er.absentSubscriberDiagnosticSM",
    "gsm_map.er.absentSubscriberReason",
    "gsm_map.er.sm_EnumeratedDeliveryFailureCause",
    "gsm_map.er.callBarringCause",
    "gsm_map.er.networkResource",
    "gsm_map.dialogue.userSpecificReason_element",
    "gsm_map.dialogue.userResourceLimitation_element",
    "gsm_map.dialogue.resourceUnavailable",
    "gsm_map.dialogue.applicationProcedureCancellation",
    "gsm_map.dialogue.map_ProviderAbortReason",
)

USER_PLANE = ("ip.src", "ip.dst", "gtp.teid")

ALL = (
    *DIAMETER,
    *GTPV2,
    *RADIUS,
    *NAS_EPS,
    *IDENTITY,
    *NGAP,
    *NAS_5GS,
    *PFCP,
    *MAP,
    *USER_PLANE,
)

# tshark preferences applied when available. Lab cores often run NAS with the null cipher
# (NEA0); this lets tshark decode the 5GSM payload in those captures.
PREFERENCES = {"nas-5gs.null_decipher": "TRUE"}

DISPLAY_FILTER = "diameter or gtpv2 or nas-eps or s1ap or radius"
