# Changelog

## Unreleased

- A Create Session refused because the PCRF (Gx) or the online charging system (Gy) refused
  the gateway's CCR-I is one finding that names the refusing server and its result, instead
  of a "system failure" plus a separate Gx/Gy reject. The CCR-I is linked only when it is the
  only failed one inside that Create Session's request-to-answer window (same IMSI when both
  carry one) and no other rejected Create Session overlaps it.
- The report opens with the most likely cause when there is more than one problem: chains
  that join messages rank above a single refusal code, which ranks above timeouts and aborts,
  then the more frequent wins. In text, `--summary`, JSON (`most_likely_cause`) and the web
  demo, whose header now lists MAP and Gx/Gy too.
- Session refusals are explained across GTP-C and PFCP instead of as two vague codes. A
  Create Session is linked to the PFCP Session Establishment its gateway sent the UPF (by
  time, in arrival order, only when unambiguous). When the UPF refused it, one finding says
  the gateway's cause (often 72 System failure) only passes on the UPF's refusal. When the
  UPF also deleted another session on the same UE address (Session Report with "deleted by
  the UP function"), the finding names the address and the APNs: two APNs sharing one static
  address knock each other's sessions out, which looks like an intermittent failure.

## 0.3.0

Operator network coverage: roaming, policy and charging, 2G/3G MAP, ciphered 5G NAS.

- Ciphered 5G NAS: an INFO finding says how many NAS messages were encrypted and with
  which algorithm; registration that never completed and registrations with no PDU session
  are inferred from NGAP (Initial Context Setup, PDU Session Resource Setup, UE Context
  Release) and labelled as inferences.
- MAP (2G/3G over SS7/SIGTRAN): operation errors with their diagnostics (authentication,
  location update, SMS routing and delivery), TCAP aborts with the reason, TCAP rejects,
  unanswered operations (30 s MAP timer floor), and a warning when the capture holds answers
  without their requests. SCTP-bundled TCAP messages are split exactly or left alone.
- All RFC 6733 base Diameter Result-Codes are named (5008 DIAMETER_AVP_NOT_ALLOWED was shown
  as "code 5008").
- Fix: a capture record without a timestamp (tshark opens some non-capture files, e.g. MP4,
  that way) no longer crashes the analysis.
- Roaming: S8 Create Session rejects and timeouts from a visited SGW, with the visited
  network (MCC/MNC from the Serving Network IE) and roaming-specific hints; S6a rejects
  show the Visited-PLMN-Id.
- Gx/Gy policy and charging: PCRF/OCS rejects by interface and request type, per-service
  (rating group) credit failures with Final-Unit-Action, policy rules the gateway could not
  install, and a failed CCR-I linked to the Create Session reject it caused.

## 0.2.0

First release on PyPI. Usable on real captures.

- `--imsi X`: one subscriber's attach, authentication, session and data steps in order, and
  where it stopped.
- Large captures: streaming analysis, so memory grows with open procedures, not packets.
  Same findings as 0.1 on every capture in the local regression corpus.
- `--summary`: top problems with counts, first/last time and subscribers affected, the most
  affected subscribers, and problems over time.
- `--redact` / `--redact-all`: mask IMSI, MSISDN, IP addresses, hosts/realms and the capture
  file name in text and JSON output.
- Hosted demo redesigned (finding cards, demo captures, redact switch, report downloads).

## 0.1.0

First release.

- 4G: Diameter S6a/base result codes, GTPv2-C rejects (cause source, RADIUS Access-Accept
  before cause 92, PDN-type split, retransmission folding), EPS NAS EMM/ESM rejects,
  authentication MAC vs sync failure.
- 5G SA: NGAP unsuccessful outcomes, 5GMM/5GSM rejects, PDU session refused by the AMF with
  the DNN, PFCP rejects and timeouts, one-way GTP-U user plane with N6 NAT hint.
- Unanswered requests, with one-directional capture detection.
- Subscriber linking via S1AP / NGAP UE IDs; SUPI only from a null-scheme SUCI.
- CLI with text/JSON output and `--fail-on` exit codes; optional web demo (`capsight[web]`).
- Validated on 5 public LTE captures (5/5) and 12 public 5G SA captures (12/12).
