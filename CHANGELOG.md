# Changelog

## Unreleased

- Gx/Gy policy and charging: PCRF/OCS rejects by interface and request type, per-service
  (rating group) credit failures with Final-Unit-Action, policy rules the gateway could not
  install, and a failed CCR-I linked to the Create Session reject it caused.

## 0.2.0

First release on PyPI. Usable on real captures.

- `--imsi X`: one subscriber's attach, authentication, session and data steps in order, and
  where it stopped.
- Large captures: streaming analysis; a 1.1 GB capture runs in about 780 MB of memory.
  Same findings as 0.1 on 476 real and 17 public captures.
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
