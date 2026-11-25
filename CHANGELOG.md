# Changelog

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
