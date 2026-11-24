# capsight

**Drop in a packet capture, get a plain-English diagnosis of why your mobile network call flow failed.**

> Status: early development. 4G core rules work today. See [docs/PLAN.md](docs/PLAN.md) for the roadmap.

Debugging a 4G/5G core usually means scrolling through thousands of Diameter, GTP and NAS packets in Wireshark, looking up result codes and cause values by hand. capsight does that part for you:

```
$ capsight analyze attach-failure.pcap

VERDICT  Attach rejected: the HSS does not know this subscriber.

WHY      ULA from the HSS carried Experimental-Result-Code 5001
         (DIAMETER_ERROR_USER_UNKNOWN) for IMSI 001010000000001.
         The MME then sent Attach Reject, EMM cause #8.

WHERE    packet #412  12:02:11.384  S6a  ULR -> ULA (5001)
         packet #415  12:02:11.391  NAS  Attach Reject (#8)

FIX      Provision the subscriber in the HSS/UDM, or check that the
         IMSI on the SIM matches the provisioned one.
```

(Illustrative output. IMSIs in examples use the 001/01 test network.)

## How it works

1. **Decode** - `tshark` turns the capture into structured fields (no custom dissectors).
2. **Correlate** - packets are grouped into transactions (request/answer pairs, per-subscriber flows) by session IDs, hop-by-hop IDs, TEIDs and IMSI.
3. **Diagnose** - a deterministic rule engine matches known failure patterns (result codes, cause values, timeouts, missing answers). Every verdict cites the exact packets.
4. **Explain (optional)** - an LLM rewrites the finding in plain language. It never invents the verdict; rules do. Works with your own API key or a local model, and is fully optional.

## What it detects today

- Diameter answers with a failure Result-Code or Experimental-Result-Code (e.g. S6a user unknown, roaming not allowed, RAT not allowed, unable to deliver)
- Diameter and GTPv2-C requests that never got an answer
- GTPv2-C rejections (e.g. missing or unknown APN, IP pool exhausted, context not found)
- NAS Attach / TAU / Service Reject with EMM cause
- Authentication failures (key mismatch vs sequence-number resync)
- PDN Connectivity Reject with ESM cause

Repeated failures are grouped, with a count and the subscribers affected.

## Protocols (planned)

| Protocol | Interface | Phase |
|---|---|---|
| Diameter S6a | MME - HSS | 1 |
| GTPv2-C | S11 / S5 / S8 | 1 |
| NAS EMM/ESM | UE - MME | 1 |
| PFCP | N4 | 2 |
| NGAP / 5G NAS | N2 / N1 | 2 |
| HTTP/2 SBI | 5GC NFs | 2 |
| SIP / Diameter Cx, Rx | IMS / VoLTE | 3 |

## Interfaces

- **CLI** - `capsight analyze file.pcap`
- **Web** - upload a capture, get the report (planned)
- **MCP server** - let AI agents call capsight as a tool (planned)

## Privacy

Captures contain subscriber identities. capsight runs locally by default, never uploads a capture anywhere, and has a `--redact` mode that masks IMSI, MSISDN and IP addresses in reports. The optional LLM step only receives the redacted finding, never the raw capture.

## Requirements

- Python 3.11+
- Wireshark / `tshark` 4.x

## License

MIT
