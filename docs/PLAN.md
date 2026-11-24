# capsight build plan

Goal: a tool that turns a mobile-core packet capture into a cited, plain-English diagnosis. Portfolio-grade means: live demo, clean README with a GIF, tests against public captures, and a write-up.

Budget target: ~$0/month (local by default, free hosting tier, bring-your-own LLM key).

## Design principles

1. **Rules decide, the LLM explains.** Every verdict comes from a deterministic rule and cites packet numbers. The LLM only rephrases. No hallucinated diagnoses.
2. **tshark does the decoding.** We never write dissectors.
3. **Privacy first.** Local by default, `--redact` for IMSI/MSISDN/IP, nothing leaves the machine unless the user opts in.
4. **Every rule has a test capture.** No rule ships without a fixture that triggers it and one that does not.

## Phase 0: skeleton (weekend 1) - done

- [x] Python package `capsight`, CLI, `pyproject.toml`, `uv` workflow
- [x] `tshark` wrapper: `-T ek`, selected fields only, streamed
- [x] Internal model: `Packet`, `Transaction`, `Finding` (verdict, evidence packets, severity, fix)
- [x] CI: GitHub Actions, ruff, pytest, tshark installed in the runner
- [x] Test captures synthesized at test time (test-network IMSIs, RFC 5737 addresses)
- [ ] Public sample captures with a SOURCE note (samples/public/SOURCES.md)

## Phase 1: 4G attach and session failures (weekends 2-3) - first rules done

Correlation:
- [x] Diameter: pair requests and answers by hop-by-hop ID + end-to-end ID + command
- [x] Unanswered requests flagged after a configurable timeout (`--timeout`)
- [x] GTPv2-C: pair by sequence number and request/response type
- [x] NAS: link messages to a subscriber via S1AP eNB-UE-S1AP-ID when no IMSI is visible

Rules:
- [x] Diameter Result-Code / Experimental-Result-Code failures (S6a: 5001 user unknown,
      5004 roaming not allowed, 5420 unknown EPS subscription, 5421 RAT not allowed,
      4181 auth data unavailable; base: 3002 unable to deliver, 3004 too busy, ...)
- [x] Diameter request with no answer
- [x] GTPv2-C rejection causes (64 context not found, 69/70 mandatory IE, 72 system failure,
      73 no resources, 78 missing or unknown APN, 84 IP pool exhausted, 92, 93, 100, ...)
- [x] GTPv2-C request with no response
- [x] NAS Attach / TAU / Service Reject with EMM cause
- [x] Authentication Failure: MAC failure (keys mismatch) vs synch failure (SQN)
- [x] PDN Connectivity Reject with ESM cause
- [x] Repeated failures grouped into one finding with count and subscribers
- [x] Validated on the 5 CoLTE public captures, 5/5 correct (docs/VALIDATION.md)
- [ ] Validate against 10+ public captures (need roaming, GTPv2 reject and 5G samples)
- [x] Sync failure followed by a successful Authentication Response reported as info, not a failure

## Phase 2: 5G SA (weekends 4-5)

- [ ] NGAP + 5G NAS registration flow, 5GMM cause codes
- [ ] PFCP session establishment failures (N4), cause values
- [ ] HTTP/2 SBI: decode problem details (`application/problem+json`), map cause strings (e.g. USER_NOT_FOUND, SUBSCRIPTION_NOT_FOUND)
- [ ] Note in docs: 5G NAS is often ciphered; diagnose from NGAP/SBI where NAS is opaque

## Phase 3: interfaces (weekend 6)

- [ ] `--format json` for machine use
- [ ] `--redact` mode (IMSI, MSISDN, IPs hashed consistently so flows stay readable)
- [ ] Optional LLM explain step: OpenAI-compatible endpoint, user's own key or a local model (Ollama); input is the redacted Finding only
- [ ] MCP server exposing `analyze_capture` and `list_findings`
- [ ] Web demo: single-page upload on Hugging Face Spaces (Gradio), runs analysis server-side, deletes upload after the request, size limit

## Phase 4: IMS / VoLTE (stretch)

- [ ] SIP REGISTER / INVITE failure classification (401 loops, 403, 404, 480, 503)
- [ ] Diameter Cx (UAR/MAR/SAR) and Rx result codes
- [ ] Call flow ladder diagram output (Mermaid)

## Launch and portfolio checklist

- [ ] README with a demo GIF (asciinema or vhs)
- [ ] Live demo link
- [ ] "Supported failures" table generated from the rule registry
- [ ] Blog post: "Teaching a tool to read 4G/5G packet captures"
- [ ] Post in Open5GS / free5GC discussions and r/networking with a real solved example
- [ ] Track: rules count, captures tested, stars, external issues solved

## Non-goals

- Live capture or running on production traffic
- Writing protocol dissectors
- Decrypting ciphered NAS
