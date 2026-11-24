# capsight build plan

Goal: a tool that turns a mobile-core packet capture into a cited, plain-English diagnosis. Portfolio-grade means: live demo, clean README with a GIF, tests against public captures, and a write-up.

Budget target: ~$0/month (local by default, free hosting tier, bring-your-own LLM key).

## Design principles

1. **Rules decide, the LLM explains.** Every verdict comes from a deterministic rule and cites packet numbers. The LLM only rephrases. No hallucinated diagnoses.
2. **tshark does the decoding.** We never write dissectors.
3. **Privacy first.** Local by default, `--redact` for IMSI/MSISDN/IP, nothing leaves the machine unless the user opts in.
4. **Every rule has a test capture.** No rule ships without a fixture that triggers it and one that does not.

## Phase 0: skeleton (weekend 1)

- [ ] Python package `capsight`, CLI via `typer`, `pyproject.toml`, `uv` workflow
- [ ] `tshark` wrapper: run with `-T ek` or `-T json`, selected fields only, stream large files
- [ ] Internal model: `Packet`, `Transaction`, `Finding` (verdict, evidence packets, severity, fix)
- [ ] CI: GitHub Actions, ruff, pytest, tshark installed in the runner
- [ ] Fixture folder with public sample captures only (Wireshark sample captures, Open5GS/free5GC issue attachments with compatible licenses), each with a SOURCE note

## Phase 1: 4G attach and session failures (weekends 2-3)

Correlation:
- [ ] Diameter: pair requests and answers by hop-by-hop ID + end-to-end ID, flag unanswered requests (timeout)
- [ ] GTPv2-C: pair by sequence number, track TEIDs per subscriber
- [ ] NAS: link to subscriber via IMSI / GUTI where visible (plaintext NAS only)

Rules (first set):
- [ ] S6a AIR/ULR result codes: 5001 user unknown, 5420 unknown EPS subscription, 5421 RAT not allowed, 5004 roaming not allowed, 3002 unable to deliver, 3004 too busy
- [ ] Diameter request with no answer within N seconds
- [ ] GTPv2 Create Session Response causes: 64 context not found, 66 missing/unknown APN, 73 no resources, 78 missing mandatory IE, 92 request rejected
- [ ] NAS Attach Reject / TAU Reject EMM causes (#3, #6, #7, #8, #11, #13, #15, #19)
- [ ] Authentication failure: MAC failure vs synch failure (SQN out of range)
- [ ] Output: verdict, why, where (packet numbers + timestamps), suggested fix

Deliverable: `capsight analyze file.pcap` works on 10+ public captures.

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
