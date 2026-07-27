# PACT — A Contract Layer for Autonomous Agent Commerce

**Propose · Agree · Complete · Trust**

Today's agent protocols move tasks (A2A, unpriced), money (x402,
unconditional), and payment authorization (AP2, unverified) — but nothing
binds **work to money to proof**. PACT is a proposed contract layer that
closes that gap:

- **Propose** — sealed-bid, second-price (Vickrey) task awards: truthful
  bidding is the dominant strategy, so there is no LLM-vs-LLM negotiation
  attack surface.
- **Agree** — a co-signed **Verifiable Task Contract (VTC)** binds parties
  (DIDs), scope (hash-committed TaskSpec), price, verification method, and
  liability; funds lock in escrow.
- **Complete** — optimistic settlement: pay at delivery, with a fraud-proof
  challenge window; valid challengers are paid from the slashed bond.
  Verification is graded: re-execution → TEE attestation (RATS/EAT) →
  zkML proof → staked jury.
- **Trust** — settlement emits co-signed **Work Attestations**: reputation
  as the exhaust of settlement — unforgeable without funding real, bonded
  contracts. Contracts compose into **Merkle contract trees** with
  cascading liability; repeated dealings run over **contract channels**.

## Status

- **Submitted to the IETF** (27 July 2026):
  [draft-laxsharma-pact-00](https://datatracker.ietf.org/doc/draft-laxsharma-pact-00/)
  is live on the Datatracker.
- Read it: [rendered HTML](https://pact-spec.github.io/spec/draft/draft-laxsharma-pact-00.html)
  · [plain text](draft/draft-laxsharma-pact-00.txt)
  · [XML source](draft/draft-laxsharma-pact-00.xml)
- This is a **-00 strawman, published for demolition.** Issues and PRs
  welcome — especially "here is where this breaks." Feedback is collected
  for the next revision in the
  [-01 changelog issue](https://github.com/pact-spec/spec/issues).
- Not endorsed by the IETF; an individual submission with no formal
  standing in the standards process.

## Repository layout

| Path | Contents |
|---|---|
| `draft/` | The Internet-Draft (XML source, plain-text, HTML) |
| `schemas/` | JSON Schema (2020-12) for every protocol object |
| `examples/` | Worked examples — **hashes really verify** (see below) |
| `tools/validate.py` | Validates examples against schemas and checks every hash commitment |
| `diagrams/` | Protocol diagrams |

## The examples are self-consistent

`examples/` is not illustrative pseudo-JSON. The commitments verify:

- `cfb.json` / `vtc.json` `spec_hash` = SHA-256 over the
  JCS-canonicalized (RFC 8785) `taskspec.json`
- `criteria_hash` = SHA-256 over `acceptance-tests.txt`
- `bid.json` `commitment` = SHA-256 over the JCS-canonicalized reveal in
  `bid-reveal.json`
- `attestation.json` `vtc_hash` = SHA-256 over the VTC minus its
  `signatures` member

```
pip install jsonschema referencing
python3 tools/validate.py
```

(Signature values are illustrative placeholders; producing real JWS
signatures requires party keys.)

## Building the draft

```
pip install xml2rfc
xml2rfc --text --html draft/draft-laxsharma-pact-00.xml
```

## Relationship to other work

PACT composes A2A, x402 (as a proposed `pact-escrow` payment scheme),
AP2, OAuth token exchange (RFC 8693), RATS/EAT (RFC 9334/9711), and JCS
(RFC 8785). It differs from marketplace-mediated escrow (VCAP), transport
negotiation (AGTP), and passport formats (ATEP, ERC-8004) — and cites and
positions against each in Section 1.2 of the draft. Lineage: the Contract
Net Protocol (Smith, 1980), finally runnable among untrusting parties.

## License

Code and schemas: Apache-2.0 (see `LICENSE`). The Internet-Draft is
subject to the IETF Trust Legal Provisions (BCP 78/79); see
`CONTRIBUTING.md`.
