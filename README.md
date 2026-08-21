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
- **Complete** — settlement gated on verification, with a fraud-proof
  challenge window and challengers paid from the slashed bond.
  Verification is graded: re-execution → TEE attestation (RATS/EAT) →
  zkML proof → staked jury. (The -00 makes release optimistic by default.
  Two audit rounds found that this does not close economically, and -01
  changes the default. See Status below.)
- **Trust** — settlement emits co-signed **Work Attestations**: reputation
  as the exhaust of settlement — unforgeable without funding real, bonded
  contracts. Contracts compose into **Merkle contract trees** with
  cascading liability; repeated dealings run over **contract channels**.

## Status

- **Submitted to the IETF** (27 July 2026):
  [draft-laxsharma-pact-00](https://datatracker.ietf.org/doc/draft-laxsharma-pact/)
  is live on the Datatracker.
- Read it: [rendered HTML](https://pact-spec.github.io/spec/draft/draft-laxsharma-pact-00.html)
  · [plain text](draft/draft-laxsharma-pact-00.txt)
  · [XML source](draft/draft-laxsharma-pact-00.xml)
- This is a **-00 strawman, published for demolition.** Issues and PRs
  welcome, especially "here is where this breaks." Feedback is collected
  for the next revision in the
  [-01 changelog issue](https://github.com/pact-spec/spec/issues/1).

### Known defects in -00, and what -01 changes

External review and two adversarial audit rounds found that the -00's
settlement economics do not close. Everything is logged in
[issue #1](https://github.com/pact-spec/spec/issues/1), with dispositions.
The three that matter most if you are reading the draft today:

1. **A defrauded buyer recovers nothing from the bond.** Section 4.3
   directs the slashed bond to the challenger and then to a neutral sink
   "rather than to any party to the dispute", and the buyer is a party to
   the dispute. The bond is a fine, not collateral.
2. **Optimistic release exceeds the bond, so defection dominates.**
   Honest performance requires roughly `q * ((P - E) + B) >= C`. On the
   worked example's own numbers a 10 percent bond needs a 91 percent
   detection rate, which nothing in -00 supplies.
3. **Challenger reimbursement is capped by the bond** while re-execution
   verification costs about what execution costs, so the reimbursement
   requirement in 4.3 is unsatisfiable in the common case.

-01 is targeted for mid-September 2026 and reworks the settlement core,
adds a Delivery object and a Verifier role, and corrects the x402, A2A
and AP2 bindings. The repository is being corrected ahead of it where a
fix does not depend on those design decisions.
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
- `criteria_hash`, and `taskspec.acceptance.harness_hash`, = SHA-256 over
  the JCS-canonicalized manifest of `examples/acceptance-harness/`, which
  maps each file's relative path to the SHA-256 of its bytes
- `bid.json` `commitment` = SHA-256 over the JCS-canonicalized reveal in
  `bid-reveal.json`
- `attestation.json` `vtc_hash` = SHA-256 over the VTC minus its
  `signatures` member

The validator also checks the rules JSON Schema cannot express (parties
are distinct, one signature per named party, protected headers carry
`alg`/`kid`/`typ` with an allowed algorithm), pins the canonical key
order described below, and runs negative vectors that must be rejected.

```
pip install jsonschema referencing
python3 tools/validate.py
```

Two honest caveats. Signature values are illustrative placeholders, since
producing real JWS signatures requires party keys. And `jcs()` in
`tools/validate.py` is a restricted RFC 8785 implementation that is
correct for the value types these examples use but is not a conforming
general one, so a green run evidences self-consistency of these examples
rather than canonicalization interoperability with another
implementation. What it does get right, and pins with a vector, is the
key order: RFC 8785 section 3.2.3 sorts object keys by UTF-16 code unit,
which `json.dumps(sort_keys=True)` does not, the two agreeing throughout
the Basic Multilingual Plane and diverging above it. What remains
unimplemented is the ECMAScript number serialization rules over the full
float range.

## Building the draft

```
pip install xml2rfc
xml2rfc --text --html draft/draft-laxsharma-pact-00.xml
```

## Relationship to other work

PACT composes A2A, x402 (as a proposed `pact-escrow` release-policy
profile over the merged `auth-capture` scheme, which the -00 text
inaccurately calls a payment scheme), AP2, OAuth token exchange
(RFC 8693), RATS/EAT (RFC 9334/9711), and JCS (RFC 8785). It differs from marketplace-mediated escrow (VCAP), transport
negotiation (AGTP), and passport formats (ATEP, ERC-8004) — and cites and
positions against each in Section 1.2 of the draft. Lineage: the Contract
Net Protocol (Smith, 1980), finally runnable among untrusting parties.

## License

Code and schemas: Apache-2.0 (see `LICENSE`). The Internet-Draft is
subject to the IETF Trust Legal Provisions (BCP 78/79); see
`CONTRIBUTING.md`.
