# PACT: a contract layer for autonomous agent commerce

**Propose · Agree · Complete · Trust**

Today's agent protocols move tasks (A2A, unpriced), money (x402,
unconditional) and payment authorization (AP2, unverified). Nothing binds
work to money to proof. PACT is a proposed contract layer that closes that
gap, and it specifies exactly four things:

- **liability** as a required member of a co-signed Verifiable Task
  Contract (VTC): a seller bond, a verification fund, a cap and a
  restitution basis, agreed before any work starts;
- a **Delivery** object against which the contract is judged;
- a **settlement** procedure whose release of escrow is conditioned on a
  declared assurance level, with a challenge path that pays the challenger
  from a fund the contract itself provisions;
- a **subcontract tree** through which liability cascades upward as
  recovery and never downward as discharge.

Everything else PACT needs (identity, delegation, discovery, transport,
audit, the payment rail, reputation, a dispute forum) it composes from
existing work and cites. Settlement emits a Work Attestation signed by the
Facilitator, so a seller cannot veto its own negative record.

## Status

- **Revision -01 is current.** Posted to the IETF Datatracker on
  4 September 2026, expires 8 March 2027:
  [draft-laxsharma-pact](https://datatracker.ietf.org/doc/draft-laxsharma-pact/).
- Read it: [rendered HTML](https://www.ietf.org/archive/id/draft-laxsharma-pact-01.html)
  · [plain text](draft/draft-laxsharma-pact-01.txt)
  · [XML source](draft/draft-laxsharma-pact-01.xml)
- An individual submission with no formal standing in the standards
  process. Not endorsed by the IETF.
- The -00 of 27 July 2026 is superseded. Its sources stay in `draft/` so
  that citations of it remain checkable. The review that led from -00 to
  -01, with dispositions, is in
  [issue #1](https://github.com/pact-spec/spec/issues/1).

### What -01 changed

External review and two adversarial audit rounds found that the -00's
settlement economics did not close. A defrauded buyer recovered nothing
from the bond, optimistic release let a seller walk away with more than
the bond, and challenger reimbursement was capped by a bond too small to
cover re-execution. The -01 reworks the settlement core around those
findings and narrows the document to what only PACT can specify:

- The sealed-bid award procedure and contract channels are gone. How a
  contract is awarded is out of scope.
- Release is no longer optimistic by default. A contract declares an
  assurance mode and a release mode, and a Facilitator must refuse a
  contract whose bond cannot cover the declared detection probability.
- Recovery follows a five-rank waterfall that pays the buyer's restitution
  before anything is burned.
- A Delivery object and a Verifier role are defined; the Challenge object
  the -00 named but never specified now exists.
- `vtc_hash` is computed over the contract including its signature set,
  so the digest proves who agreed and not only what was written.
- The x402, A2A and AP2 bindings are corrected. PACT composes with x402 as
  the `pact-escrow` scheme.

## Repository layout

| Path | Contents |
|---|---|
| `draft/` | The Internet-Draft, -01 and -00 (XML source, plain text, HTML) |
| `schemas/` | JSON Schema (2020-12) for every -01 protocol object |
| `examples/` | Worked examples whose hash commitments verify (see below) |
| `examples/legacy-00/` | The -00 call-for-bids, bid and capability objects, kept so the published -00 stays checkable; not part of the conformance surface |
| `tools/validate.py` | Validates the examples against the schemas and checks every rule the draft states |
| `diagrams/` | Protocol diagrams |

## The examples are self-consistent

`examples/` is not illustrative pseudo-JSON. The commitments verify:

- `vtc.json` `spec_hash` is SHA-256 over the JCS-canonicalized (RFC 8785)
  `taskspec.json`;
- `criteria_hash`, and `taskspec.acceptance.harness_hash`, is SHA-256 over
  the JCS-canonicalized manifest of `examples/acceptance-harness/`, which
  maps each file's relative path to the SHA-256 of its bytes;
- `vtc_hash` in `delivery.json`, `verdict.json`, `challenge.json` and
  `attestation.json` is SHA-256 over the JCS-canonicalized contract
  **including** its `signatures` member (-01 Section 6);
- the Merkle root of the subcontract tree follows RFC 9162: leaves hashed
  with a `0x00` prefix, nodes with `0x01`, split at the largest power of
  two less than the count.

The validator runs 66 checks: 7 schema, 2 canonicalization, 10 hash,
10 rule, 9 assurance-constraint, 6 Merkle, and 22 negative vectors from
the draft's conformance table. The rules JSON Schema cannot express are
checked in code: parties distinct after normalization, one signature per
named party, protected headers carrying `alg`, `kid` and `typ` with an
allowed algorithm, and the assurance constraint of -01 Section 7.2 against
the worked figures of Section 14.

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
unimplemented is the ECMAScript number serialization over the full float
range.

## Building the draft

```
pip install xml2rfc
xml2rfc --text --html draft/draft-laxsharma-pact-01.xml
```

## Relationship to other work

PACT composes A2A task identifiers, x402 (as the `pact-escrow` scheme),
AP2 mandates, JWS (RFC 7515) with keys resolved through DID Core, did:web
or a JWK Set, JCS (RFC 8785), the RFC 9162 Merkle tree, RATS/EAT evidence
formats (RFC 9334/9711) for the TEE verification tier, and RFC 9457
problem details for errors. Its settlement is an optimistic fair exchange
in the sense of Asokan, Shoup and Waidner (1998). The bond-sizing rule it
relies on is prior art (Polinsky and Shavell; Belenkiy et al.;
Mamageishvili and Felten) that the draft cites rather than reintroduces.
The introduction relates PACT to the adjacent drafts on AP2 binding,
transport negotiation, action receipts, accountability composition,
delegation chains and contestability. Lineage: the Contract Net Protocol
(Smith, 1980), finally runnable among untrusting parties.

## License

Code and schemas: Apache-2.0 (see `LICENSE`). The Internet-Draft is
subject to the IETF Trust Legal Provisions (BCP 78/79); see
`CONTRIBUTING.md`.
