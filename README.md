# PACT: a task contract record for autonomous agents

**Propose · Agree · Complete · Trust**

By late 2026 an agent can prove who it is, act under a delegated authority,
discover another agent, call it, receipt the call and pay for it. None of
those records what one agent asked another to do, what came back, or
whether the one met the other. PACT specifies exactly four things to close
that gap:

- a co-signed **Verifiable Task Contract** whose digest covers its
  signature set, naming its settlement terms by reference (a profile
  identifier, a digest over the profile's bundle, and an opaque parameter
  object the document never reads);
- a **Delivery** record and the **Verdict** record bound to it by digest,
  with a challenge window in which a **Challenge** can be answered by a
  second Verdict;
- an **event trace**, signed by a Facilitator, from which one **Outcome
  Record** per contract is produced and against which any party can check
  what the named terms profile computed;
- a **Merkle commitment** from a parent contract's Outcome Record to its
  children's, so a tree of subcontracts settles in a verifiable order.

What the terms mean, and everything about who holds or moves value under
them, is the profile's to say and is outside this document. An example
profile is printed as an appendix so that the protocol can be exercised,
and it is normative nowhere.

## Status

- Source of record for **revision -02** is `draft/draft-laxsharma-pact-02.*`
  at tag `v0.2.0`. The revision the IETF Datatracker shows as current is at
  [draft-laxsharma-pact](https://datatracker.ietf.org/doc/draft-laxsharma-pact/);
  -01 was posted 4 September 2026 and stays checkable at its archive URL.
- An individual submission with no formal standing in the standards
  process. Not adopted by any working group, not endorsed by the IETF.
- The -00 (27 July 2026) and -01 sources stay in `draft/` so that citations
  remain checkable. The review that led from -00 to -01, with dispositions,
  is in [issue #1](https://github.com/pact-spec/spec/issues/1).

### What -02 changed

Two readers on the IETF dispatch list observed in September 2026 that the
-01 made who owed whom the subject of the document, which placed it outside
what the IETF is placed to evaluate. They were right, and -02 separates the
protocol from the meaning of its terms. Appendix B of the draft lists every
change; the ones with wire consequences:

- `pact` is `0.2` and every committed digest changed.
- The `liability` member is gone. A contract carries `terms`: a profile
  URI, `profile_hash` over the profile's bundle, and `parameters` the
  document does not read. The -01 figures are the parameters of the example
  profile in `profiles/bonded-restitution/`.
- The four release modes are replaced by three flows (`verdict-first`,
  `delivery-first`, `no-window`) and a profile parameter.
- `verification.max_verdict_seconds` is added, with a `verdict-lapsed`
  event, so a silent Verifier cannot hold a contract forever.
- The Work Attestation is the **Outcome Record**: parties, an outcome
  object, the full trace, and `terms_result`. One per contract, signed by
  the Facilitator alone.
- Every accepted request is answered with a signed **Contract Status**
  carrying the trace, and every later Status extends it as a prefix, so a
  Facilitator that reorders or rewrites events is attributable.
- `delivery_hash` covers the Delivery's signature; signature sets are
  sorted; ECDSA is low-S; Merkle leaves cover signatures.
- A nonconformant Delivery is refused and recorded nowhere; a Seller-signed
  Challenge is refused; a Buyer's Challenge cannot be refused.
- Contract trees work across Facilitators, with a finite latest finality
  instant per contract and the rule L(child) before L(parent).
- Media types move to the vendor tree; the two registries the -01 requested
  are withdrawn; problem types use a `tag:` URI namespace.
- The -01 digests were computed by a canonicalizer that printed the float
  one as `1.0`, which RFC 8785 does not allow, so the `spec_hash` and `vtc_hash` the -01
  printed are not what a conforming implementation computes. The -02
  examples were minted after the fix and vector V-25 pins the rule.

## Repository layout

| Path | Contents |
|---|---|
| `draft/` | The Internet-Draft, -02, -01 and -00 (XML source, plain text, HTML) |
| `schemas/` | JSON Schema (2020-12) for every -02 object |
| `examples/` | The worked example the draft prints: contract, Delivery, two Verdicts, Challenge, Status, Outcome Record, capability document, with real signatures |
| `examples/keys/` | The public keys that verify those signatures; the private keys derive from public seeds and are not secrets |
| `examples/task-content/` | The three files the TaskSpec commits to by sibling hash |
| `examples/acceptance-harness/` | The instrument `criteria_hash` commits to, as a manifest |
| `examples/legacy-00/` | The -00 call-for-bids, bid and capability objects, kept so the published -00 stays checkable; not part of the conformance surface |
| `profiles/bonded-restitution/` | The example terms profile bundle: README, parameter schema, vectors. `profile_hash` is the manifest digest over these three files |
| `tools/` | The validator, the example minter, and the reference implementation; see `tools/README.md` |
| `diagrams/` | Protocol diagrams |

## The examples are what the draft prints, and they recompute

Every digest in the draft's worked example (Section 15) is read out of
`examples/` by the build, and `tools/validate.py` recomputes each one:

- `spec_hash` is the digest over `taskspec.json`; the three URIs inside it
  carry sibling hashes over `examples/task-content/`;
- `criteria_hash` is the manifest digest over `examples/acceptance-harness/`;
- `profile_hash` is the manifest digest over `profiles/bonded-restitution/`;
- `vtc_hash` is the digest over the signed contract, `delivery_hash` over
  the signed Delivery, and every trace entry's `object` over the signed
  object it names;
- the transfers in the Outcome Record are the profile's schedule over its
  own trace, and satisfy no-overdraft and closure.

The signatures are real Ed25519 over the Section 14.1 signing input, minted
by `tools/mint_examples.py` from public seeds so that anyone can reproduce
the bytes. The validator verifies all of them with `examples/keys/`.

```
pip install jsonschema referencing cryptography
python3 tools/validate.py
```

107 checks, in the validator's own words: 10 schema conformance; 4 canonicalization (RFC 8785); 18 hash commitments; 21 rules of the document; 9 signature verification; 11 terms profile: bonded-restitution; 6 Merkle tree hash (RFC 9162); 28 conformance vectors of Section 14.3, through the reference Facilitator. `pactcore.jcs` is a full RFC 8785 canonicalizer for
the JSON value types, including UTF-16 key order and ECMAScript number
formatting; both are pinned by vectors because both were got wrong once.

## Building the draft

```
pip install xml2rfc
xml2rfc --text --html draft/draft-laxsharma-pact-02.xml
```

Figures wider than the page are folded per RFC 8792 and say so in their
first line; the digests in them are whole once the fold is removed.

## Relationship to other work

PACT composes JWS (RFC 7515) with keys resolved through DID Core, did:web
or a JWK Set, JCS (RFC 8785), the RFC 9162 Merkle tree, RATS/EAT evidence
formats (RFC 9334/9711) for the TEE verification tier, and RFC 9457 problem
details for errors. It names a settlement binding rather than assuming a
rail, and it binds none of the agent transport or payment protocols; the
introduction relates it to the adjacent drafts on AP2 binding, transport
negotiation, action receipts, accountability composition, delegation chains
and contestability. Carrying terms by reference follows ACME's
terms-of-service URL, X.509 policy identifiers and the Internet Open
Trading Protocol. Lineage: the Contract Net Protocol (Smith, 1980),
finally runnable among untrusting parties.

## License

Code and schemas: Apache-2.0 (see `LICENSE`). The Internet-Draft is
subject to the IETF Trust Legal Provisions (BCP 78/79); see
`CONTRIBUTING.md`.
