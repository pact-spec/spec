# tools

Seven programs. Two check what is committed; the rest are a working
implementation of draft-laxsharma-pact-02.

| File | What it is |
|---|---|
| `validate.py` | The conformance validator: 103 checks over the committed examples and the profile bundle. Schemas, canonicalization, every digest the objects commit to, every signature (with the public keys in `examples/keys/`), the profile's vectors and the two lists printed in Appendix A.6, the RFC 9162 tree, and every vector of Section 14.3 run through the reference Facilitator. |
| `mint_examples.py` | Mints `examples/` from public seeds. Ed25519 is deterministic, so anyone who runs it gets the same bytes and the same digests the draft prints; `--check` diffs against disk. |
| `pactcore.py` | RFC 8785 canonicalization including ECMAScript number formatting, digests, JWS signing and verification over the transmitted protected header, identifier normalization, sorted signature sets, low-S ECDSA, the manifest digest, and the RFC 9162 Merkle tree. |
| `profile.py` | The example terms profile of Appendix A, `bonded-restitution`: its admission rule, its schedule over a trace, its two invariants, and the generator of `profiles/bonded-restitution/vectors.json`. The only file in this directory that knows what an amount is for. |
| `facilitator.py` | A reference Facilitator: the operations of Section 13 over a signed event trace, the state machine of Section 4 including verdict-first and delivery-first flows, lapses, contract trees within one venue, a signed Status on every accepted request, one signed Outcome Record per terminal contract, and RFC 9457 refusals that name the section or the profile section. `--rules` prints what it enforces and what it chose; `--problems` prints every problem type it emits. |
| `agents.py` | Buyer, Seller, Verifier and Challenger clients that check what they are handed. |
| `measure.py` | Drives ten paths through the terminal states on a clock the harness advances, checks every Outcome Record the way a party would, reproduces the seven profile vectors, exercises 40 refusals and 5 acceptances, and reports what each path cost on the wire. |

```
pip install jsonschema referencing cryptography
python3 tools/validate.py
python3 tools/measure.py
python3 tools/facilitator.py --rules
```

`validate.py` runs without `cryptography`, printing `[skip]` for the signature
checks and the vectors that go through the Facilitator, which need it. The
count of 103 is with all three packages installed, and that is what CI runs.
The Facilitator refuses to start without `jsonschema`, because Section 14.2
makes schema conformance a MUST and a Facilitator that skips it is not one.

## What this does and does not answer

Section 16 of the draft says one implementation exists and the author wrote
it. That is this directory, and it is the weakest possible evidence that the
specification is implementable. The experiment of Section 1.4 needs two
independent Facilitators producing the same trace from the same posted records
and the same transfer list from the same trace and profile. This is the first
half of that experiment and an invitation for the second.

Nothing here holds or moves money. The Facilitator records events and hands
each one to the profile the contract names; what comes back is a list of
transfers between named accounts, and the Facilitator signs it without
understanding it. The -01 tools kept three pools of cents; those are gone with
the -01 text.

## Not implemented, and refused rather than faked

A contract that needs any of these is refused at Propose with a problem body
saying so: the `no-window` flow, challenge deposits, network key resolution,
any payment rail, the committed-sample draw, settlement bindings other than the
one the capability document advertises, verification profiles other than
`acceptance`, terms profiles other than the one whose vectors reproduce, and
prices finer than a cent.

## Choices the draft left to the implementer

`facilitator.py --rules` prints the same list. A second implementation is free
to choose differently, which is the kind of disagreement the experiment exists
to surface.

1. **funded is recorded in the same call as accepted.** There is no rail, so
   nothing can be observed, and the Status of a 201 already reads FUNDED.
2. **Retrieval is open on the loopback interface.** Section 17.12 restricts it
   by default and leaves the mechanism to the deployment. This process emits
   no `retrieval-restricted`; a deployment puts authentication in front of it.
3. **Trees within one venue.** A registered child that lives in this process is
   noticed when it reaches a terminal state; any other child's Outcome Record
   must be supplied by POST. No cross-venue GET is made.
4. **Whole cents.** Amounts are settled by the profile's own decimal arithmetic
   and a price with more than two decimals is refused as `amount-invalid`.
5. **Nothing else.** Everything the -01 tools had to choose about value, the
   bond on ABANDONED, the bounty, rank 2, the net reading of rank 3, is now the
   profile's, and Appendix A states each one.

## Measured on 16 September 2026

Intel Core i9-9880H at 2.30 GHz, Python 3.12, Ed25519, single host, loopback
HTTP, in-memory store, no payment rail, the Facilitator's clock advanced by the
harness. The per-call figures move two to three times between sessions on the
same laptop; the order of magnitude is the result.

| Path | Exchanges | Request / response bytes | What the profile moved at the end |
|---|---|---|---|
| FINAL: verdict-first, PASS, window closes | 4 | 3,301 / 4,636 | principal 180.00 to the seller, bond and fund returned |
| SETTLED: the Verifier records FAIL | 4 | 3,301 / 4,549 | escrow 180.00 back to the buyer, bond 18.00 to the sink |
| ABANDONED: deadline, no Delivery | 2 | 1,735 / 2,320 | escrow back, bond and fund returned |
| SETTLED: PASS overturned by a Challenge | 6 | 4,778 / 8,212 | principal 180.00 stays, restitution 18.00 to the buyer, costs 0.50 to the challenger |
| SETTLED: the same with `restitution_basis` price | 6 | 4,775 / 8,212 | the same amounts (cap 180.00, bond 18.00) |
| FINAL after verdict-lapsed | 4 | 2,646 / 4,372 | principal 180.00 |
| FINAL under delivery-first, principal at window-closed | 3 | 2,653 / 3,487 | principal 180.00 |
| FINAL after dispute-lapsed, the PASS stands | 5 | 4,032 / 6,250 | principal 180.00, costs unpaid |
| FINAL with one child in the same venue | 9 | 8,631 / 11,372 | principal 180.00; `children_merkle_root` recomputes |
| FINAL with one child unresolved at L(child) | 6 | 5,184 / 7,514 | principal 180.00; the root is MTH of the empty list |

The first seven rows reproduce the seven vectors in
`profiles/bonded-restitution/vectors.json` exactly. Every Outcome Record was
checked the way a party would check it: the Facilitator's signature verifies,
the transfer list recomputes from the trace with the named profile, no account
is overdrawn and every internal account closes at zero, and every Status
received along the way is a prefix of the final trace.

The messages of the first and fourth rows, request bytes and response bytes:

```
FINAL                                   SETTLED, overturned
POST contracts    201   1735 /  639     POST contracts    201   1735 /  639
POST deliveries   202    911 /  775     POST deliveries   202    911 /  775
POST verdicts     201    655 / 1053     POST verdicts     201    655 / 1053
GET  contract     200      0 / 2169     POST challenges   202    731 / 1263
                                        POST verdicts     201    746 / 1766
                                        GET  contract     200      0 / 2716
```

Each lifecycle completes in 20 to 85 ms, most of it schema validation of the
posted objects (1.7 ms per contract). Per call, medians: canonicalize a
contract 217 us; canonicalize and digest 227 us; sign a Verdict including
canonicalization 151 us; verify a Verdict end to end 263 us; normalize an
identifier 1.9 us; the profile's schedule over the nine-entry overturned trace
27 us; an RFC 9162 root over 2, 8 and 64 leaves 6, 29 and 253 us.
Canonicalization is four times slower than the v0.1.0 figure because it no
longer delegates to `json.dumps`; see the third correction below.

There is no verification-cost figure. The example instrument is a pytest module
whose runtime says nothing about real work.

## Corrections

This file records where it was wrong rather than deleting it, because the point
of publishing a specification for demolition is lost if the corrections are
not published too.

An earlier version claimed, as a defect, that "a defrauded buyer still recovers
nothing from the bond". That was wrong, and it was wrong in the transcript
printed directly beneath it: rank 1 returned the whole escrow to the Buyer
before rank 3 was reached, so the Buyer's loss was zero and a restitution of
zero was correct.

An earlier `facilitator.py` returned the Bond and reached FINAL in the same call
that recorded a PASS, so no challenge window ever opened. A second adversarial
review on 11 September 2026 found that, along with a deadline parsed in local
time, Verdict and Challenge commitments that could be bypassed by omitting a
member, a bounty paid to a Challenger that did not exist, an unsigned
capability document, and no schema validation at Propose. All were fixed in
v0.1.0.

Until 16 September 2026 `pactcore.jcs` serialized the float `1.0` as `1.0`,
where RFC 8785 requires `1`. Every digest v0.1.0 printed over an object that
carried a float was therefore not the digest an RFC 8785 canonicalizer would
compute, and a second implementation would have disagreed with this one on
`spec_hash` and `vtc_hash` for the worked contract without either being able to say why. The
validator's own number check caught it while the -02 examples were being
minted; the fix is a canonicalizer that formats numbers as ECMAScript does,
vector V-25 in the draft pins it, and every -02 digest was minted after the
fix.
