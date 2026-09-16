# tools

Five programs. The first checks the committed examples; the rest are a working
implementation of the protocol.

| File | What it is |
|---|---|
| `validate.py` | The conformance validator: 71 checks over the committed examples, the Section 13.3 vectors, and the two vectors V-21 and V-22 added here ahead of the text (choice 7 below). Needs only `jsonschema` and `referencing`. It recomputes digests and Merkle roots but verifies no signature; the constraint, the normalization and the signature-set rules are imported from `pactcore.py` so the two tools cannot disagree. |
| `pactcore.py` | Canonicalization, digests, JWS signing and verification over the transmitted protected header, identifier normalization, the assurance constraint in exact decimal arithmetic, and the RFC 9162 Merkle tree. |
| `facilitator.py` | A reference Facilitator: the six operations of Table 1 over five paths, the Figure 2 state machine including the challenge window and the Figure 6 overturned-PASS path, the Section 7.4 waterfall, schema validation of every posted object, a signed capability document, and RFC 9457 refusals in the draft's own namespace that name the rule. `--rules` prints what it enforces and what it chose; `--problems` prints every problem type it emits with its status and section. |
| `agents.py` | Buyer, Seller, Verifier and Challenger clients. |
| `measure.py` | Drives five contracts through the terminal states on a clock the harness advances, exercises 24 refusals and 2 acceptances each on the rule it is named for, asserts that money balances, checks every minted object and the capability document against the schemas, and reports costs. |

```
pip install jsonschema referencing cryptography
python3 tools/validate.py
python3 tools/measure.py
python3 tools/facilitator.py --rules
```

`validate.py` needs only the first two packages, so a checkout still validates
on a machine with nothing else installed. The Facilitator refuses to start
without `jsonschema`, because Section 12.1 makes schema conformance a MUST at
Propose and a Facilitator that skips it is not one.

## What this does and does not answer

Section 15 of the draft records that no Facilitator, Buyer or Seller exchanging
messages over the Section 12 endpoints was known to the author when -01 was
posted. This is that implementation, and it is one implementation written by the
same person who wrote the specification, which is the weakest possible evidence
that the specification is implementable. The falsifiable experiment of Section
1.4 needs *two independent* implementations settling each other's contracts.
This is an invitation for the second, not a substitute for it.

The signatures are real Ed25519. The contracts `measure.py` mints are fresh and
so are the keys, deliberately: the committed examples under `examples/` keep
their placeholder signature values because the published Internet-Draft prints
their digests in Section 14 and cannot be corrected, so re-signing them would
silently desynchronise this repository from that document. Real keys and
recomputed digests belong together in a -02.

No payment rail is touched. Section 1.2 puts the rail out of scope and
`price.settlement` names a binding; money here is an integer number of cents in
three pools. What is real is the object flow, the state machine, the signature
verification and the arithmetic.

## Not implemented, and refused rather than faked

A contract that needs any of these is refused at Propose with a problem body
saying so, rather than accepted and then stranded or silently mishandled:
subcontracts (Section 10; `liability.parent` is refused as `parent-unresolvable`),
release modes other than on-verification, assurance modes other than certain,
verification profiles other than acceptance, challenge deposits, settlement
bindings other than the one the capability document advertises, and amounts
finer than a cent. Key resolution is an in-process registry with the Section
13.1.1 interface; the network lookup is the part that is stubbed.

## Choices the draft left to the implementer

Each of these is a place where the -01 text is silent or says two things.
`facilitator.py --rules` prints the same list. They are choices, not rules, and
a second implementation is free to choose differently, which is exactly the
kind of disagreement the experiment exists to surface.

1. **The Bond on ABANDONED.** Section 6 slashes it "to the extent of
   `restitution_basis`", which under `released` with nothing released is zero.
   Section 7.6 returns the Bond on FINAL or SETTLED and says nothing about the
   third terminal state. This implementation returns it. Measured: a Seller that
   signs, posts 18.00, and never delivers gets the whole 18.00 back.
2. **Rank 3 restores the Buyer's loss, net of rank 1.** Read literally, basis
   `price` would pay the Bond on top of a reversed escrow in the pre-release
   failure, a windfall the draft's own `remainder_to` rule exists to prevent.
   Under the net reading the two basis values differ only when release was
   partial; under on-verification they never differ.
3. **The bounty.** The draft requires it to be non-exclusive and forbids capping
   it at a fraction "chosen for tidiness", and does not fix it. This
   implementation pays the whole remaining Bond after rank 3, split equally among
   successful Challengers. With K independent discoverers a full bounty each is
   not fundable from one Bond, which the draft's text assumes it is.
4. **Rank 2 pays 0.00.** The Challenge object has no member for the documented
   costs rank 2 reimburses, and its schema is closed.
5. **A Challenge with no Verdict inside `max_dispute_seconds` lapses**; the
   earlier Verdict stands and the window is not extended. The draft declares the
   bound and never applies it.
6. **PROPOSED is not observable.** With no rail the pools are debited in memory
   when a co-signed contract is accepted, so the 201 reports FUNDED.
7. **The signature set is sorted and ECDSA is low-S.** Section 6 digests the
   contract including its `signatures` array, and the -01 text does not order
   that array, so one agreement signed in two orders has two `vtc_hash` values.
   This implementation refuses an array not sorted by the Section 9.1
   normalized kid (ties by the raw kid, code point order) as
   `signatures-unordered`, and refuses an ECDSA signature whose s is in the high
   half of the curve order, for the same reason: a second valid encoding of one
   signature is a second digest. Both are checked in `validate.py` and both
   are proposed as rules for the next revision. It also computes `delivery_hash` over the Delivery
   including its signature, which is what `validate.py` now checks too; the
   v0.1.0 validator excluded the signature and the two tools disagreed.

## Measured on 12 September 2026

Intel Core i9-9880H at 2.30 GHz, Python 3.12.11, Ed25519, single host, loopback
HTTP, in-memory store, no payment rail, the Facilitator's clock advanced by the
harness. The same code has produced per-call figures two to three times apart
across sessions on the same laptop; the order of magnitude is the result.

| Path | Exchanges | Request / response bytes | Attestation amounts (settled / restituted / slashed) |
|---|---|---|---|
| FINAL: PASS, window closes | 4 | 3,065 / 4,011 | 180.00 / 0.00 / 0.00 |
| SETTLED: verifier FAIL | 4 | 3,071 / 4,014 | 0.00 / 0.00 / 18.00 |
| ABANDONED: no Delivery | 3 | 1,469 / 3,780 | 0.00 / 0.00 / 0.00 |
| SETTLED: PASS overturned by a Challenge | 6 | 4,458 / 5,446 | 180.00 / 18.00 / 18.00 |

Each lifecycle completes in 25 to 45 ms, most of it schema validation of the
posted objects. Per call, medians: canonicalize a contract 51 us; canonicalize
and digest 60 us; sign a contract including canonicalization 128 us; verify a
contract signature end to end 198 us, of which the Ed25519 primitive over 1.5 KB
is 123 us; normalize an identifier 1.3 us; the assurance constraint in exact
decimal 2.1 us; an RFC 9162 root over 2, 8 and 64 leaves 4, 21 and 179 us.

The overturned-PASS row is the one the restitution basis does any work in, and
its amounts are what Section 11's worked attestation should carry: the draft's
example has restituted 18.00 with settled 0.00, which fits neither path.

There is no verification-cost figure. The example instrument is a pytest module
whose runtime says nothing about real work, and an earlier version of this file
reported a number for it that was pytest's import time.

## Corrections

This file has been wrong twice, and both are recorded here rather than deleted,
because the point of publishing a specification for demolition is lost if the
corrections are not published too.

An earlier version claimed, as a defect, that "a defrauded buyer still recovers
nothing from the bond". That was wrong, and it was wrong in the transcript
printed directly beneath it: rank 1 returns the whole escrow to the Buyer before
rank 3 is reached, so the Buyer's loss is zero and a restitution payment of zero
is correct.

An earlier version of `facilitator.py` returned the Bond and reached FINAL in the
same call that recorded a PASS, so no challenge window ever opened and the
Figure 6 path was unreachable in the only release mode the draft requires. A
second adversarial review on 11 September found that, along with a deadline
parsed in local time, Verdict and Challenge commitments that could be bypassed
by omitting a member, a bounty paid to a Challenger that did not exist, an
unsigned capability document, and no schema validation at Propose. All are fixed
and the numbers above are from the corrected code.
