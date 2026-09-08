# tools

Four programs. The first checks the committed examples; the other three are a
working implementation of the protocol.

| File | What it is |
|---|---|
| `validate.py` | The conformance validator: 66 checks over the committed examples and the Section 13.3 vectors. Needs only `jsonschema` and `referencing`. |
| `pactcore.py` | Canonicalization, digests, JWS signing and verification, identifier normalization, the assurance constraint, and the RFC 9162 Merkle tree. |
| `facilitator.py` | A reference Facilitator: the six operations of Section 12 over five paths, the Figure 2 state machine, the Section 7.4 waterfall, and RFC 9457 refusals that name the rule. |
| `agents.py` | Buyer, Seller, Verifier and Challenger clients. |
| `measure.py` | Drives three contracts to the three terminal states, exercises the refusal paths, and reports what it costs. |

```
pip install jsonschema referencing            # validate.py
pip install cryptography pytest               # everything else
python3 tools/validate.py
python3 tools/measure.py
```

`cryptography` is optional and `validate.py` does not need it, so a checkout
still validates on a machine with nothing else installed.

## What this does and does not answer

Section 15 of the draft records that no Facilitator, Buyer or Seller exchanging
messages over the Section 12 endpoints was known to the author when -01 was
posted. This is that implementation, and it is one implementation. The
falsifiable experiment of Section 1.4 is *two independent* implementations
settling contracts through every terminal state, so this is the first half of
it and an invitation for the second.

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

## Two defects this implementation found

Both are in the specification, not in the code, and both are -02 items.

**The rule that is supposed to make silence expensive makes it free.** Section 6
says "This is the rule that makes silence expensive: under the -00 the cheapest
attack was to deliver nothing verifiable and be paid anyway", and then requires
that on a missed deadline the Facilitator "slash the Bond to the extent of
`liability.restitution_basis`". The worked example sets `restitution_basis` to
`released`, and under the default `on-verification` release nothing is released
before a Verdict, so the extent is zero. Run it and the Seller signs, posts a
bond, delivers nothing, and gets the whole bond back:

```
locked escrow 180.00, bond 18.00, fund 0.50
deadline passed with no Delivery, returned escrow 180.00 to buyer
restitution basis 'released' gives 0.00 from bond
returned bond 18.00 to seller
```

**A defrauded buyer still recovers nothing from the bond.** Section 7.4 reorders
the waterfall to pay restitution before any bounty, and says of the -00 that
because the remainder went to a neutral sink "a defrauded Buyer recovered
nothing". Under `restitution_basis: released` the amount owed at rank 3 is again
zero, so the bond falls through to rank 5 and lands on the same sink:

```
rank 1: reversed unreleased escrow 180.00 to buyer
rank 3: restitution basis 'released' owed 0.00, paid 0.00 from bond
rank 5: remainder 18.00 directed to sink
```

Change one enum to `price` and the same fraud pays the buyer 18.00 out of the
bond. Same protocol, same fraud, opposite outcome for the injured party, decided
by a member whose default the document never argues for.

The fix is a -02 question, not a code change: either the worked example should
use `price`, or `restitution_basis` needs a stated default and a rule that a
Facilitator refuses a combination that makes the remedy vacuous.
