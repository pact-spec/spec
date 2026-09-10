# tools

Five programs. The first checks the committed examples; the rest are a working
implementation of the protocol.

| File | What it is |
|---|---|
| `validate.py` | The conformance validator: 66 checks over the committed examples and the Section 13.3 vectors. Needs only `jsonschema` and `referencing`. |
| `pactcore.py` | Canonicalization, digests, JWS signing and verification, identifier normalization, the assurance constraint, and the RFC 9162 Merkle tree. |
| `facilitator.py` | A reference Facilitator: the six operations of Table 1 over five paths, the Figure 2 state machine, the Section 7.4 waterfall, and RFC 9457 refusals that name the rule. |
| `agents.py` | Buyer, Seller, Verifier and Challenger clients. |
| `measure.py` | Drives four contracts through the terminal states, exercises thirteen refusal paths, checks that money balances, and reports costs. |

```
pip install jsonschema referencing            # validate.py
pip install cryptography                      # everything else
python3 tools/validate.py
python3 tools/measure.py
```

`cryptography` is optional and `validate.py` does not need it, so a checkout
still validates on a machine with nothing else installed.

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

## Questions this raises for -02

These are readings of the specification that an implementer has to resolve
before writing code, and the draft does not resolve them. They are not bugs in
this code, and none of them was discovered by running it: the arithmetic came
from an adversarial review of the text in early September, and building the
implementation confirmed it and added the second item below.

**Non-delivery can carry no bond consequence, and the disposition of the bond is
then unspecified.** Section 6 requires that on a missed deadline the Facilitator
"slash the Bond to the extent of `liability.restitution_basis`". The worked
example sets that member to `released`, and under the default `on-verification`
release nothing is released before a Verdict, so the extent is zero. Separately,
Section 7.6 requires the Bond be returned "when the contract reaches FINAL or
SETTLED" and says nothing about ABANDONED, which is the third terminal state. So
the specification neither slashes the bond nor returns it. This implementation
returns it, which is a choice it had to make and not a rule it followed:

```
locked escrow 180.00, bond 18.00, fund 0.50
deadline passed with no Delivery, returned escrow 180.00 to buyer
restitution basis 'released' gives 0.00 from bond
returned bond 18.00 to seller
```

**The `restitution_basis` default is load-bearing and undefended.** Under
`released` the amount owed to the Buyer at rank 3 of the Section 7.4 waterfall
is whatever was paid out before the Verdict, which under the default release
mode is nothing. Under `price` the Buyer is restored from the Bond up to the
cap. The document never argues for one over the other, and the worked example
picks `released` without comment. Note carefully what this does and does not
mean: in the ordinary pre-release FAIL path the Buyer is made whole anyway,
because rank 1 returns the full unreleased escrow first, so a rank 3 payment of
zero is arithmetically correct rather than a failure. The member matters in the
paths where value has already moved, which is the Figure 6 overturned PASS.

**The Challenge object carries no cost claim.** Rank 2 of the waterfall
reimburses "the successful Challenger's documented verification and submission
costs" from the Verification Fund, and the Challenge schema is closed and has no
member for those costs. A Facilitator has nothing in the object to reimburse
against.

## A correction

An earlier version of this file claimed, as a second defect, that "a defrauded
buyer still recovers nothing from the bond". That was wrong, and it was wrong in
the transcript printed directly beneath it: rank 1 returns the whole 180.00
escrow to the Buyer before rank 3 is reached, so the Buyer's loss is zero and a
restitution payment of zero is correct. It is recorded here rather than quietly
deleted because the same misreading is easy for anyone else reading the
waterfall, and because the point of publishing a specification for demolition is
lost if the corrections are not published too.
