# bonded-restitution: an example terms profile

Identifier: `tag:laxsharma79@gmail.com,2026:pact:bonded-restitution`.
Problem types: `tag:laxsharma79@gmail.com,2026:pact:bonded-restitution:problem:<name>`.

This directory is a terms profile bundle in the sense of draft-laxsharma-pact-02
Section 5.3: this file, `parameters.schema.json` and `vectors.json`. `profile_hash`
is the manifest digest of Section 5.1 over the three files, and `tools/validate.py`
recomputes it on every run. It is the profile printed as Appendix A of the draft,
and it is not normative anywhere: it exists so that the experiment in Section 1.4
can be run before any other profile is written.

It carries the settlement content of draft-laxsharma-pact-01 written as a schedule
over the events of Section 4.2, with the choices -01 left open now made. What the
figures below mean between the parties to a contract that names this profile is a
question the draft does not answer and its author is not qualified to answer. A
profile meant for use needs an owner who is.

## Parameters

`terms.parameters` validates against `parameters.schema.json`:

| Member | Type | Meaning |
|---|---|---|
| `seller_bond` | amount, required | what the Seller posts before performance |
| `verification_fund` | amount, required | what the Buyer posts to pay for checking |
| `cap` | amount, required | the most that leaves the Seller's accounts under the contract |
| `restitution_basis` | `released` or `price`, required | what the Buyer's loss is measured against |
| `remainder_to` | `buyer` or `sink`, optional | where a remaining bond goes; `sink` when absent |
| `verifier_fee` | amount, optional | paid from the fund at each Verdict; `0.00` when absent |
| `principal_on` | `verdict`, `delivered` or `window-closed`, required | the event at which the price moves to the Seller |
| `assurance` | object, required | `mode` (`certain`, `committed-sample`, `open`) and `q_min` in (0, 1] |

The -01 release modes map onto the contract's `flow` and this profile's
`principal_on`: on-verification is verdict-first with `verdict`; on-window is
delivery-first with `window-closed`; optimistic is delivery-first with `delivered`;
unsecured is no-window with `delivered`.

## Accounts

Three internal accounts, opened empty: `escrow`, `bond`, `fund`. External accounts,
unbounded as sources and sinks: `buyer`, `seller`, `verifier`, `challenger:<kid>` for
each Challenger, and `sink`. Closure requires the three internal accounts to hold
zero after the last entry; no entry ever takes from an internal account more than it
holds.

## Admission

At `accepted` the profile evaluates, exactly and in the contract's currency, with P
the price, B `seller_bond`, q `assurance.q_min`, and E equal to P when
`principal_on` is `delivered` and zero otherwise:

    B >= P * (1 - q) / q + E

Multiplied through by q this is `B*q >= P*(1-q) + E*q`, which needs no division and
no rounding. When it does not hold, or when `assurance.mode` is `open`, the profile
reports `assurance-constraint-unsatisfied`. A contract whose `seller_bond` or
`verification_fund` exceeds `cap` is reported as `parameters-inconsistent`. The
inequality is the classical deterrence bound (Polinsky and Shavell 1999; Belenkiy et
al. 2008, Theorem 1), with E the one term -01 added.

## Schedule

For each event the schedule emits the entries below in the order listed, omitting
any entry whose amount is zero. Every event of Section 4.2 not named here emits
nothing. Amounts are computed from the contract and the trace prefix; "released" is
the sum of `principal` entries emitted so far; "the balance" of an account is what
it holds at that point in the list.

- `funded`: buyer to escrow, P, `lock`; seller to bond, B, `bond`; buyer to fund,
  `verification_fund`, `fund`.
- `delivered`: if `principal_on` is `delivered`: escrow to seller, the escrow
  balance, `principal`.
- `verdict`: fund to verifier, the lesser of `verifier_fee` and the fund balance,
  `verification`; then, if the outcome is PASS, the Verdict answers no Challenge and
  `principal_on` is `verdict`: escrow to seller, the escrow balance, `principal`.
- `window-closed`: if `principal_on` is `window-closed` and the standing Verdict is
  not FAIL: escrow to seller, the escrow balance, `principal`.
- `terminal` FINAL: escrow to seller, the escrow balance, `principal`; bond to
  seller, the bond balance, `return`; fund to buyer, the fund balance,
  `fund-return`.
- `terminal` ABANDONED: escrow to buyer, the escrow balance, `reverse`; bond to
  seller, the bond balance, `return`; fund to buyer, the fund balance,
  `fund-return`. With the price reversed the Buyer's loss is zero under either
  basis, so nothing is slashed.
- `terminal` SETTLED, in five ranks, each drawing only what remains: (1) escrow to
  buyer, the escrow balance, `reverse`; (2) if `challenge_upheld`, fund to the
  Challenger whose Challenge the standing Verdict answers, the lesser of that
  Challenge's `costs` and the fund balance, `costs`; (3) bond to buyer, the lesser
  of the bond balance, `cap` and the Buyer's loss, `restitution`, the loss being
  "released" under basis `released` and P minus the rank-1 entry under basis
  `price`; (4) if `challenge_upheld`, bond to that Challenger, the bond balance,
  `bounty`; (5) bond to buyer or sink per `remainder_to`, the bond balance,
  `remainder`. Then fund to buyer, the fund balance, `fund-return`.

Ranks 2 and 4 pay one Challenger, the one whose Challenge the standing Verdict
answers. A Challenge that was lapsed, rejected or superseded receives nothing. Rank
4 gives the whole remaining bond because -01 forbade capping it at a fraction chosen
for tidiness and fixed no figure. `cap` bounds ranks 3 to 5 together.

## Vectors

`vectors.json` is an array of `{name, contract, trace, transfers}` objects, each a
complete trace with the list the schedule produces for it, generated by
`tools/profile.py` and checked against the lists printed in Appendix A.6 of the
draft by `tools/validate.py`. A Facilitator reproduces every vector before listing
this profile in its capability document (Section 12.1).
