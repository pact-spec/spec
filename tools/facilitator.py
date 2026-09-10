"""A reference Facilitator: the six operations of Section 12 over five paths.

This is the first implementation that speaks the protocol. Section 15 of the
-01 records that no Facilitator, Buyer or Seller exchanging messages over
these endpoints was known to the author when the draft was posted; this file
and agents.py are the answer to that, and the count of independent
implementations is still one, which is not the falsifiable experiment of
Section 1.4. Two independent implementations settling each other's contracts
is that experiment. This is the first half of it.

What it enforces, with the section each rule comes from, is listed in RULES
below. Every refusal is an RFC 9457 problem document naming the rule that was
violated, because a Facilitator that refuses without saying why cannot be
debugged against by a second implementer.

Storage is in memory. Money is an integer number of cents in three pools. No
payment rail is touched: Section 1.2 puts the rail out of scope, and a
settlement binding names one. What is real here is the object flow, the state
machine, the signature verification and the arithmetic.

Run it:

    python3 tools/facilitator.py --port 8402

Then drive it with agents.py, or measure it with measure.py.
"""

from __future__ import annotations

import argparse
import json
import re
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pactcore as pc

RULES = """
Section 5.3   liability is REQUIRED, and a contract without it is not a PACT contract
Section 7.1   cumulative release before a recorded Verdict MUST NOT exceed the Bond
Section 7.2   the assurance constraint is evaluated BEFORE funds lock, and a contract
              that fails it is refused
Section 7.4   the five-rank remedy waterfall, restitution before bounty or remainder
Section 7.5   the Bond is returned when the contract reaches FINAL or SETTLED
Section 6     deadline expiry with no Delivery moves the contract to ABANDONED
Section 9.1   verifier independence is DERIVED by comparing normalized party
              identifiers, never read from a field
Section 3     a Facilitator MUST NOT act as Verifier for a contract it settles
Section 11    an attestation is issued for every terminal contract, is signed by the
              Facilitator, and does not require the signature of the party whose loss
              it records
Section 12.2  a POST whose body canonicalizes to a known hash returns 200 and the
              existing resource; the same id with a different hash returns 409
Section 12.3  every failure is an RFC 9457 problem document naming the rule
Section 12.4  a Verdict signer MUST satisfy Section 9.1, and a Verdict for a contract
              with no recorded Delivery is rejected
Section 13.1  JWS with a detached payload, an algorithm allowlist, and kid inside the
              protected header
"""

# Section 18.5: "This document creates no registry for its problem types." A
# URL that 404s is worse than an opaque identifier, so these are document-local
# URNs until a registry exists. RFC 9457 permits any URI and does not require
# it to dereference.
PROBLEM_BASE = "urn:pact:problem:"

# Section 18.5 reserves these names but does not create a registry; the draft
# asks IANA to create one on publication. Until then these are the document's
# own strings and are stable within this implementation.
PROBLEMS = {
    "assurance-constraint-unsatisfied": (422, "Section 7.2"),
    "liability-missing": (422, "Section 5.3"),
    "parties-not-distinct": (422, "Section 9.1"),
    "signature-invalid": (401, "Section 13.1"),
    "signature-missing": (401, "Section 13.1"),
    "verifier-not-independent": (422, "Section 9.1"),
    "facilitator-cannot-verify": (422, "Section 3"),
    "no-recorded-delivery": (409, "Section 12.4"),
    "wrong-state": (409, "Section 12"),
    "object-conflict": (409, "Section 12.2"),
    "challenge-window-closed": (409, "Section 7.4"),
    "evidence-nonconformant": (422, "Section 6"),
    "release-exceeds-bond": (422, "Section 7.1"),
    "unknown-contract": (404, "Section 12"),
}

TERMINAL = ("FINAL", "SETTLED", "ABANDONED")


class Refuse(Exception):
    def __init__(self, kind: str, detail: str, **extra: Any) -> None:
        self.kind = kind
        self.detail = detail
        self.extra = extra
        super().__init__(detail)


@dataclass
class Contract:
    vtc: dict
    state: str = "PROPOSED"
    pools: pc.Pools = field(default_factory=pc.Pools)
    delivery: dict | None = None
    verdict: dict | None = None
    challenge: dict | None = None
    attestation: dict | None = None
    window_opened_at: float | None = None
    created_at: float = field(default_factory=time.time)

    @property
    def id(self) -> str:
        return self.vtc["id"]

    @property
    def buyer(self) -> str:
        return self.vtc["parties"]["buyer"]

    @property
    def seller(self) -> str:
        return self.vtc["parties"]["seller"]

    def digest(self) -> str:
        return pc.digest_over(pc.hashable(self.vtc))


class Facilitator:
    """The settlement service. Thread safe under the threading HTTP server."""

    def __init__(self, identity: str, key: pc.Key, resolver: pc.KeyResolver,
                 now: Any = time.time) -> None:
        self.identity = identity
        self.key = key
        self.resolver = resolver
        self.now = now
        self.contracts: dict[str, Contract] = {}
        self.seen: dict[str, tuple[str, dict]] = {}  # object digest -> (kind, body)
        self.lock = threading.RLock()
        self.message_count = 0

    # -- Section 12.2 ------------------------------------------------------
    def _idempotent(self, kind: str, obj: dict) -> dict | None:
        digest = pc.digest_over(pc.hashable(obj))
        hit = self.seen.get(digest)
        if hit is not None:
            return hit[1]
        return None

    def _remember(self, kind: str, obj: dict, body: dict) -> None:
        self.seen[pc.digest_over(pc.hashable(obj))] = (kind, body)

    # -- Propose, Section 12.1 --------------------------------------------
    def propose(self, vtc: dict) -> tuple[int, dict]:
        with self.lock:
            existing = self._idempotent("contract", vtc)
            if existing is not None:
                return 200, existing

            vid = vtc.get("id")
            if vid in self.contracts:
                raise Refuse("object-conflict",
                             f"contract {vid} exists with a different hash")

            liability = vtc.get("liability")
            if not liability:
                raise Refuse("liability-missing",
                             "a contract that does not allocate liability is not "
                             "a PACT contract")

            buyer = vtc["parties"]["buyer"]
            seller = vtc["parties"]["seller"]
            if pc.same_party(buyer, seller):
                raise Refuse("parties-not-distinct",
                             "buyer and seller are the same party after the "
                             "normalization of Section 9.1",
                             buyer=buyer, seller=seller)

            ok, why = pc.verify_object(vtc, self.resolver,
                                       "application/pact-contract+json",
                                       [buyer, seller])
            if not ok:
                raise Refuse("signature-invalid", why)

            price = float(vtc["price"]["amount"])
            bond = float(liability["seller_bond"])
            fund = float(liability["verification_fund"])
            q_min = float(vtc["assurance"]["q_min"])

            # Section 7.2: evaluated BEFORE funds lock. This is the one check
            # that makes a bond size a claim a Facilitator can refuse rather
            # than a number a Seller asserts.
            if not pc.assurance_holds(price, bond, q_min, released=0.0):
                need = pc.required_bond(price, q_min, 0.0)
                raise Refuse(
                    "assurance-constraint-unsatisfied",
                    f"Bond {bond:.2f} is below the minimum {need:.2f} required "
                    f"for q_min {q_min:.2f} at price {price:.2f} with E 0.00.",
                    required_bond=f"{need:.2f}", declared_bond=f"{bond:.2f}",
                    q_min=q_min, price=f"{price:.2f}")

            c = Contract(vtc=vtc)
            c.pools.escrow = pc.cents(price)
            c.pools.bond = pc.cents(bond)
            c.pools.bond_initial = pc.cents(bond)
            c.pools.fund = pc.cents(fund)
            c.pools.note(f"locked escrow {price:.2f}, bond {bond:.2f}, fund {fund:.2f}")
            c.state = "FUNDED"
            self.contracts[c.id] = c
            body = self._contract_body(c)
            self._remember("contract", vtc, body)
            return 201, body

    def _contract_body(self, c: Contract) -> dict:
        out = dict(c.vtc)
        out["state"] = c.state  # Section 12: added here, never signed or hashed
        return out

    # -- Retrieve ----------------------------------------------------------
    def get_contract(self, vid: str) -> tuple[int, dict]:
        with self.lock:
            c = self.contracts.get(vid)
            if c is None:
                raise Refuse("unknown-contract", f"no contract {vid}")
            self._expire_if_due(c)
            return 200, self._contract_body(c)

    # -- Section 6: deadline expiry ---------------------------------------
    def _expire_if_due(self, c: Contract) -> None:
        if c.state != "FUNDED":
            return
        deadline = c.vtc.get("task", {}).get("deadline")
        if not deadline:
            return
        due = time.mktime(time.strptime(deadline, "%Y-%m-%dT%H:%M:%SZ"))
        if self.now() < due:
            return
        # Nothing was delivered and the deadline passed. The escrow goes back
        # and the Bond is slashed to the extent of restitution_basis. Under
        # basis "released" with nothing released that is zero, which is the
        # honest reading of the current example and a live -02 question.
        c.pools.paid_to_buyer += c.pools.escrow
        c.pools.note(f"deadline {deadline} passed with no Delivery, "
                     f"returned escrow {pc.money(c.pools.escrow)} to buyer")
        c.pools.escrow = 0
        basis = c.vtc["liability"]["restitution_basis"]
        owed = c.pools.released if basis == "released" else pc.cents(c.vtc["price"]["amount"])
        slashed = min(owed, c.pools.bond)
        c.pools.bond -= slashed
        c.pools.paid_to_buyer += slashed
        c.pools.restituted += slashed
        c.pools.note(f"restitution basis {basis!r} gives {pc.money(slashed)} from bond")
        self._return_bond(c)
        c.state = "ABANDONED"
        self._attest(c, outcome="abandoned")

    def _return_bond(self, c: Contract) -> None:
        # Section 7.5: the Bond is returned on finality. The -00 had no rule
        # returning it at all.
        if c.pools.bond:
            c.pools.note(f"returned bond {pc.money(c.pools.bond)} to seller")
            c.pools.bond_returned += c.pools.bond
            c.pools.bond = 0
        if c.pools.fund:
            c.pools.note(f"returned verification fund {pc.money(c.pools.fund)}")
            c.pools.fund_returned += c.pools.fund
            c.pools.fund = 0

    # -- Submit Delivery, Section 12 --------------------------------------
    def submit_delivery(self, dlv: dict) -> tuple[int, dict]:
        with self.lock:
            existing = self._idempotent("delivery", dlv)
            if existing is not None:
                return 200, existing

            c = self._contract_for(dlv)
            self._expire_if_due(c)
            if c.state != "FUNDED":
                raise Refuse("wrong-state",
                             f"contract {c.id} is {c.state}, a Delivery is only "
                             f"accepted in FUNDED")

            # A Delivery not signed by the contract's Seller is rejected.
            ok, why = pc.verify_object(dlv, self.resolver,
                                       "application/pact-delivery+json", [c.seller])
            if not ok:
                raise Refuse("signature-invalid", why)

            # Section 6: the Delivery is the thing being judged, and evidence
            # must conform to the profile the contract declares. Without this
            # the -00's cheapest attack, deliver nothing verifiable, is open
            # again. validate.py's negative vector V-14 covers the same rule.
            # Draft line 832: "A Facilitator MUST reject a Delivery whose
            # evidence is absent or does not conform to the profile named in the
            # VTC, and MUST apply Section 7.4 as though a FAIL Verdict had been
            # recorded." Both halves are normative. Refusing without applying
            # the waterfall would leave the contract sitting in FUNDED with the
            # Buyer's escrow locked, which is the outcome the rule exists to
            # prevent. This is the rule the draft calls the one that makes
            # silence expensive.
            evidence = dlv.get("evidence")
            declared = c.vtc["verification"]["profile"]
            reason = None
            if not isinstance(evidence, dict):
                reason = "the Delivery carries no evidence member"
            elif evidence.get("profile") != declared:
                reason = (f"evidence profile {evidence.get('profile')!r} does not "
                          f"match the contract's declared profile {declared!r}")
            elif evidence.get("instrument_hash") != \
                    c.vtc["verification"]["criteria_hash"]:
                reason = ("the evidence does not commit to the instrument the "
                          "contract committed to")
            if reason is not None:
                c.pools.note(f"nonconformant Delivery: {reason}; applying "
                             f"Section 7.4 as though a FAIL Verdict were recorded")
                self._apply_waterfall(c, challenger=c.buyer, costs=0)
                raise Refuse("evidence-nonconformant", reason,
                             state=c.state,
                             remedy="Section 7.4 applied as though FAIL")

            c.delivery = dlv
            c.state = "DELIVERED"
            body = dict(dlv)
            body["state"] = c.state
            self._remember("delivery", dlv, body)
            return 202, body

    def _contract_for(self, obj: dict) -> Contract:
        """Resolve the contract an object refers to, and check its commitment.

        The objects commit differently and the schemas say so. A Delivery
        carries vtc_hash and commits to the contract. A Verdict and a Challenge
        carry delivery_hash and commit to the Delivery being judged, which is
        the right thing to bind: a Verdict is a statement about a Delivery.
        """
        c = self.contracts.get(obj.get("vtc_id"))
        if c is None:
            raise Refuse("unknown-contract", f"no contract {obj.get('vtc_id')}")

        if "vtc_hash" in obj:
            if obj["vtc_hash"] != c.digest():
                raise Refuse("object-conflict",
                             "vtc_hash does not commit to this contract",
                             expected=c.digest(), received=obj["vtc_hash"])
        elif "delivery_hash" in obj:
            if c.delivery is None:
                raise Refuse("no-recorded-delivery",
                             f"contract {c.id} has no recorded Delivery to judge")
            recorded = pc.digest_over(pc.hashable(c.delivery))
            if obj["delivery_hash"] != recorded:
                raise Refuse("object-conflict",
                             "delivery_hash does not commit to the recorded Delivery",
                             expected=recorded, received=obj["delivery_hash"])
        return c

    # -- Record Verdict, Section 12.4 -------------------------------------
    def record_verdict(self, verdict: dict) -> tuple[int, dict]:
        with self.lock:
            existing = self._idempotent("verdict", verdict)
            if existing is not None:
                return 200, existing

            c = self._contract_for(verdict)
            if c.state not in ("DELIVERED", "DISPUTED"):
                raise Refuse("wrong-state",
                             f"contract {c.id} is {c.state}; a Verdict is accepted "
                             f"on DELIVERED, or on DISPUTED to resolve a challenge")

            kids = pc.signer_kids(verdict)
            if not kids:
                raise Refuse("signature-missing", "the Verdict carries no signature")

            # Draft line 1852: "The Verifier is the party identified by the kid
            # of the Verdict's signature. Where the contract names
            # parties.verifier, the Verdict MUST be signed by that party;
            # otherwise the Facilitator evaluates Section 9.1 against the
            # signer." An earlier version checked only that the signer was not
            # the Seller or the Facilitator, so any resolvable key could pass or
            # fail any contract.
            named = c.vtc["parties"].get("verifier")
            if named:
                if not any(pc.kid_covers(k, named) for k in kids):
                    raise Refuse("verifier-not-independent",
                                 "the contract names a verifier and the Verdict "
                                 "is not signed by that party",
                                 signer=kids[0], required_verifier=named)
            for kid in kids:
                if pc.kid_covers(kid, c.seller):
                    raise Refuse("verifier-not-independent",
                                 "the Verdict is signed by the contract's Seller",
                                 signer=kid, seller=c.seller)
                if pc.kid_covers(kid, c.buyer):
                    raise Refuse("verifier-not-independent",
                                 "the Verdict is signed by the contract's Buyer",
                                 signer=kid, buyer=c.buyer)
                if pc.kid_covers(kid, self.identity):
                    raise Refuse("facilitator-cannot-verify",
                                 "a Facilitator MUST NOT act as Verifier for a "
                                 "contract it settles",
                                 signer=kid, facilitator=self.identity)

            ok, why = pc.verify_object(
                verdict, self.resolver, "application/pact-verdict+json",
                [named] if named else [])
            if not ok:
                raise Refuse("signature-invalid", why)

            c.verdict = verdict
            outcome = verdict["outcome"]
            if outcome == "PASS":
                mode = c.vtc["release"]
                if mode == "on-verification":
                    c.state = "RELEASING"
                    self._settle_pass(c)
                else:
                    c.state = "RELEASING"
                    c.window_opened_at = self.now()
            else:
                c.state = "DISPUTED"
                self._apply_waterfall(c, challenger=c.buyer, costs=0)
            body = dict(verdict)
            body["state"] = c.state
            self._remember("verdict", verdict, body)
            return 201, body

    def _settle_pass(self, c: Contract) -> None:
        c.pools.paid_to_seller += c.pools.escrow
        c.pools.note(f"released escrow {pc.money(c.pools.escrow)} to seller on PASS")
        c.pools.escrow = 0
        self._return_bond(c)
        c.state = "FINAL"
        self._attest(c, outcome="performed")

    # -- Open challenge, Section 7.4 --------------------------------------
    def open_challenge(self, ch: dict) -> tuple[int, dict]:
        with self.lock:
            existing = self._idempotent("challenge", ch)
            if existing is not None:
                return 200, existing

            c = self._contract_for(ch)
            if c.state not in ("RELEASING", "DELIVERED"):
                raise Refuse("wrong-state",
                             f"contract {c.id} is {c.state}, no challenge window "
                             f"is open")
            window = int(c.vtc.get("challenge", {}).get("window_seconds", 0))
            if c.window_opened_at is not None and \
                    self.now() - c.window_opened_at > window:
                raise Refuse("challenge-window-closed",
                             f"the {window}s challenge window has closed")

            ok, why = pc.verify_object(ch, self.resolver,
                                       "application/pact-challenge+json", [])
            if not ok:
                raise Refuse("signature-invalid", why)

            # A Challenge is a fraud proof submitted for evaluation, not a
            # finding. Section 7.5: "A Challenge that is accepted is evaluated
            # by a party satisfying Section 9.1, whose finding is a Verdict; the
            # Challenger's own assertion is not." An earlier version of this
            # file applied the waterfall directly here, which let any party with
            # a resolvable key destroy a Seller's bond with no Verdict ever
            # recorded. Accepting a Challenge moves the contract to DISPUTED and
            # nothing else.
            c.challenge = ch
            c.state = "DISPUTED"
            c.pools.note(f"challenge accepted from "
                         f"{pc.signer_kids(ch)[0] if pc.signer_kids(ch) else 'unknown'}, "
                         f"awaiting a Verdict from an independent evaluator")
            body = dict(ch)
            body["state"] = c.state
            self._remember("challenge", ch, body)
            return 202, body

    # -- Section 7.4, the five ranks in order ------------------------------
    def _apply_waterfall(self, c: Contract, challenger: str, costs: int) -> None:
        p = c.pools

        # 1. Reverse any unreleased escrow to the Buyer.
        if p.escrow:
            p.paid_to_buyer += p.escrow
            p.note(f"rank 1: reversed unreleased escrow {pc.money(p.escrow)} to buyer")
            p.escrow = 0

        # 2. Reimburse the Challenger's documented costs FROM THE VERIFICATION
        #    FUND. Paying this from the Bond is what made the -00 rule
        #    unsatisfiable, since proving fraud costs about what the work cost.
        if costs:
            paid = min(costs, p.fund)
            p.fund -= paid
            p.paid_to_challenger += paid
            p.note(f"rank 2: reimbursed challenger {pc.money(paid)} from the "
                   f"verification fund")
            if paid < costs:
                p.note(f"rank 2: verification fund short by "
                       f"{pc.money(costs - paid)}, which is a sizing failure "
                       f"and not a protocol one")

        # 3. Restore the Buyer from the Bond, up to restitution_basis.
        basis = c.vtc["liability"]["restitution_basis"]
        cap = pc.cents(c.vtc["liability"]["cap"])
        owed = p.released if basis == "released" else pc.cents(c.vtc["price"]["amount"])
        owed = min(owed, cap)
        restitution = min(owed, p.bond)
        if restitution:
            p.bond -= restitution
            p.paid_to_buyer += restitution
            p.restituted += restitution
        p.note(f"rank 3: restitution basis {basis!r} owed {pc.money(owed)}, "
               f"paid {pc.money(restitution)} from bond")

        # 4. Pay the Challenger bounty from the remaining Bond.
        bounty = min(p.bond, owed) if p.bond else 0
        if bounty:
            p.bond -= bounty
            p.paid_to_challenger += bounty
            p.note(f"rank 4: bounty {pc.money(bounty)} from the remaining bond")

        # 5. Direct any remainder per liability.remainder_to.
        remainder_to = c.vtc["liability"].get("remainder_to", "sink")
        if p.bond:
            if remainder_to == "buyer":
                p.paid_to_buyer += p.bond
            else:
                p.remainder += p.bond
            p.note(f"rank 5: remainder {pc.money(p.bond)} directed to {remainder_to}")
            p.bond = 0

        if p.fund:
            p.note(f"returned unspent verification fund {pc.money(p.fund)}")
            p.fund_returned += p.fund
            p.fund = 0

        c.state = "SETTLED"
        self._attest(c, outcome="slashed")

    # -- Section 11, the Work Attestation ---------------------------------
    def _attest(self, c: Contract, outcome: str) -> None:
        """Issued for every terminal contract, signed by the Facilitator alone.

        Under the -00 a slashed Seller simply declined to co-sign its own
        conviction, which made the reputation layer structurally incapable of
        recording a negative outcome. The Seller does not consent to this
        record and its consent is not required.
        """
        att = {
            "pact": "0.1",
            "type": "WorkAttestation",
            "vtc_id": c.id,
            "vtc_hash": c.digest(),
            "parties": {"buyer": c.buyer, "seller": c.seller,
                        "facilitator": self.identity},
            "subject": c.seller,
            "role": "seller",
            "outcome": outcome,
            "amounts": {
                "settled": pc.money(c.pools.paid_to_seller),
                # Restitution is what the Buyer recovered FROM THE BOND. Escrow
                # coming back is the Buyer's own money and is not restitution;
                # conflating the two is how the -00 was able to look solvent.
                "restituted": pc.money(c.pools.restituted),
                "slashed": pc.money(c.pools.bond_initial - c.pools.bond_returned
                                     - c.pools.bond),
                "currency": c.vtc["price"]["currency"],
            },
            "opened_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                       time.gmtime(c.created_at)),
            "settled_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                        time.gmtime(self.now())),
        }
        if c.delivery is not None:
            att["work_hash"] = c.delivery["work_hash"]
        att["signatures"] = [pc.sign(att, self.key,
                                     "application/pact-attestation+json")]
        c.attestation = att

    def get_attestation(self, vid: str) -> tuple[int, dict]:
        with self.lock:
            c = self.contracts.get(vid)
            if c is None:
                raise Refuse("unknown-contract", f"no contract {vid}")
            self._expire_if_due(c)
            if c.attestation is None:
                raise Refuse("wrong-state",
                             f"contract {vid} is {c.state} and not terminal, so "
                             f"no attestation exists yet")
            return 200, c.attestation

    def capability_document(self) -> dict:
        return {
            "pact": "0.1",
            "facilitator": self.identity,
            "endpoints": {
                "contract": "/pact/v1/contracts",
                "delivery": "/pact/v1/deliveries",
                "verdict": "/pact/v1/verdicts",
                "challenge": "/pact/v1/challenges",
                "attestation": "/pact/v1/attestations",
            },
            "release_modes": ["on-verification"],
            "assurance_modes": ["certain"],
            "profiles": ["acceptance"],
            "max_contract_value": "50000.00",
            "currencies": ["USDC"],
            "challenge_deposit": "0.00",
        }


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

ROUTES = {
    "contracts": "propose",
    "deliveries": "submit_delivery",
    "verdicts": "record_verdict",
    "challenges": "open_challenge",
}

MEDIA = {
    "propose": "application/pact-contract+json",
    "submit_delivery": "application/pact-delivery+json",
    "record_verdict": "application/pact-verdict+json",
    "open_challenge": "application/pact-challenge+json",
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "pact-reference-facilitator/0.1"

    @property
    def fac(self) -> Facilitator:
        return self.server.facilitator  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        if getattr(self.server, "verbose", False):  # type: ignore[attr-defined]
            super().log_message(fmt, *args)

    def _send(self, status: int, body: dict, content_type: str) -> None:
        raw = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
        self.fac.message_count += 1

    def _problem(self, exc: Refuse) -> None:
        status, section = PROBLEMS.get(exc.kind, (400, "Section 12.3"))
        body = {
            "type": PROBLEM_BASE + exc.kind,
            "title": exc.kind.replace("-", " "),
            "status": status,
            "detail": exc.detail,
            # Section 12.3: errors MUST name the rule that was violated.
            "section": section,
        }
        body.update(exc.extra)
        self._send(status, body, "application/problem+json")

    def do_GET(self) -> None:
        try:
            if self.path == "/.well-known/pact-facilitator":
                self._send(200, self.fac.capability_document(),
                           "application/pact-facilitator+json")
                return
            m = re.match(r"^/pact/v1/(contracts|attestations)/([^/]+)$", self.path)
            if not m:
                raise Refuse("unknown-contract", f"no route for {self.path}")
            kind, vid = m.groups()
            if kind == "contracts":
                status, body = self.fac.get_contract(vid)
                self._send(status, body, "application/pact-contract+json")
            else:
                status, body = self.fac.get_attestation(vid)
                self._send(status, body, "application/pact-attestation+json")
        except Refuse as exc:
            self._problem(exc)
        except Exception as exc:  # pragma: no cover
            self._problem(Refuse("wrong-state", f"{type(exc).__name__}: {exc}"))

    def do_POST(self) -> None:
        try:
            m = re.match(r"^/pact/v1/(contracts|deliveries|verdicts|challenges)$",
                         self.path)
            if not m:
                raise Refuse("unknown-contract", f"no route for {self.path}")
            op = ROUTES[m.group(1)]
            length = int(self.headers.get("Content-Length", 0))
            obj = json.loads(self.rfile.read(length) or b"{}")
            status, body = getattr(self.fac, op)(obj)
            self._send(status, body, MEDIA[op])
        except Refuse as exc:
            self._problem(exc)
        except Exception as exc:  # pragma: no cover
            self._problem(Refuse("wrong-state", f"{type(exc).__name__}: {exc}"))


def serve(facilitator: Facilitator, port: int = 8402,
          verbose: bool = False) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    httpd.facilitator = facilitator  # type: ignore[attr-defined]
    httpd.verbose = verbose  # type: ignore[attr-defined]
    return httpd


def build(identity: str = "did:web:settle.example") -> tuple[Facilitator, pc.KeyResolver]:
    resolver = pc.KeyResolver()
    key = resolver.register(pc.Key.generate(identity + "#key-1"))
    return Facilitator(identity, key, resolver), resolver


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8402)
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--rules", action="store_true",
                    help="print the rules this implementation enforces and exit")
    args = ap.parse_args()
    if args.rules:
        print(RULES.strip())
        return
    fac, _ = build()
    httpd = serve(fac, args.port, args.verbose)
    print(f"reference Facilitator {fac.identity} on http://127.0.0.1:{args.port}")
    print(f"capability document at "
          f"http://127.0.0.1:{args.port}/.well-known/pact-facilitator")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
