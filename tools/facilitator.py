"""A reference Facilitator: the six operations of Section 12 over five paths.

This is the first implementation that speaks the protocol. Section 15 of the
-01 records that no Facilitator, Buyer or Seller exchanging messages over
these endpoints was known to the author when the draft was posted; this file
and agents.py are the answer to that, and the count of independent
implementations is still one, which is not the falsifiable experiment of
Section 1.4. Two independent implementations settling each other's contracts
is that experiment. This is the first half of it.

What it enforces, with the section each rule comes from, is listed in RULES.
Where the draft is silent an implementer has to choose; every such choice is
listed in CHOICES and repeated in tools/README.md, because a choice presented
as a rule is how a second implementer ends up disagreeing with the first.

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
import pathlib
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pactcore as pc

ROOT = pathlib.Path(__file__).resolve().parent.parent

RULES = """
Section 5     a VTC is valid only if buyer and seller each signed it once; nobody else signs it
Section 5.3   liability is REQUIRED, and a contract without it is not a PACT contract
Section 6     evidence absent or nonconformant: refuse the Delivery AND apply 7.4 as though FAIL;
              input_hash REQUIRED where the tier re-executes; deadline with no Delivery: ABANDONED
Section 7.1   cumulative release before a recorded Verdict never exceeds the Bond (on-verification
              releases nothing before a Verdict, so the cap is satisfied by construction)
Section 7.2   the assurance constraint is evaluated exactly, BEFORE funds lock; failure is refused
Section 7.3   release modes this Facilitator does not advertise are refused at propose
Section 7.4   the five-rank remedy waterfall, restitution before bounty or remainder; a bounty is
              paid only to a Challenger that exists; nothing above liability.cap leaves the Seller
Section 7.5   a Challenge is a fraud proof submitted for evaluation, accepted only inside the
              window, only with a proof conformant to the profile, and it settles nothing itself;
              a Verdict on a Challenge supersedes the earlier one and both are kept
Section 7.6   the Bond is returned when the contract reaches FINAL or SETTLED, less what 7.4 took
Section 8     the capability document is signed and validates against facilitator.schema.json
Section 9.1   verifier independence is DERIVED by comparing normalized party identifiers, at
              propose for a named verifier and at Verdict for the signer; never read from a field
Section 3     a Facilitator MUST NOT act as Verifier for a contract it settles
Section 10.1  a contract carrying liability.parent is refused: subcontracts are NOT implemented
Section 11    an attestation is issued for every terminal contract, signed by the Facilitator,
              never requiring the signature of the party whose loss it records
Section 12.1  every posted object validates against its published schema and the 13.2 checks
Section 12.2  a POST whose body canonicalizes to a known digest returns 200 and the CURRENT
              resource; the same id with a different digest returns 409
Section 12.3  every failure is an RFC 9457 problem document naming the rule
Section 12.4  a Verdict signer MUST satisfy 9.1 (or be the named verifier); no Verdict without
              a recorded Delivery; a Verdict commits to the contract's instrument and profile
Section 13.1  JWS with a detached payload over the TRANSMITTED protected header, an algorithm
              allowlist, kid inside the protected header, typ compared to the media type
Section 16.7  a contract naming another Facilitator, or a settlement, network or asset this one
              does not advertise, is refused
Section 16.11 the public key resolved for every accepted signature is recorded with the object
"""

CHOICES = """
Where the -01 text is silent or inconsistent this implementation chose, and says so:
C1  ABANDONED: the Bond is slashed to the extent of restitution_basis (zero under `released`
    with nothing released) and the rest is RETURNED. Section 7.6 returns the Bond only on
    FINAL or SETTLED and says nothing about ABANDONED.
C2  Rank 3 restores the Buyer's LOSS up to the basis, net of what rank 1 already returned.
    Read literally, basis `price` would pay the Bond on top of a reversed escrow.
C3  Rank 4 pays the whole remaining Bond as the bounty, split equally among the successful
    Challengers. The draft bounds the bounty and does not fix it; with K discoverers the
    non-exclusive full bounty is not fundable from one Bond.
C4  Rank 2 pays 0.00: the Challenge object has no member for documented costs.
C5  A Challenge that receives no Verdict within max_dispute_seconds lapses and the contract
    returns to RELEASING; the window it interrupted is not extended.
C6  PROPOSED is never observable: with no rail the pools are debited in memory the moment a
    co-signed contract is accepted, so the 201 reports FUNDED.
C7  Amounts are settled in whole cents; a contract with more decimal places is refused.
C8  Not implemented: subcontracts (Section 10), release modes other than on-verification,
    challenge deposits, committed-sample assurance, network key resolution, any rail.
"""

# Section 18.5: identifiers are appended to this prefix, which the draft owns.
PROBLEM_BASE = "https://pact-spec.github.io/problem/"

# Table 9 entries first, with the status and section the draft assigns; then the
# document-local types this implementation needs, each naming the section whose
# rule it reports. Section 18.5 permits a document-local namespace.
PROBLEMS = {
    "assurance-constraint-unsatisfied": (422, "Section 7.2"),
    "evidence-nonconformant": (422, "Section 6"),
    "parent-unresolvable": (422, "Section 10.1"),
    "finality-ordering-violation": (422, "Section 10.3"),
    "parties-not-distinct": (422, "Section 13.2"),
    "algorithm-not-permitted": (400, "Section 13.1"),
    "verifier-not-independent": (422, "Section 9.1"),
    "release-exceeds-bond": (409, "Section 7.1"),
    # document-local
    "schema-invalid": (422, "Section 13.2"),
    "liability-missing": (422, "Section 5.3"),
    "signature-invalid": (401, "Section 13.1"),
    "signature-missing": (401, "Section 13.1"),
    "unexpected-signer": (422, "Section 5"),
    "facilitator-cannot-verify": (422, "Section 3"),
    "facilitator-mismatch": (422, "Section 16.7"),
    "settlement-unsupported": (422, "Section 8"),
    "release-mode-unsupported": (422, "Section 7.3"),
    "assurance-unsupported": (422, "Section 7.2"),
    "deadline-invalid": (422, "Section 13.2"),
    "amount-invalid": (422, "Section 13.2"),
    "no-recorded-delivery": (409, "Section 12.4"),
    "verdict-nonconformant": (422, "Section 12.4"),
    "proof-nonconformant": (422, "Section 7.5"),
    "challenge-window-closed": (409, "Section 7.5"),
    "wrong-state": (409, "Section 12"),
    "object-conflict": (409, "Section 12.2"),
    "unknown-contract": (404, "Section 12"),
    "payload-too-large": (413, "Section 12"),
    "internal-error": (500, "Section 12"),
}

TERMINAL = ("FINAL", "SETTLED", "ABANDONED")

MEDIA_CONTRACT = "application/pact-contract+json"
MEDIA_DELIVERY = "application/pact-delivery+json"
MEDIA_VERDICT = "application/pact-verdict+json"
MEDIA_CHALLENGE = "application/pact-challenge+json"
MEDIA_ATTESTATION = "application/pact-attestation+json"
MEDIA_FACILITATOR = "application/pact-facilitator+json"

MAX_BODY = 1 << 20  # one MiB; a contract is under two KB


class Refuse(Exception):
    def __init__(self, kind: str, detail: str, **extra: Any) -> None:
        self.kind = kind
        self.detail = detail
        self.extra = extra
        super().__init__(detail)


# --------------------------------------------------------------------------
# Schemas. The published ones, loaded once. The Facilitator refuses to start
# without jsonschema because Section 12.1 makes schema conformance a MUST at
# Propose and a Facilitator that skips it is not one.
# --------------------------------------------------------------------------

class Schemas:
    def __init__(self) -> None:
        try:
            from jsonschema import Draft202012Validator
            from referencing import Registry, Resource
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "the reference Facilitator needs `jsonschema` and `referencing` "
                "to validate posted objects; pip install them") from exc
        docs = {p.name: json.loads(p.read_text())
                for p in (ROOT / "schemas").glob("*.schema.json")}
        registry = Registry().with_resources(
            [(name, Resource.from_contents(s)) for name, s in docs.items()])
        self._v = {name: Draft202012Validator(s, registry=registry)
                   for name, s in docs.items()}

    def check(self, obj: Any, name: str) -> None:
        errors = sorted(self._v[name].iter_errors(obj), key=lambda e: list(e.path))
        if errors:
            e = errors[0]
            where = "/".join(str(x) for x in e.path) or "(root)"
            raise Refuse("schema-invalid",
                         f"does not validate against {name} at {where}: {e.message}",
                         schema=name, path=where)


# --------------------------------------------------------------------------

def parse_rfc3339(s: str) -> float:
    """RFC 3339 to a POSIX timestamp, UTC. Accepts Z, an offset, fractions.

    An earlier version used time.mktime(strptime(...)), which interprets the
    string in the host's local zone and accepts one fixed format, so ABANDONED
    fired hours early or late depending on where the Facilitator ran.
    """
    try:
        if s.endswith("Z") or s.endswith("z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
    except (ValueError, TypeError) as exc:
        raise Refuse("deadline-invalid", f"task.deadline {s!r} is not RFC 3339") from exc
    if dt.tzinfo is None:
        raise Refuse("deadline-invalid", f"task.deadline {s!r} carries no zone")
    return dt.astimezone(timezone.utc).timestamp()


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def money_cents(label: str, amount: Any) -> int:
    try:
        return pc.cents(amount)
    except (ValueError, InvalidOperation, TypeError) as exc:
        raise Refuse("amount-invalid",
                     f"{label} {amount!r}: this Facilitator settles in whole cents "
                     f"and refuses amounts it cannot represent") from exc


@dataclass
class Contract:
    vtc: dict
    state: str = "PROPOSED"
    pools: pc.Pools = field(default_factory=pc.Pools)
    delivery: dict | None = None
    verdicts: list[dict] = field(default_factory=list)
    challenges: list[dict] = field(default_factory=list)
    attestation: dict | None = None
    window_opened_at: float | None = None
    disputed_at: float | None = None
    created_at: float = 0.0
    deadline: float = 0.0
    keys: dict[str, str] = field(default_factory=dict)  # Section 16.11 record

    @property
    def id(self) -> str:
        return self.vtc["id"]

    @property
    def buyer(self) -> str:
        return self.vtc["parties"]["buyer"]

    @property
    def seller(self) -> str:
        return self.vtc["parties"]["seller"]

    @property
    def verdict(self) -> dict | None:
        return self.verdicts[-1] if self.verdicts else None

    @property
    def challenge(self) -> dict | None:
        return self.challenges[-1] if self.challenges else None

    @property
    def window_seconds(self) -> int:
        return int(self.vtc["challenge"]["window_seconds"])

    @property
    def max_dispute_seconds(self) -> int:
        return int(self.vtc["challenge"].get("max_dispute_seconds", 0))

    def digest(self) -> str:
        return pc.digest_over(pc.hashable(self.vtc))


class Facilitator:
    """The settlement service. Thread safe under the threading HTTP server."""

    def __init__(self, identity: str, key: pc.Key, resolver: pc.KeyResolver,
                 now: Any = time.time, base_url: str = "http://127.0.0.1:8402") -> None:
        self.identity = identity
        self.key = key
        self.resolver = resolver
        self.now = now
        self.base_url = base_url.rstrip("/")
        self.schemas = Schemas()
        self.contracts: dict[str, Contract] = {}
        self.seen: dict[tuple[str, str], str] = {}  # (kind, digest) -> vtc_id
        self.lock = threading.RLock()
        self.message_count = 0
        # What this Facilitator advertises, Section 8. Contracts outside it are
        # refused at propose rather than accepted and stranded.
        self.settlement_bindings = [
            {"id": "pact-escrow", "networks": ["eip155:8453"], "assets": ["USDC"]}]
        self.release_modes = ["on-verification"]
        self.verification_profiles = ["acceptance"]
        self.assurance_modes = ["certain"]
        self.max_contract_value = {"amount": "50000.00", "currency": "USDC"}

    # -- Section 12.2 ------------------------------------------------------
    def _digest(self, obj: dict) -> str:
        return pc.digest_over(pc.hashable(obj))

    def _remember(self, kind: str, obj: dict, vid: str) -> None:
        self.seen[(kind, self._digest(obj))] = vid

    def _replay(self, kind: str, obj: dict) -> tuple[int, dict] | None:
        """200 with the CURRENT resource, not a snapshot taken at creation."""
        vid = self.seen.get((kind, self._digest(obj)))
        if vid is None:
            return None
        c = self.contracts[vid]
        self._tick(c)
        if kind == "contract":
            return 200, self._with_state(c, c.vtc)
        if kind == "delivery":
            return 200, self._with_state(c, c.delivery)
        if kind == "verdict":
            return 200, self._with_state(c, obj)
        return 200, self._with_state(c, obj)

    def _with_state(self, c: Contract, obj: dict) -> dict:
        out = dict(obj)
        out["state"] = c.state  # Section 12: added here, never signed or hashed
        return out

    # -- time ----------------------------------------------------------------
    def _tick(self, c: Contract) -> None:
        """Advance the contract along every clock-driven edge that is due."""
        self._expire_if_due(c)
        self._lapse_dispute_if_due(c)
        self._close_window_if_due(c)

    def _record_keys(self, c: Contract, obj: dict) -> None:
        # Section 16.11: record the key material resolved at acceptance, so a
        # later rotation or revocation does not orphan a signature already
        # accepted. The resolver here is in-process; the record is real.
        for kid in pc.signer_kids(obj):
            key = self.resolver.resolve(kid)
            if key is not None and kid not in c.keys:
                c.keys[kid] = pc.b64u(pc.public_bytes(key))

    # -- Propose, Section 12.1 --------------------------------------------
    def propose(self, vtc: dict) -> tuple[int, dict]:
        with self.lock:
            hit = self._replay("contract", vtc)
            if hit is not None:
                return hit

            self.schemas.check(vtc, "vtc.schema.json")
            vid = vtc["id"]
            if vid in self.contracts:
                raise Refuse("object-conflict",
                             f"contract {vid} exists with a different digest")
            if vtc.get("pact") != "0.1" or vtc.get("type") != "VerifiableTaskContract":
                raise Refuse("schema-invalid", "pact version or type is not one this "
                             "Facilitator implements")

            parties = vtc["parties"]
            buyer, seller = parties["buyer"], parties["seller"]
            if pc.same_party(buyer, seller):
                raise Refuse("parties-not-distinct",
                             "buyer and seller are the same party after the "
                             "normalization of Section 9.1", buyer=buyer, seller=seller)
            if not pc.same_party(parties["facilitator"], self.identity):
                raise Refuse("facilitator-mismatch",
                             "the contract names a different Facilitator; accepting it "
                             "would make this signed instrument replayable across venues",
                             named=parties["facilitator"], this=self.identity)
            named = parties.get("verifier")
            if named:
                for who, label in ((buyer, "buyer"), (seller, "seller"),
                                   (self.identity, "facilitator")):
                    if pc.same_party(named, who):
                        raise Refuse("verifier-not-independent",
                                     f"parties.verifier is the {label} after "
                                     f"normalization; such a contract could never be "
                                     f"verified", verifier=named)

            liability = vtc.get("liability")
            if not liability:
                raise Refuse("liability-missing", "a contract that does not allocate "
                             "liability is not a PACT contract")
            if "parent" in liability:
                raise Refuse("parent-unresolvable",
                             "subcontracts (Section 10) are not implemented by this "
                             "Facilitator; a contract naming a parent is refused rather "
                             "than accepted with the parent ignored")

            price_m = vtc["price"]
            binding = next((b for b in self.settlement_bindings
                            if b["id"] == price_m["settlement"]), None)
            if (binding is None or price_m["network"] not in binding["networks"]
                    or price_m["currency"] not in binding["assets"]):
                raise Refuse("settlement-unsupported",
                             "settlement, network or asset is not one this Facilitator "
                             "advertises in its capability document",
                             settlement=price_m["settlement"], network=price_m["network"],
                             currency=price_m["currency"])
            if vtc["release"] not in self.release_modes:
                raise Refuse("release-mode-unsupported",
                             f"release mode {vtc['release']!r} is not implemented; "
                             f"accepting it would strand the contract in RELEASING",
                             supported=self.release_modes)
            mode = vtc["assurance"]["mode"]
            if mode == "open":
                raise Refuse("assurance-unsupported",
                             "a contract MUST NOT declare open as its sole source of "
                             "assurance (Section 7.2)")
            if mode not in self.assurance_modes:
                raise Refuse("assurance-unsupported",
                             f"assurance mode {mode!r} is not implemented",
                             supported=self.assurance_modes)
            if vtc["verification"]["profile"] not in self.verification_profiles:
                raise Refuse("settlement-unsupported",
                             f"verification profile {vtc['verification']['profile']!r} "
                             f"is not one this Facilitator supports",
                             supported=self.verification_profiles)

            deadline = parse_rfc3339(vtc["task"]["deadline"])
            if deadline <= self.now():
                raise Refuse("deadline-invalid",
                             "task.deadline is already past on this Facilitator's clock; "
                             "the contract would be ABANDONED the moment it was funded")

            price = money_cents("price.amount", price_m["amount"])
            bond = money_cents("liability.seller_bond", liability["seller_bond"])
            fund = money_cents("liability.verification_fund", liability["verification_fund"])
            cap = money_cents("liability.cap", liability["cap"])
            maxv = money_cents("max_contract_value", self.max_contract_value["amount"])
            if price > maxv:
                raise Refuse("settlement-unsupported",
                             f"price exceeds this Facilitator's max_contract_value "
                             f"{self.max_contract_value['amount']}")

            # Section 5: exactly the Buyer's and the Seller's signatures, each
            # once, verifying against keys bound to those identifiers. A third
            # signer changes the digest without changing the agreement.
            ok, why = pc.verify_object(vtc, self.resolver, MEDIA_CONTRACT, [buyer, seller])
            if not ok:
                raise Refuse(_sig_kind(why), why)
            for kid in pc.signer_kids(vtc):
                if not (pc.kid_covers(kid, buyer) or pc.kid_covers(kid, seller)):
                    raise Refuse("unexpected-signer",
                                 "the contract carries a signature from a party that is "
                                 "neither its Buyer nor its Seller", signer=kid)

            # Section 7.2: evaluated exactly, BEFORE funds lock.
            q_min = vtc["assurance"]["q_min"]
            if not pc.assurance_holds(price_m["amount"], liability["seller_bond"],
                                      q_min, "0"):
                need = pc.required_bond(float(price_m["amount"]), float(q_min), 0.0)
                raise Refuse(
                    "assurance-constraint-unsatisfied",
                    f"Bond {liability['seller_bond']} is below the minimum {need:.2f} "
                    f"required for q_min {float(q_min):.2f} at price "
                    f"{price_m['amount']} with E 0.00.",
                    required_bond=f"{need:.2f}", declared_bond=liability["seller_bond"],
                    q_min=q_min, price=price_m["amount"])

            c = Contract(vtc=vtc, created_at=self.now(), deadline=deadline)
            c.pools.escrow = price
            c.pools.bond = bond
            c.pools.bond_initial = bond
            c.pools.fund = fund
            c.pools.cap = cap
            c.pools.note(f"locked escrow {pc.money(price)}, bond {pc.money(bond)}, "
                         f"fund {pc.money(fund)} (in memory: no rail, so PROPOSED is "
                         f"not observable and the contract is FUNDED at once)")
            c.state = "FUNDED"
            self._record_keys(c, vtc)
            self.contracts[c.id] = c
            self._remember("contract", vtc, c.id)
            return 201, self._with_state(c, vtc)

    # -- Retrieve ----------------------------------------------------------
    def get_contract(self, vid: str) -> tuple[int, dict]:
        with self.lock:
            c = self._contract(vid)
            self._tick(c)
            return 200, self._with_state(c, c.vtc)

    def _contract(self, vid: str) -> Contract:
        c = self.contracts.get(vid)
        if c is None:
            raise Refuse("unknown-contract", f"no contract {vid}")
        return c

    # -- Section 6: deadline expiry ---------------------------------------
    def _expire_if_due(self, c: Contract) -> None:
        if c.state != "FUNDED" or self.now() < c.deadline:
            return
        p = c.pools
        p.paid_to_buyer += p.escrow
        p.note(f"deadline {iso(c.deadline)} passed with no Delivery: returned escrow "
               f"{pc.money(p.escrow)} to buyer")
        p.escrow = 0
        # Section 6: slash the Bond to the extent of restitution_basis. Under
        # `released` with nothing released that extent is zero. What happens to
        # the rest is unspecified (Section 7.6 covers FINAL and SETTLED only);
        # CHOICES C1: it is returned.
        owed = self._basis_owed(c)
        slashed = min(owed, p.bond, p.cap)
        if slashed:
            p.bond -= slashed
            p.paid_to_buyer += slashed
            p.restituted += slashed
        p.note(f"restitution basis {c.vtc['liability']['restitution_basis']!r} slashes "
               f"{pc.money(slashed)} from the bond on ABANDONED (Section 6)")
        self._return_bond(c, "C1: the draft does not say; returned")
        c.state = "ABANDONED"
        self._attest(c, outcome="abandoned")

    def _basis_owed(self, c: Contract) -> int:
        """Rank 3: the Buyer's loss, up to the basis, net of rank 1 (CHOICES C2)."""
        p = c.pools
        basis = c.vtc["liability"]["restitution_basis"]
        ceiling = p.released if basis == "released" else pc.cents(c.vtc["price"]["amount"])
        loss = pc.cents(c.vtc["price"]["amount"]) - p.paid_to_buyer  # escrow not yet back
        return max(0, min(ceiling, loss))

    def _return_bond(self, c: Contract, why: str) -> None:
        # Section 7.6: returned at FINAL or SETTLED, less what 7.4 applied.
        p = c.pools
        if p.bond:
            p.note(f"returned bond {pc.money(p.bond)} to seller ({why})")
            p.bond_returned += p.bond
            p.bond = 0
        if p.fund:
            p.note(f"returned unspent verification fund {pc.money(p.fund)} to seller")
            p.fund_returned += p.fund
            p.fund = 0

    # -- the challenge window, Section 7.5 --------------------------------
    def _close_window_if_due(self, c: Contract) -> None:
        if c.state != "RELEASING" or c.window_opened_at is None:
            return
        if self.now() - c.window_opened_at < c.window_seconds:
            return
        c.pools.note(f"challenge window of {c.window_seconds}s closed with no "
                     f"successful Challenge")
        self._return_bond(c, "Section 7.6, FINAL")
        c.state = "FINAL"
        self._attest(c, outcome="performed")

    def _lapse_dispute_if_due(self, c: Contract) -> None:
        # CHOICES C5. The draft bounds a dispute by max_dispute_seconds and does
        # not say what happens when the bound passes with no Verdict.
        if c.state != "DISPUTED" or c.disputed_at is None or not c.max_dispute_seconds:
            return
        if self.now() - c.disputed_at < c.max_dispute_seconds:
            return
        c.pools.note(f"no Verdict within max_dispute_seconds {c.max_dispute_seconds}; "
                     f"the Challenge lapses and the earlier Verdict stands (C5)")
        c.disputed_at = None
        c.state = "RELEASING"

    # -- Submit Delivery, Section 12 --------------------------------------
    def submit_delivery(self, dlv: dict) -> tuple[int, dict]:
        with self.lock:
            hit = self._replay("delivery", dlv)
            if hit is not None:
                return hit
            for member in ("vtc_id", "vtc_hash", "signature"):
                if not isinstance(dlv.get(member), (str, dict)):
                    raise Refuse("schema-invalid", f"the Delivery lacks {member}")
            c = self._contract(dlv["vtc_id"])
            self._tick(c)
            if dlv["vtc_hash"] != c.digest():
                raise Refuse("object-conflict", "vtc_hash does not commit to this contract",
                             expected=c.digest(), received=dlv["vtc_hash"])
            if c.state != "FUNDED":
                raise Refuse("wrong-state", f"contract {c.id} is {c.state}; a Delivery "
                             f"is only accepted in FUNDED")

            # Section 12: a Delivery not signed by the contract's Seller is
            # rejected, and nobody else may sign it.
            ok, why = pc.verify_object(dlv, self.resolver, MEDIA_DELIVERY, [c.seller])
            if not ok:
                raise Refuse(_sig_kind(why), why)

            # Section 6: shape, not substance. Absent or nonconformant evidence
            # is refused AND remedied as though a FAIL Verdict had been recorded,
            # which is the rule the draft calls the one that makes silence
            # expensive. Both halves are normative (line 832).
            reason = self._delivery_nonconformance(c, dlv)
            if reason is None:
                # Shape of everything else: a schema failure inside `evidence`
                # is nonconformance too; elsewhere it is a plain 13.2 refusal.
                try:
                    self.schemas.check(dlv, "delivery.schema.json")
                except Refuse as exc:
                    if str(exc.extra.get("path", "")).startswith("evidence"):
                        reason = exc.detail
                    else:
                        raise
            if reason is not None:
                c.pools.note(f"nonconformant Delivery: {reason}; applying Section 7.4 as "
                             f"though a FAIL Verdict were recorded")
                self._record_keys(c, dlv)
                self._apply_waterfall(c, challengers=[])
                raise Refuse("evidence-nonconformant", reason, state=c.state,
                             remedy="Section 7.4 applied as though FAIL")

            c.delivery = dlv
            c.state = "DELIVERED"
            self._record_keys(c, dlv)
            self._remember("delivery", dlv, c.id)
            return 202, self._with_state(c, dlv)

    def _delivery_nonconformance(self, c: Contract, dlv: dict) -> str | None:
        ev = dlv.get("evidence")
        ver = c.vtc["verification"]
        if not isinstance(ev, dict):
            return "the Delivery carries no evidence member"
        if ev.get("profile") != ver["profile"]:
            return (f"evidence profile {ev.get('profile')!r} does not match the "
                    f"contract's declared profile {ver['profile']!r}")
        if ev.get("instrument_hash") != ver["criteria_hash"]:
            return "the evidence does not commit to the instrument the contract committed to"
        if "results_hash" not in ev:
            return "the acceptance profile requires results_hash in the evidence"
        if "results_uri" in ev and "results_hash" not in ev:
            return "results_uri without a sibling results_hash (Section 5.1)"
        if ver["tier"] == "T0-reexec" and "input_hash" not in dlv:
            return ("input_hash is REQUIRED for a tier whose fraud proof re-executes "
                    "(Section 6)")
        return None

    def _delivery_digest(self, c: Contract) -> str:
        if c.delivery is None:
            raise Refuse("no-recorded-delivery",
                         f"contract {c.id} has no recorded Delivery to judge")
        return pc.digest_over(pc.hashable(c.delivery))

    # -- Record Verdict, Section 12.4 -------------------------------------
    def record_verdict(self, verdict: dict) -> tuple[int, dict]:
        with self.lock:
            hit = self._replay("verdict", verdict)
            if hit is not None:
                return hit
            self.schemas.check(verdict, "verdict.schema.json")
            c = self._contract(verdict["vtc_id"])
            self._tick(c)
            recorded = self._delivery_digest(c)
            if verdict["delivery_hash"] != recorded:
                raise Refuse("object-conflict",
                             "delivery_hash does not commit to the recorded Delivery",
                             expected=recorded, received=verdict["delivery_hash"])
            if c.state not in ("DELIVERED", "DISPUTED"):
                raise Refuse("wrong-state",
                             f"contract {c.id} is {c.state}; a Verdict is accepted on "
                             f"DELIVERED, or on DISPUTED to resolve a Challenge")

            # A Verdict commits to the instrument it ran (Section 12.4). One
            # over a different instrument or profile is the Section 16.3
            # substitution attack from the verifier's side.
            ver = c.vtc["verification"]
            if verdict["instrument_hash"] != ver["criteria_hash"]:
                raise Refuse("verdict-nonconformant",
                             "instrument_hash is not the instrument the contract committed to",
                             expected=ver["criteria_hash"], received=verdict["instrument_hash"])
            if verdict["profile"] != ver["profile"]:
                raise Refuse("verdict-nonconformant",
                             f"profile {verdict['profile']!r} is not the contract's "
                             f"{ver['profile']!r}")
            if verdict["outcome"] not in ("PASS", "FAIL"):
                raise Refuse("verdict-nonconformant", "outcome must be PASS or FAIL")

            kids = pc.signer_kids(verdict)
            if not kids:
                raise Refuse("signature-missing", "the Verdict carries no signature")
            self._check_verdict_signer(c, kids)
            named = c.vtc["parties"].get("verifier")
            ok, why = pc.verify_object(verdict, self.resolver, MEDIA_VERDICT,
                                       [named] if named else [])
            if not ok:
                raise Refuse(_sig_kind(why), why)

            # Every check passed; only now does state move.
            c.verdicts.append(verdict)  # Section 7.5: both are recorded
            self._record_keys(c, verdict)
            outcome = verdict["outcome"]
            if c.state == "DELIVERED":
                if outcome == "PASS":
                    self._release_on_pass(c)
                else:
                    c.state = "DISPUTED"
                    self._apply_waterfall(c, challengers=[])
            else:  # DISPUTED: this Verdict resolves the open Challenge(s)
                c.disputed_at = None
                if outcome == "FAIL":
                    c.pools.note("Challenge upheld: this Verdict supersedes the PASS")
                    self._apply_waterfall(c, challengers=list(c.challenges))
                else:
                    c.pools.note("Challenge rejected: the PASS stands; window resumes")
                    c.state = "RELEASING"
                    self._close_window_if_due(c)
            self._remember("verdict", verdict, c.id)
            return 201, self._with_state(c, verdict)

    def _check_verdict_signer(self, c: Contract, kids: list[str]) -> None:
        # Draft line 1852: where the contract names parties.verifier the Verdict
        # MUST be signed by that party; otherwise 9.1 is evaluated against the
        # signer. Section 3: never the Facilitator. Section 7.5: never a
        # Challenger judging its own Challenge.
        named = c.vtc["parties"].get("verifier")
        if named and not any(pc.kid_covers(k, named) for k in kids):
            raise Refuse("verifier-not-independent",
                         "the contract names a verifier and the Verdict is not signed "
                         "by that party", signer=kids[0], required_verifier=named)
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
                             "a Facilitator MUST NOT act as Verifier for a contract it "
                             "settles", signer=kid, facilitator=self.identity)
            for ch in c.challenges:
                for ck in pc.signer_kids(ch):
                    if c.state == "DISPUTED" and pc.same_party(ck, kid):
                        raise Refuse("verifier-not-independent",
                                     "a Challenger's own assertion is not a Verdict "
                                     "(Section 7.5)", signer=kid)

    def _release_on_pass(self, c: Contract) -> None:
        # on-verification: the price releases on PASS, the window opens now,
        # and the Bond and fund stay locked until it closes (draft lines
        # 477 to 482). An earlier version returned the Bond here and reached
        # FINAL in the same call, so no window ever opened and the Figure 6
        # path was unreachable in the only mode the draft requires.
        p = c.pools
        # Section 7.1: cumulative release before a Verdict never exceeds the
        # Bond. Under on-verification nothing is released before the Verdict,
        # so E is zero here by construction and the cap cannot bind.
        p.paid_to_seller += p.escrow
        p.released += p.escrow
        p.note(f"released escrow {pc.money(p.escrow)} to seller on PASS; challenge "
               f"window of {c.window_seconds}s opens")
        p.escrow = 0
        c.state = "RELEASING"
        c.window_opened_at = self.now()

    # -- Open challenge, Section 7.5 --------------------------------------
    def open_challenge(self, ch: dict) -> tuple[int, dict]:
        with self.lock:
            hit = self._replay("challenge", ch)
            if hit is not None:
                return hit
            self.schemas.check(ch, "challenge.schema.json")
            c = self._contract(ch["vtc_id"])
            self._tick(c)
            recorded = self._delivery_digest(c)
            if ch["delivery_hash"] != recorded:
                raise Refuse("object-conflict",
                             "delivery_hash does not commit to the recorded Delivery",
                             expected=recorded, received=ch["delivery_hash"])
            if c.state not in ("RELEASING", "DISPUTED"):
                raise Refuse("challenge-window-closed",
                             f"no challenge window is open: contract {c.id} is {c.state}, "
                             f"and under on-verification the window opens when a PASS "
                             f"is recorded and closes {c.window_seconds}s later",
                             state=c.state)
            if c.window_opened_at is None or \
                    self.now() - c.window_opened_at >= c.window_seconds:
                raise Refuse("challenge-window-closed",
                             f"the {c.window_seconds}s challenge window has closed")

            # Section 7.5: a proof that does not conform to the profile is
            # refused. Under the acceptance profile that means the committed
            # instrument and a results digest.
            proof = ch["proof"]
            ver = c.vtc["verification"]
            if proof.get("profile") != ver["profile"]:
                raise Refuse("proof-nonconformant",
                             f"proof profile {proof.get('profile')!r} is not the "
                             f"contract's {ver['profile']!r}")
            if proof.get("instrument_hash") != ver["criteria_hash"]:
                raise Refuse("proof-nonconformant",
                             "the proof does not commit to the instrument the contract "
                             "committed to")
            if "results_hash" not in proof:
                raise Refuse("proof-nonconformant",
                             "the acceptance profile requires results_hash in the proof")

            ok, why = pc.verify_object(ch, self.resolver, MEDIA_CHALLENGE, [])
            if not ok:
                raise Refuse(_sig_kind(why), why)
            kids = pc.signer_kids(ch)
            if any(pc.kid_covers(k, c.seller) for k in kids):
                raise Refuse("unexpected-signer", "a Seller cannot challenge its own "
                             "Delivery", signer=kids[0])

            # A Challenge is a fraud proof submitted for evaluation, not a
            # finding. It moves the contract to DISPUTED and nothing else; the
            # Verdict that resolves it comes from an independent party.
            c.challenges.append(ch)
            if c.state != "DISPUTED":
                c.disputed_at = self.now()
                c.state = "DISPUTED"
            c.pools.note(f"challenge accepted from {kids[0]}; awaiting a Verdict from "
                         f"an independent evaluator ({len(c.challenges)} open)")
            self._record_keys(c, ch)
            self._remember("challenge", ch, c.id)
            return 202, self._with_state(c, ch)

    # -- Section 7.4, the five ranks in order ------------------------------
    def _apply_waterfall(self, c: Contract, challengers: list[dict]) -> None:
        p = c.pools
        moved_from_seller = 0

        # 1. Reverse any unreleased escrow to the Buyer.
        if p.escrow:
            p.paid_to_buyer += p.escrow
            p.note(f"rank 1: reversed unreleased escrow {pc.money(p.escrow)} to buyer")
            p.escrow = 0

        # 2. Reimburse the successful Challenger's documented costs FROM THE
        #    VERIFICATION FUND. The Challenge object has no member in which to
        #    document them (a -02 item), so this is 0.00 (CHOICES C4).
        if challengers:
            p.note("rank 2: the Challenge carries no cost claim; reimbursed 0.00 from "
                   "the verification fund (C4)")

        # 3. Restore the Buyer from the Bond, up to restitution_basis, net of
        #    what rank 1 already returned (CHOICES C2), and never beyond cap.
        owed = self._basis_owed(c)
        restitution = min(owed, p.bond, p.cap - moved_from_seller)
        if restitution:
            p.bond -= restitution
            p.paid_to_buyer += restitution
            p.restituted += restitution
            moved_from_seller += restitution
        p.note(f"rank 3: restitution basis {c.vtc['liability']['restitution_basis']!r}, "
               f"buyer's loss {pc.money(owed)}, paid {pc.money(restitution)} from bond")

        # 4. The Challenger bounty from the remaining Bond: only to a
        #    Challenger that exists, the whole remainder, split equally among
        #    successful Challengers (CHOICES C3).
        if challengers and p.bond:
            pool = min(p.bond, p.cap - moved_from_seller)
            share = pool // len(challengers)
            paid = share * len(challengers)
            p.bond -= paid
            p.paid_to_challenger += paid
            moved_from_seller += paid
            p.note(f"rank 4: bounty {pc.money(paid)} from the remaining bond to "
                   f"{len(challengers)} challenger(s), {pc.money(share)} each (C3)")
        elif not challengers:
            p.note("rank 4: no Challenger, no bounty")

        # 5. Direct any remainder per liability.remainder_to, within cap.
        remainder_to = c.vtc["liability"].get("remainder_to", "sink")
        if p.bond:
            movable = min(p.bond, p.cap - moved_from_seller)
            if movable:
                if remainder_to == "buyer":
                    p.paid_to_buyer += movable
                else:
                    p.remainder += movable
                p.bond -= movable
                moved_from_seller += movable
                p.note(f"rank 5: remainder {pc.money(movable)} directed to {remainder_to}")
            if p.bond:
                p.note(f"liability.cap reached: {pc.money(p.bond)} of the bond is not "
                       f"the Facilitator's to move and is returned")

        self._return_bond(c, "Section 7.6, SETTLED")
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
        p = c.pools
        att = {
            "pact": "0.1",
            "type": "WorkAttestation",
            "vtc_id": c.id,
            "vtc_hash": c.digest(),
            "parties": {"buyer": c.buyer, "seller": c.seller, "facilitator": self.identity},
            "subject": c.seller,
            "role": "seller",
            "outcome": outcome,
            "amounts": {
                "settled": pc.money(p.paid_to_seller),
                # Restitution is what the Buyer recovered FROM THE BOND. Escrow
                # coming back is the Buyer's own money and is not restitution.
                "restituted": pc.money(p.restituted),
                "slashed": pc.money(p.bond_initial - p.bond_returned - p.bond),
                "currency": c.vtc["price"]["currency"],
            },
            "opened_at": iso(c.created_at),
            "settled_at": iso(self.now()),
        }
        if c.delivery is not None:
            att["work_hash"] = c.delivery["work_hash"]
        att["signatures"] = [pc.sign(att, self.key, MEDIA_ATTESTATION)]
        self.schemas.check(att, "attestation.schema.json")
        c.attestation = att

    def get_attestation(self, vid: str) -> tuple[int, dict]:
        with self.lock:
            c = self._contract(vid)
            self._tick(c)
            if c.attestation is None:
                raise Refuse("wrong-state",
                             f"contract {vid} is {c.state} and not terminal, so no "
                             f"attestation exists yet")
            return 200, c.attestation

    # -- Section 8 -----------------------------------------------------------
    def capability_document(self) -> dict:
        doc = {
            "pact": "0.1",
            "facilitator": self.identity,
            "settlement_bindings": self.settlement_bindings,
            "release_modes": self.release_modes,
            "verification_profiles": self.verification_profiles,
            "assurance_modes": self.assurance_modes,
            "max_contract_value": self.max_contract_value,
            "endpoints": {
                "contract": self.base_url + "/pact/v1/contracts",
                "delivery": self.base_url + "/pact/v1/deliveries",
                "verdict": self.base_url + "/pact/v1/verdicts",
                "challenge": self.base_url + "/pact/v1/challenges",
                "attestation": self.base_url + "/pact/v1/attestations",
            },
            # no challenge_deposit member: absent means none is required
        }
        doc["signature"] = pc.sign(doc, self.key, MEDIA_FACILITATOR)
        self.schemas.check(doc, "facilitator.schema.json")
        return doc


def _sig_kind(why: str) -> str:
    return "algorithm-not-permitted" if why.startswith("algorithm") else "signature-invalid"


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
    "propose": MEDIA_CONTRACT,
    "submit_delivery": MEDIA_DELIVERY,
    "record_verdict": MEDIA_VERDICT,
    "open_challenge": MEDIA_CHALLENGE,
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "pact-reference-facilitator/0.2"

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
            "section": section.split(" ", 1)[1],  # draft Figure 12: "7.2", not "Section 7.2"
        }
        body.update(exc.extra)
        self._send(status, body, "application/problem+json")

    def _guard(self, fn) -> None:
        try:
            fn()
        except Refuse as exc:
            self._problem(exc)
        except Exception as exc:  # pragma: no cover
            # Never a 409 dressed as a rule, and never the traceback: a caller
            # cannot locate a Python exception in the specification.
            self._problem(Refuse("internal-error",
                                 f"the Facilitator failed internally ({type(exc).__name__})"))

    def do_GET(self) -> None:
        def run() -> None:
            if self.path == "/.well-known/pact-facilitator":
                self._send(200, self.fac.capability_document(), MEDIA_FACILITATOR)
                return
            m = re.match(r"^/pact/v1/(contracts|attestations)/([^/]+)$", self.path)
            if not m:
                raise Refuse("unknown-contract", f"no route for {self.path}")
            kind, vid = m.groups()
            if kind == "contracts":
                status, body = self.fac.get_contract(vid)
                self._send(status, body, MEDIA_CONTRACT)
            else:
                status, body = self.fac.get_attestation(vid)
                self._send(status, body, MEDIA_ATTESTATION)
        self._guard(run)

    def do_POST(self) -> None:
        def run() -> None:
            m = re.match(r"^/pact/v1/(contracts|deliveries|verdicts|challenges)$", self.path)
            if not m:
                raise Refuse("unknown-contract", f"no route for {self.path}")
            op = ROUTES[m.group(1)]
            length = int(self.headers.get("Content-Length", 0))
            if length > MAX_BODY:
                raise Refuse("payload-too-large", f"body exceeds {MAX_BODY} bytes")
            try:
                obj = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                raise Refuse("schema-invalid", "body is not JSON")
            if not isinstance(obj, dict):
                raise Refuse("schema-invalid", "body is not a JSON object")
            status, body = getattr(self.fac, op)(obj)
            self._send(status, body, MEDIA[op])
        self._guard(run)


def serve(facilitator: Facilitator, port: int = 8402,
          verbose: bool = False) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    httpd.facilitator = facilitator  # type: ignore[attr-defined]
    httpd.verbose = verbose  # type: ignore[attr-defined]
    return httpd


def build(identity: str = "did:web:settle.example", now: Any = time.time,
          base_url: str = "http://127.0.0.1:8402") -> tuple[Facilitator, pc.KeyResolver]:
    resolver = pc.KeyResolver()
    key = resolver.register(pc.Key.generate(identity + "#key-1"))
    return Facilitator(identity, key, resolver, now=now, base_url=base_url), resolver


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8402)
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--rules", action="store_true",
                    help="print the rules this implementation enforces, and its choices, and exit")
    args = ap.parse_args()
    if args.rules:
        print(RULES.strip())
        print()
        print(CHOICES.strip())
        return
    fac, _ = build(base_url=f"http://127.0.0.1:{args.port}")
    httpd = serve(fac, args.port, args.verbose)
    print(f"reference Facilitator {fac.identity} on http://127.0.0.1:{args.port}")
    print(f"capability document at http://127.0.0.1:{args.port}/.well-known/pact-facilitator")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
