"""The bonded-restitution terms profile, evaluated the way -02 Section 5.3 says.

A terms profile is a total, deterministic function from a contract and a trace
prefix to the entries it emits at the last event of that prefix. This module
is that function for the one profile in the repository, the non-normative
Appendix A of draft-laxsharma-pact-02, whose bundle lives under
profiles/bonded-restitution/. The Facilitator calls it at every event and
never decides anything about value itself; validate.py calls it to reproduce
the vectors; nothing in the Internet-Draft depends on what it computes.

Every figure here is the -01 draft's settlement content: the assurance
constraint as the admission rule, the three pools as accounts, the five-rank
remedy as the SETTLED schedule, and the choices the -01 left open made where
the reference implementation had already made them.

    python3 tools/profile.py --vectors     # regenerate the bundle's vectors.json
    python3 tools/profile.py --hash        # print profile_hash
"""

from __future__ import annotations

import argparse
import json
import pathlib
from decimal import ROUND_UP, Decimal
from typing import Any

import pactcore as pc

ROOT = pathlib.Path(__file__).resolve().parent.parent
BUNDLE = ROOT / "profiles" / "bonded-restitution"
ID = "tag:laxsharma79@gmail.com,2026:pact:bonded-restitution"
PROBLEM_BASE = ID + ":problem:"
INTERNAL = ("escrow", "bond", "fund")
CENT = Decimal("0.01")


class ProfileRefusal(Exception):
    """A refusal arising from a rule of the profile, not of the document.

    Reported per -02 Section 13.3 with `profile` and `profile_section` in the
    problem body instead of `section`.
    """

    def __init__(self, kind: str, detail: str, section: str, **extra: Any) -> None:
        self.kind = kind
        self.detail = detail
        self.section = section
        self.extra = extra
        super().__init__(detail)


def _d(x: Any) -> Decimal:
    return Decimal(str(x))


def _money(d: Decimal) -> str:
    return f"{d.quantize(CENT):f}"


class BondedRestitution:
    id = ID
    problem_base = PROBLEM_BASE

    def __init__(self, bundle: pathlib.Path = BUNDLE) -> None:
        self.bundle = pathlib.Path(bundle)
        self.schema = json.loads((self.bundle / "parameters.schema.json").read_text())
        self.profile_hash = pc.manifest_digest(self.bundle)
        self._validator = None
        try:
            from jsonschema import Draft202012Validator
            self._validator = Draft202012Validator(self.schema)
        except ImportError:  # pragma: no cover
            pass

    # -- Section 5.3: the parameters validate against the profile's schema --
    def parameters_error(self, params: Any) -> str | None:
        if self._validator is None:
            return None if isinstance(params, dict) else "parameters is not an object"
        errors = sorted(self._validator.iter_errors(params), key=lambda e: list(e.path))
        if not errors:
            return None
        e = errors[0]
        where = "/".join(str(x) for x in e.path) or "(root)"
        return f"parameters do not validate against the profile's schema at {where}: {e.message}"

    # -- Appendix A.4: admission at `accepted` ----------------------------
    def admit(self, vtc: dict) -> None:
        prm = vtc["terms"]["parameters"]
        price = _d(vtc["price"]["amount"])
        bond = _d(prm["seller_bond"])
        fund = _d(prm["verification_fund"])
        cap = _d(prm["cap"])
        if bond > cap or fund > cap:
            raise ProfileRefusal("parameters-inconsistent",
                                 "seller_bond and verification_fund cannot exceed cap",
                                 "A.4", cap=prm["cap"])
        mode = prm["assurance"]["mode"]
        if mode == "open":
            raise ProfileRefusal("assurance-constraint-unsatisfied",
                                 "open challenge is a backstop, not a source of q; this "
                                 "profile refuses it as the sole declared assurance", "A.4")
        q = _d(prm["assurance"]["q_min"])
        released_before_verdict = price if prm["principal_on"] == "delivered" else Decimal(0)
        if not pc.assurance_holds(price, bond, q, released_before_verdict):
            need = (price * (1 - q) / q + released_before_verdict).quantize(CENT, rounding=ROUND_UP)
            raise ProfileRefusal(
                "assurance-constraint-unsatisfied",
                f"seller_bond {prm['seller_bond']} is below the minimum {need:f} required "
                f"for q_min {q:f} at price {vtc['price']['amount']} with E "
                f"{_money(released_before_verdict)}", "A.4",
                required_bond=f"{need:f}", declared_bond=prm["seller_bond"],
                q_min=prm["assurance"]["q_min"], price=vtc["price"]["amount"])

    # -- Appendix A.3: accounts -----------------------------------------------
    @staticmethod
    def accounts(vtc: dict) -> dict[str, Decimal]:
        return {name: Decimal(0) for name in INTERNAL}

    # -- Appendix A.5: the schedule over a whole trace ------------------------
    def schedule(self, vtc: dict, trace: list[dict]) -> list[dict]:
        prm = vtc["terms"]["parameters"]
        currency = vtc["price"]["currency"]
        price = _d(vtc["price"]["amount"])
        bond0 = _d(prm["seller_bond"])
        fund0 = _d(prm["verification_fund"])
        cap = _d(prm["cap"])
        fee = _d(prm.get("verifier_fee", "0.00"))
        basis = prm["restitution_basis"]
        remainder_to = prm.get("remainder_to", "sink")
        principal_on = prm["principal_on"]

        bal = self.accounts(vtc)
        out: list[dict] = []
        released = Decimal(0)
        from_seller = Decimal(0)          # what has left the Seller's accounts, for cap
        verdicts: list[dict] = []
        challenges: dict[str, dict] = {}  # digest -> entry

        def emit(i: int, src: str, dst: str, amount: Decimal, code: str) -> None:
            nonlocal released, from_seller
            if amount <= 0:
                return
            if src in bal:
                assert bal[src] >= amount, f"schedule would overdraw {src}"
                bal[src] -= amount
            if dst in bal:
                bal[dst] += amount
            if code == "principal":
                released += amount
            if src == "bond":
                from_seller += amount
            out.append({"event": i, "from": src, "to": dst,
                        "amount": _money(amount), "code": code})

        def standing() -> dict | None:
            return verdicts[-1] if verdicts else None

        for i, e in enumerate(trace):
            ev = e["event"]
            if ev == "funded":
                emit(i, "buyer", "escrow", price, "lock")
                emit(i, "seller", "bond", bond0, "bond")
                emit(i, "buyer", "fund", fund0, "fund")
            elif ev == "delivered":
                if principal_on == "delivered":
                    emit(i, "escrow", "seller", bal["escrow"], "principal")
            elif ev == "challenge":
                challenges[e["object"]] = e
            elif ev == "verdict":
                verdicts.append(e)
                emit(i, "fund", "verifier", min(fee, bal["fund"]), "verification")
                if (e["outcome"] == "PASS" and "answers" not in e
                        and principal_on == "verdict"):
                    emit(i, "escrow", "seller", bal["escrow"], "principal")
            elif ev == "window-closed":
                st = standing()
                if principal_on == "window-closed" and not (st and st["outcome"] == "FAIL"):
                    emit(i, "escrow", "seller", bal["escrow"], "principal")
            elif ev == "terminal":
                state = e["state"]
                if state == "FINAL":
                    emit(i, "escrow", "seller", bal["escrow"], "principal")
                    emit(i, "bond", "seller", bal["bond"], "return")
                    emit(i, "fund", "buyer", bal["fund"], "fund-return")
                elif state == "ABANDONED":
                    emit(i, "escrow", "buyer", bal["escrow"], "reverse")
                    emit(i, "bond", "seller", bal["bond"], "return")
                    emit(i, "fund", "buyer", bal["fund"], "fund-return")
                else:  # SETTLED, five ranks
                    st = standing()
                    upheld = bool(e.get("challenge_upheld")) and st is not None and "answers" in st
                    challenger_account = None
                    costs = Decimal(0)
                    if upheld:
                        ch = challenges.get(st["answers"])
                        if ch is not None:
                            challenger_account = "challenger:" + ch.get("signer", st["answers"])
                            c = ch.get("costs")
                            if c and c.get("currency") == currency:
                                costs = _d(c["amount"])
                    reversed_ = bal["escrow"]
                    emit(i, "escrow", "buyer", reversed_, "reverse")                 # rank 1
                    if upheld and challenger_account:
                        emit(i, "fund", challenger_account, min(costs, bal["fund"]), "costs")  # 2
                    loss = released if basis == "released" else price - reversed_
                    room = max(Decimal(0), cap - from_seller)
                    emit(i, "bond", "buyer", min(bal["bond"], room, loss), "restitution")  # 3
                    if upheld and challenger_account:
                        room = max(Decimal(0), cap - from_seller)
                        emit(i, "bond", challenger_account, min(bal["bond"], room), "bounty")  # 4
                    room = max(Decimal(0), cap - from_seller)
                    emit(i, "bond", "buyer" if remainder_to == "buyer" else "sink",
                         min(bal["bond"], room), "remainder")                        # 5
                    # anything the cap kept in the bond is not this profile's to move
                    emit(i, "bond", "seller", bal["bond"], "return")
                    emit(i, "fund", "buyer", bal["fund"], "fund-return")
        return out

    def step(self, vtc: dict, trace: list[dict]) -> list[dict]:
        """The entries emitted at the last event of `trace`."""
        last = len(trace) - 1
        return [t for t in self.schedule(vtc, trace) if t["event"] == last]

    # -- Section 12.1: the two arithmetic facts over a list --------------------
    def check(self, vtc: dict, transfers: list[dict], terminal: bool) -> tuple[bool, str]:
        bal = self.accounts(vtc)
        for t in transfers:
            amount = _d(t["amount"])
            if amount <= 0:
                return False, f"non-positive amount {t['amount']}"
            if t["from"] in bal:
                if bal[t["from"]] < amount:
                    return False, f"entry overdraws {t['from']} ({t['code']})"
                bal[t["from"]] -= amount
            if t["to"] in bal:
                bal[t["to"]] += amount
        if terminal:
            for name, v in bal.items():
                if v != 0:
                    return False, f"internal account {name} holds {_money(v)} after the last entry"
        return True, "ok"

    # -- the bundle's vectors.json ------------------------------------------
    def vectors(self) -> list[dict]:
        return json.loads((self.bundle / "vectors.json").read_text())

    def reproduces(self) -> tuple[bool, str]:
        for v in self.vectors():
            got = self.schedule(v["contract"], v["trace"])
            if got != v["transfers"]:
                return False, f"vector {v['name']}: schedule differs from the bundle"
            ok, why = self.check(v["contract"], got, terminal=v["trace"][-1]["event"] == "terminal")
            if not ok:
                return False, f"vector {v['name']}: {why}"
        return True, "ok"


# --------------------------------------------------------------------------
# Vector generation. The traces here are the canonical paths of the draft's
# figures; timestamps are fixed and the profile never reads them.
# --------------------------------------------------------------------------

def _contract(**over: Any) -> dict:
    prm = {"seller_bond": "18.00", "verification_fund": "0.50", "cap": "180.00",
           "restitution_basis": "released", "remainder_to": "sink",
           "principal_on": "verdict", "assurance": {"mode": "certain", "q_min": 1.0}}
    prm.update(over.pop("parameters", {}))
    c = {"price": {"amount": "180.00", "currency": "USDC"},
         "flow": "verdict-first", "terms": {"profile": ID, "parameters": prm}}
    c.update(over)
    return c


T = ["2026-11-01T10:00:00Z", "2026-11-10T08:30:12Z", "2026-11-10T09:14:30Z",
     "2026-11-10T09:40:00Z", "2026-11-10T09:58:05Z", "2026-11-10T10:14:31Z",
     "2026-11-14T00:00:01Z"]
H = {k: "sha256:" + k.ljust(64, "0") for k in
     ("vtc", "delivery", "verdict1", "verdict2", "challenge")}
CHALLENGER = "did:web:watch.example#k1"
VERIFIER = "did:web:audit.example#k1"


def _trace_final() -> list[dict]:
    return [
        {"event": "accepted", "at": T[0], "object": H["vtc"]},
        {"event": "funded", "at": T[0]},
        {"event": "delivered", "at": T[1], "object": H["delivery"]},
        {"event": "verdict", "at": T[2], "object": H["verdict1"], "signer": VERIFIER,
         "outcome": "PASS"},
        {"event": "window-opened", "at": T[2], "closes_at": "2026-11-10T10:14:30Z"},
        {"event": "window-closed", "at": T[5]},
        {"event": "children-final", "at": T[5]},
        {"event": "terminal", "at": T[5], "state": "FINAL", "challenge_upheld": False},
    ]


def _trace_overturned() -> list[dict]:
    return [
        {"event": "accepted", "at": T[0], "object": H["vtc"]},
        {"event": "funded", "at": T[0]},
        {"event": "delivered", "at": T[1], "object": H["delivery"]},
        {"event": "verdict", "at": T[2], "object": H["verdict1"], "signer": VERIFIER,
         "outcome": "PASS"},
        {"event": "window-opened", "at": T[2], "closes_at": "2026-11-10T10:14:30Z"},
        {"event": "challenge", "at": T[3], "object": H["challenge"], "signer": CHALLENGER,
         "costs": {"amount": "1.20", "currency": "USDC"}},
        {"event": "verdict", "at": T[4], "object": H["verdict2"], "signer": VERIFIER,
         "outcome": "FAIL", "answers": H["challenge"], "supersedes": H["verdict1"]},
        {"event": "children-final", "at": T[4]},
        {"event": "terminal", "at": T[4], "state": "SETTLED", "challenge_upheld": True},
    ]


def _trace_settled_by_verifier() -> list[dict]:
    return [
        {"event": "accepted", "at": T[0], "object": H["vtc"]},
        {"event": "funded", "at": T[0]},
        {"event": "delivered", "at": T[1], "object": H["delivery"]},
        {"event": "verdict", "at": T[2], "object": H["verdict1"], "signer": VERIFIER,
         "outcome": "FAIL"},
        {"event": "children-final", "at": T[2]},
        {"event": "terminal", "at": T[2], "state": "SETTLED", "challenge_upheld": False},
    ]


def _trace_abandoned() -> list[dict]:
    return [
        {"event": "accepted", "at": T[0], "object": H["vtc"]},
        {"event": "funded", "at": T[0]},
        {"event": "deadline-passed", "at": T[6]},
        {"event": "children-final", "at": T[6]},
        {"event": "terminal", "at": T[6], "state": "ABANDONED", "challenge_upheld": False},
    ]


def _trace_verdict_lapsed() -> list[dict]:
    return [
        {"event": "accepted", "at": T[0], "object": H["vtc"]},
        {"event": "funded", "at": T[0]},
        {"event": "delivered", "at": T[1], "object": H["delivery"]},
        {"event": "verdict-lapsed", "at": "2026-11-11T08:30:13Z"},
        {"event": "window-opened", "at": "2026-11-11T08:30:13Z", "closes_at": "2026-11-11T09:30:13Z"},
        {"event": "window-closed", "at": "2026-11-11T09:30:14Z"},
        {"event": "children-final", "at": "2026-11-11T09:30:14Z"},
        {"event": "terminal", "at": "2026-11-11T09:30:14Z", "state": "FINAL", "challenge_upheld": False},
    ]


def _trace_delivery_first() -> list[dict]:
    return [
        {"event": "accepted", "at": T[0], "object": H["vtc"]},
        {"event": "funded", "at": T[0]},
        {"event": "delivered", "at": T[1], "object": H["delivery"]},
        {"event": "window-opened", "at": T[1], "closes_at": "2026-11-10T09:30:12Z"},
        {"event": "window-closed", "at": "2026-11-10T09:30:13Z"},
        {"event": "children-final", "at": "2026-11-10T09:30:13Z"},
        {"event": "terminal", "at": "2026-11-10T09:30:13Z", "state": "FINAL", "challenge_upheld": False},
    ]


def build_vectors(profile: BondedRestitution) -> list[dict]:
    cases = [
        ("FINAL: PASS, window closes, Figure 1", _contract(), _trace_final()),
        ("SETTLED on an upheld Challenge, Figure 5", _contract(), _trace_overturned()),
        ("SETTLED: the Verifier records FAIL", _contract(), _trace_settled_by_verifier()),
        ("ABANDONED: deadline with no Delivery", _contract(), _trace_abandoned()),
        ("SETTLED on an upheld Challenge, basis price",
         _contract(parameters={"restitution_basis": "price"}), _trace_overturned()),
        ("FINAL after verdict-lapsed", _contract(), _trace_verdict_lapsed()),
        ("FINAL under delivery-first, principal at window-closed",
         _contract(flow="delivery-first", parameters={"principal_on": "window-closed"}),
         _trace_delivery_first()),
    ]
    out = []
    for name, contract, trace in cases:
        transfers = profile.schedule(contract, trace)
        ok, why = profile.check(contract, transfers, terminal=True)
        assert ok, f"{name}: {why}"
        out.append({"name": name, "contract": contract, "trace": trace, "transfers": transfers})
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--vectors", action="store_true", help="rewrite vectors.json from the schedule")
    ap.add_argument("--hash", action="store_true", help="print profile_hash and exit")
    args = ap.parse_args()
    profile = BondedRestitution()
    if args.vectors:
        vectors = build_vectors(profile)
        (BUNDLE / "vectors.json").write_text(json.dumps(vectors, indent=2) + "\n")
        profile = BondedRestitution()  # the hash covers the file just written
        print(f"wrote {len(vectors)} vectors; profile_hash {profile.profile_hash}")
        return
    if args.hash:
        print(profile.profile_hash)
        return
    ok, why = profile.reproduces()
    print(f"profile {ID}\nprofile_hash {profile.profile_hash}\nvectors reproduce: {ok} ({why})")


if __name__ == "__main__":
    main()
