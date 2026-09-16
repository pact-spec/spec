"""Measure the reference pair end to end, on the -02 protocol.

Runs the Facilitator in-process on a loopback port with a clock the harness
advances, drives every path of Section 4 with real keys and real signatures,
and reports what each path cost on the wire and what the profile did with it.
Every Outcome Record is checked the way a party would check it: the
Facilitator's signature verifies, the transfer list recomputes from the trace
with the named profile, the invariants of Appendix A.5 hold, and every Status
received along the way is a prefix of the final trace. Where the profile
bundle carries a vector for the path, the run has to reproduce it.

The refusals are the second half of the report: what the Facilitator turns
away, with which problem type, and that a refused request leaves no entry in
any trace.

Run with a venv that has cryptography, jsonschema and referencing:

    python3 tools/measure.py            # the report
    python3 tools/measure.py --json out.json
"""

from __future__ import annotations

import argparse
import json
import pathlib
import platform
import statistics
import sys
import threading
import time
from datetime import datetime, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import agents  # noqa: E402
import facilitator as F  # noqa: E402
import pactcore as pc  # noqa: E402
import profile as terms  # noqa: E402

DAY = 86400
WINDOW = 3600
MAX_DISPUTE = 86400
MAX_VERDICT = 86400


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Clock:
    """The Facilitator's clock, advanced by the harness instead of waited on."""

    def __init__(self) -> None:
        self.t = float(int(time.time()))

    def now(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class Harness:
    def __init__(self, port: int) -> None:
        self.clock = Clock()
        self.fac, self.resolver = F.build(now=self.clock.now, base_url=f"http://127.0.0.1:{port}")
        self.httpd = F.serve(self.fac, port)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.client = agents.Client(f"http://127.0.0.1:{port}")
        mk = lambda did: agents.make_party(did, self.resolver, self.client)  # noqa: E731
        self.buyer = mk("did:web:buyer.example:agents:procure-1")
        self.seller = mk("did:web:dataforge.example:agents:etl-3")
        self.verifier = mk("did:web:audit.example")
        self.sub = mk("did:web:sub.example:agents:worker-7")
        self.other = mk("did:web:other.example")
        # The watcher's kid matches the profile vectors, so an upheld
        # Challenge reproduces the vector's transfer list exactly.
        self.watch = agents.Party("did:web:watch.example",
                                  self.resolver.register(pc.Key.generate("did:web:watch.example#k1")),
                                  self.client)
        self.profile = agents.default_profile()
        self.n = 0

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    # -- building blocks ---------------------------------------------------
    def contract(self, *, verifier: bool = True, sign: bool = True, buyer=None, seller=None,
                 days: float = 7, facilitator: str | None = None, **over) -> dict:
        self.n += 1
        b = buyer or self.buyer
        s = seller or self.seller
        vtc = agents.draft_contract(
            f"vtc_m{self.n:04d}", b.did, s.did, facilitator or self.fac.identity,
            self.verifier.did if verifier else None,
            deadline=iso(self.clock.t + days * DAY), **over)
        return agents.cosign(vtc, b, s) if sign else vtc

    def call(self, fn, obj: dict, expect: int) -> dict:
        code, body = fn(obj)
        if code != expect:
            raise AssertionError(f"expected {expect}, got {code}: {json.dumps(body)[:400]}")
        if body.get("type") == "ContractStatus":
            ok, why = agents.check_status(body, self.resolver, self.fac.identity)
            if not ok:
                raise AssertionError(f"Status signature: {why}")
        return body

    def outcome(self, vtc: dict) -> dict:
        code, out = self.client.outcome(vtc["id"])
        if code != 200:
            raise AssertionError(f"outcome: {code} {json.dumps(out)[:400]}")
        ok, why = agents.check_outcome(out, self.resolver, self.fac.identity)
        if not ok:
            raise AssertionError(f"Outcome Record signature: {why}")
        return out

    def status_of(self, vtc: dict) -> dict:
        return self.call(lambda v: self.client.status(v["id"]), vtc, 200)

    def funded(self, **over) -> dict:
        vtc = self.contract(**over)
        self.call(self.client.propose, vtc, 201)
        return vtc

    def delivered(self, **over) -> tuple[dict, dict]:
        vtc = self.funded(**over)
        d = agents.make_delivery(vtc, self.seller, b"work " + vtc["id"].encode(), b"results")
        self.call(self.client.deliver, d, 202)
        return vtc, d

    def window_open(self, **over) -> tuple[dict, dict, dict]:
        vtc, d = self.delivered(**over)
        v = agents.make_verdict(vtc, d, self.verifier, "PASS")
        self.call(self.client.verdict, v, 201)
        return vtc, d, v

    def disputed(self, **over) -> tuple[dict, dict, dict, dict]:
        vtc, d, v = self.window_open(**over)
        ch = agents.make_challenge(vtc, d, self.watch, ["row_count"], costs="0.50")
        self.call(self.client.challenge, ch, 202)
        return vtc, d, v, ch


# --------------------------------------------------------------------------
# Scenarios: each returns (contract, outcome record, statuses received)
# --------------------------------------------------------------------------

def scenario_final(h: Harness):
    vtc = h.contract()
    st = [h.call(h.client.propose, vtc, 201)]
    d = agents.make_delivery(h_vtc := vtc, h.seller, b"customers-clean.csv", b"results")
    st.append(h.call(h.client.deliver, d, 202))
    st.append(h.call(h.client.verdict, agents.make_verdict(h_vtc, d, h.verifier, "PASS"), 201))
    h.clock.advance(WINDOW + 1)
    return vtc, h.outcome(vtc), st


def scenario_settled(h: Harness):
    vtc = h.contract()
    st = [h.call(h.client.propose, vtc, 201)]
    d = agents.make_delivery(vtc, h.seller, b"customers-broken.csv", b"results")
    st.append(h.call(h.client.deliver, d, 202))
    st.append(h.call(h.client.verdict, agents.make_verdict(vtc, d, h.verifier, "FAIL"), 201))
    return vtc, h.outcome(vtc), st


def scenario_abandoned(h: Harness):
    vtc = h.contract(days=1)
    st = [h.call(h.client.propose, vtc, 201)]
    h.clock.advance(DAY + 1)
    return vtc, h.outcome(vtc), st


def scenario_overturned(h: Harness, **over):
    vtc = h.contract(**over)
    st = [h.call(h.client.propose, vtc, 201)]
    d = agents.make_delivery(vtc, h.seller, b"customers-subtle.csv", b"results")
    st.append(h.call(h.client.deliver, d, 202))
    st.append(h.call(h.client.verdict, agents.make_verdict(vtc, d, h.verifier, "PASS"), 201))
    ch = agents.make_challenge(vtc, d, h.watch, ["row_count"], costs="0.50")
    st.append(h.call(h.client.challenge, ch, 202))
    st.append(h.call(h.client.verdict, agents.make_verdict(vtc, d, h.verifier, "FAIL", ch), 201))
    return vtc, h.outcome(vtc), st


def scenario_verdict_lapsed(h: Harness):
    vtc = h.contract()
    st = [h.call(h.client.propose, vtc, 201)]
    d = agents.make_delivery(vtc, h.seller, b"customers-late.csv", b"results")
    st.append(h.call(h.client.deliver, d, 202))
    h.clock.advance(MAX_VERDICT + 1)
    st.append(h.status_of(vtc))
    assert st[-1]["state"] == "WINDOW_OPEN", st[-1]["state"]
    h.clock.advance(WINDOW + 1)
    return vtc, h.outcome(vtc), st


def scenario_delivery_first(h: Harness):
    vtc = h.contract(flow="delivery-first", principal_on="window-closed")
    st = [h.call(h.client.propose, vtc, 201)]
    d = agents.make_delivery(vtc, h.seller, b"customers-df.csv", b"results")
    st.append(h.call(h.client.deliver, d, 202))
    assert st[-1]["state"] == "WINDOW_OPEN", st[-1]["state"]
    h.clock.advance(WINDOW + 1)
    return vtc, h.outcome(vtc), st


def scenario_dispute_lapsed(h: Harness):
    vtc = h.contract()
    st = [h.call(h.client.propose, vtc, 201)]
    d = agents.make_delivery(vtc, h.seller, b"customers-dl.csv", b"results")
    st.append(h.call(h.client.deliver, d, 202))
    st.append(h.call(h.client.verdict, agents.make_verdict(vtc, d, h.verifier, "PASS"), 201))
    ch = agents.make_challenge(vtc, d, h.watch, ["row_count"], costs="0.50")
    st.append(h.call(h.client.challenge, ch, 202))
    assert st[-1]["state"] == "DISPUTED"
    h.clock.advance(MAX_DISPUTE + 1)   # longer than the window too
    out = h.outcome(vtc)
    events = [e["event"] for e in out["trace"]]
    assert "dispute-lapsed" in events and out["outcome"]["state"] == "FINAL", events
    return vtc, out, st


def scenario_tree(h: Harness):
    parent = h.contract(days=7)
    st = [h.call(h.client.propose, parent, 201)]
    link = {"vtc_id": parent["id"], "vtc_hash": pc.digest_over(parent),
            "facilitator": h.fac.identity}
    child = h.contract(buyer=h.seller, seller=h.sub, days=1, parent=link)
    st.append(h.call(h.client.propose, child, 201))
    st.append(h.call(lambda c: h.client.register_child(parent["id"], c), child, 201))
    assert st[-1]["trace"][-1]["event"] == "child-registered"
    dc = agents.make_delivery(child, h.sub, b"child work", b"child results")
    st.append(h.call(h.client.deliver, dc, 202))
    st.append(h.call(h.client.verdict, agents.make_verdict(child, dc, h.verifier, "PASS"), 201))
    h.clock.advance(WINDOW + 1)
    child_out = h.outcome(child)
    dp = agents.make_delivery(parent, h.seller, b"parent work", b"parent results")
    st.append(h.call(h.client.deliver, dp, 202))
    st.append(h.call(h.client.verdict, agents.make_verdict(parent, dp, h.verifier, "PASS"), 201))
    h.clock.advance(WINDOW + 1)
    out = h.outcome(parent)
    root = "sha256:" + pc.mth([bytes.fromhex(pc.digest_over(child_out)[7:])]).hex()
    assert out.get("children_merkle_root") == root, "children_merkle_root does not recompute"
    assert [e["event"] for e in out["trace"]].count("child-final") == 1
    return parent, out, st


def scenario_tree_unresolved(h: Harness):
    """A child registered from another venue that never reports: the parent
    waits until L(child) and then closes with child-unresolved."""
    parent = h.contract(days=7)
    st = [h.call(h.client.propose, parent, 201)]
    link = {"vtc_id": parent["id"], "vtc_hash": pc.digest_over(parent),
            "facilitator": h.fac.identity}
    child = h.contract(buyer=h.seller, seller=h.sub, days=1, parent=link,
                       facilitator=h.other.did)
    st.append(h.call(lambda c: h.client.register_child(parent["id"], c), child, 201))
    dp = agents.make_delivery(parent, h.seller, b"parent work 2", b"parent results")
    st.append(h.call(h.client.deliver, dp, 202))
    st.append(h.call(h.client.verdict, agents.make_verdict(parent, dp, h.verifier, "PASS"), 201))
    h.clock.advance(WINDOW + 1)
    st.append(h.status_of(parent))
    assert st[-1]["state"] == "AWAITING_CHILDREN", st[-1]["state"]
    h.clock.advance(F.latest_finality(child) - h.clock.t + 1)
    out = h.outcome(parent)
    events = [e["event"] for e in out["trace"]]
    empty_root = "sha256:" + pc.mth([]).hex()   # Section 12.2: D empty, the member present
    assert "child-unresolved" in events and out.get("children_merkle_root") == empty_root, events
    return parent, out, st


SCENARIOS = [
    ("FINAL (verdict-first, PASS, window closes)", scenario_final, "FINAL: PASS"),
    ("SETTLED (the Verifier records FAIL)", scenario_settled, "SETTLED: the Verifier"),
    ("ABANDONED (deadline, no Delivery)", scenario_abandoned, "ABANDONED"),
    ("SETTLED (PASS overturned by a Challenge)", scenario_overturned, "SETTLED on an upheld Challenge, Figure"),
    ("SETTLED (overturned, restitution_basis price)",
     lambda h: scenario_overturned(h, restitution_basis="price"), "SETTLED on an upheld Challenge, basis"),
    ("FINAL after verdict-lapsed", scenario_verdict_lapsed, "FINAL after verdict-lapsed"),
    ("FINAL under delivery-first, principal at window-closed", scenario_delivery_first,
     "FINAL under delivery-first"),
    ("FINAL after dispute-lapsed (the PASS stands)", scenario_dispute_lapsed, None),
    ("FINAL with one child, in-venue (Merkle root)", scenario_tree, None),
    ("FINAL with one child unresolved at L(child)", scenario_tree_unresolved, None),
]


def run_scenario(h: Harness, name: str, fn, vector: str | None) -> dict:
    start = len(h.client.wire)
    t0 = time.perf_counter()
    vtc, out, statuses = fn(h)
    ms = (time.perf_counter() - t0) * 1000
    wire = h.client.wire[start:]
    prof = h.profile
    transfers = out["terms_result"]["transfers"]
    assert prof.schedule(vtc, out["trace"]) == transfers, f"{name}: transfers do not recompute"
    ok, why = prof.check(vtc, transfers, terminal=True)
    assert ok, f"{name}: {why}"
    for s in statuses:
        if s["vtc_id"] == vtc["id"]:
            assert agents.prefix_of(s["trace"], out["trace"]), f"{name}: a Status was not a prefix"
    last = out["trace"][-1]
    assert last["event"] == "terminal" and last["state"] == out["outcome"]["state"]
    match = None
    if vector is not None:
        vec = next(v for v in prof.vectors() if v["name"].startswith(vector))
        match = ([e["event"] for e in vec["trace"]] == [e["event"] for e in out["trace"]]
                 and vec["transfers"] == transfers)
        assert match, f"{name}: does not reproduce the profile vector {vec['name']!r}"
    by_code: dict[str, str] = {}
    for t in transfers:
        if t["code"] in ("principal", "reverse", "restitution", "costs", "bounty", "remainder"):
            by_code[t["code"]] = t["amount"]
    return {
        "name": name, "state": out["outcome"]["state"],
        "challenge_upheld": out["outcome"]["challenge_upheld"],
        "exchanges": len(wire),
        "bytes_out": sum(w.request_bytes for w in wire),
        "bytes_back": sum(w.response_bytes for w in wire),
        "ms": round(ms, 1),
        "messages": [(w.method, w.path.rsplit("/", 1)[-1] if w.method == "GET" else w.path.split("/pact/v2/")[-1],
                      w.status, w.request_bytes, w.response_bytes) for w in wire],
        "events": [e["event"] for e in out["trace"]],
        "transfers": transfers, "summary": by_code,
        "vector": vector, "vector_reproduced": match,
    }


# --------------------------------------------------------------------------
# Refusals: (name, expected status, expected problem kind, profile problem?)
# --------------------------------------------------------------------------

def refusals(h: Harness) -> list[tuple[str, int, str, bool, object]]:
    c = h.client
    P = agents.Party

    def alg_none_contract():
        vtc = h.contract(sign=False)
        header = pc.b64u(json.dumps({"alg": "none", "kid": h.buyer.key.kid,
                                     "typ": agents.MEDIA_CONTRACT}).encode())
        vtc["signatures"] = agents.sort_signatures([
            {"protected": header, "signature": ""},
            pc.sign(vtc, h.seller.key, agents.MEDIA_CONTRACT)])
        return c.propose(vtc)

    def third_party_signature():
        vtc = h.contract(sign=False)
        return c.propose(agents.cosign(vtc, h.buyer, h.seller, h.watch))

    def unsorted():
        vtc = h.contract()
        vtc["signatures"] = list(reversed(vtc["signatures"]))
        return c.propose(vtc)

    def altered_same_id():
        vtc = h.funded()
        again = agents.cosign({k: v for k, v in vtc.items() if k != "signatures"} | {
            "task": dict(vtc["task"], spec_uri="https://buyer.example/specs/other.json")},
            h.buyer, h.seller)
        return c.propose(again)

    def lookalike_delivery():
        vtc = h.funded()
        evil = agents.make_party("did:web:dataforge.example.evil:agents:etl-3", h.resolver, c)
        return c.deliver(agents.make_delivery(vtc, evil, b"w", b"r"))

    def delivery_without_evidence():
        vtc = h.funded()
        d = agents.make_delivery(vtc, h.seller, b"w", b"r")
        d.pop("evidence")
        d.pop("signature")
        return c.deliver(h.seller.sign_into(d, agents.MEDIA_DELIVERY))

    def delivery_without_input_hash():
        vtc = h.funded()
        d = agents.make_delivery(vtc, h.seller, b"w", b"r")
        d.pop("input_hash")
        d.pop("signature")
        return c.deliver(h.seller.sign_into(d, agents.MEDIA_DELIVERY))

    def second_delivery():
        vtc, d = h.delivered()
        return c.deliver(agents.make_delivery(vtc, h.seller, b"another", b"r"))

    def verdict_without_delivery():
        vtc = h.funded()
        fake = agents.make_delivery(vtc, h.seller, b"never posted", b"r")
        return c.verdict(agents.make_verdict(vtc, fake, h.verifier, "PASS"))

    def verdict_by_seller():
        vtc, d = h.delivered()
        return c.verdict(agents.make_verdict(vtc, d, h.seller, "PASS"))

    def verdict_by_facilitator():
        vtc, d = h.delivered(verifier=False)
        fp = P(h.fac.identity, h.fac.key, c)
        return c.verdict(agents.make_verdict(vtc, d, fp, "PASS"))

    def verdict_by_unnamed_party():
        vtc, d = h.delivered()
        return c.verdict(agents.make_verdict(vtc, d, h.watch, "PASS"))

    def verdict_other_instrument():
        vtc, d = h.delivered()
        v = agents.make_verdict(vtc, d, h.verifier, "PASS")
        v["instrument_hash"] = pc.h(b"another instrument")
        v.pop("signature")
        return c.verdict(h.verifier.sign_into(v, agents.MEDIA_VERDICT))

    def verdict_wrong_delivery_hash():
        vtc, d = h.delivered()
        v = agents.make_verdict(vtc, d, h.verifier, "PASS")
        v["delivery_hash"] = pc.digest_over({k: x for k, x in d.items() if k != "signature"})
        v.pop("signature")
        return c.verdict(h.verifier.sign_into(v, agents.MEDIA_VERDICT))

    def verdict_with_delivery_typ():
        vtc, d = h.delivered()
        v = agents.make_verdict(vtc, d, h.verifier, "PASS")
        v.pop("signature")
        return c.verdict(h.verifier.sign_into(v, agents.MEDIA_DELIVERY))

    def challenge_before_window():
        vtc, d = h.delivered()
        return c.challenge(agents.make_challenge(vtc, d, h.watch, ["x"]))

    def challenge_by_seller():
        vtc, d, _ = h.window_open()
        return c.challenge(agents.make_challenge(vtc, d, h.seller, ["x"]))

    def challenge_nonconformant():
        vtc, d, _ = h.window_open()
        ch = agents.make_challenge(vtc, d, h.watch, ["x"])
        ch["proof"]["instrument_hash"] = pc.h(b"other")
        ch.pop("signature")
        return c.challenge(h.watch.sign_into(ch, agents.MEDIA_CHALLENGE))

    def verdict_by_the_challenger():
        vtc, d, v, ch = h.disputed(verifier=False)
        return c.verdict(agents.make_verdict(vtc, d, h.watch, "FAIL", ch))

    def verdict_in_disputed_without_challenge_hash():
        vtc, d, v, ch = h.disputed()
        return c.verdict(agents.make_verdict(vtc, d, h.verifier, "FAIL"))

    def challenge_after_window():
        vtc, d, _ = h.window_open()
        h.clock.advance(WINDOW + 1)
        return c.challenge(agents.make_challenge(vtc, d, h.watch, ["x"]))

    def verdict_after_terminal():
        vtc, d, _ = h.window_open()
        h.clock.advance(WINDOW + 1)
        h.outcome(vtc)
        return c.verdict(agents.make_verdict(vtc, d, h.verifier, "FAIL"))

    def child_wrong_buyer():
        parent = h.funded()
        link = {"vtc_id": parent["id"], "vtc_hash": pc.digest_over(parent),
                "facilitator": h.fac.identity}
        child = h.contract(buyer=h.buyer, seller=h.sub, days=1, parent=link)
        return c.register_child(parent["id"], child)

    def child_timing():
        parent = h.funded(days=1)
        link = {"vtc_id": parent["id"], "vtc_hash": pc.digest_over(parent),
                "facilitator": h.fac.identity}
        child = h.contract(buyer=h.seller, seller=h.sub, days=1, parent=link)
        return c.register_child(parent["id"], child)

    def child_outcome_wrong_hash():
        parent = h.funded()
        link = {"vtc_id": parent["id"], "vtc_hash": pc.digest_over(parent),
                "facilitator": h.fac.identity}
        child = h.contract(buyer=h.seller, seller=h.sub, days=1, parent=link,
                           facilitator=h.other.did)
        h.call(lambda x: c.register_child(parent["id"], x), child, 201)
        record = {
            "pact": "0.2", "type": "OutcomeRecord", "vtc_id": child["id"],
            "vtc_hash": pc.h(b"not the child"), "parties": child["parties"],
            "outcome": {"state": "FINAL", "challenge_upheld": False},
            "trace": [{"event": "accepted", "at": iso(h.clock.t), "object": pc.h(b"x")},
                      {"event": "terminal", "at": iso(h.clock.t), "state": "FINAL",
                       "challenge_upheld": False}],
            "terms_result": {"profile": terms.ID, "profile_hash": h.profile.profile_hash,
                             "currency": "USDC", "transfers": []},
        }
        record["signatures"] = [pc.sign(record, h.other.key, agents.MEDIA_OUTCOME)]
        return c.supply_child_outcome(parent["id"], child["id"], record)

    return [
        # propose
        ("bond below the assurance constraint (q_min 0.5)", 422, "assurance-constraint-unsatisfied", True,
         lambda: c.propose(h.contract(q_min=0.5))),
        ("bond above cap", 422, "parameters-inconsistent", True,
         lambda: c.propose(h.contract(bond="200.00"))),
        ("window_seconds 0", 422, "schema-invalid", False,
         lambda: c.propose(h.contract(window_seconds=0))),
        ("undefined member in the contract", 422, "schema-invalid", False,
         lambda: c.propose(agents.cosign(h.contract(sign=False) | {"bonus": True}, h.buyer, h.seller))),
        ("buyer equals seller", 422, "parties-not-distinct", False,
         lambda: c.propose(h.contract(buyer=h.seller, seller=h.seller))),
        ("price with three decimals", 422, "amount-invalid", False,
         lambda: c.propose(h.contract(price="180.005", bond="18.00"))),
        ("deadline already past", 422, "deadline-invalid", False,
         lambda: c.propose(h.contract(days=-1))),
        ("another Facilitator named", 422, "facilitator-mismatch", False,
         lambda: c.propose(h.contract(facilitator="did:web:elsewhere.example"))),
        ("named verifier is the seller", 422, "verifier-not-independent", False,
         lambda: c.propose(agents.cosign(h.contract(sign=False) | {
             "parties": dict(h.contract(sign=False)["parties"], verifier=h.seller.did)}, h.buyer, h.seller))),
        ("settlement binding not advertised", 422, "settlement-unsupported", False,
         lambda: c.propose(h.contract(settlement="https://elsewhere.example/bindings/x"))),
        ("flow no-window not implemented", 422, "flow-unsupported", False,
         lambda: c.propose(h.contract(flow="no-window", principal_on="delivered", bond="200.00", price="180.00")
                           if False else h.contract(flow="no-window", principal_on="delivered"))),
        ("terms profile_hash not advertised", 422, "terms-unsupported", False,
         lambda: c.propose(h.contract(profile_hash=pc.h(b"other bundle")))),
        ("terms parameters fail the profile schema", 422, "terms-parameters-invalid", False,
         lambda: c.propose(h.contract(bond="eighteen"))),
        ("contract signed with alg none", 400, "algorithm-not-permitted", False, alg_none_contract),
        ("a third party co-signs the contract", 422, "unexpected-signer", False, third_party_signature),
        ("signature set out of order", 422, "signatures-unordered", False, unsorted),
        ("same id, different contract", 409, "object-conflict", False, altered_same_id),
        # delivery
        ("Delivery signed by a lookalike seller", 422, "unexpected-signer", False, lookalike_delivery),
        ("Delivery without evidence", 422, "evidence-nonconformant", False, delivery_without_evidence),
        ("Delivery without input_hash under T0-reexec", 422, "evidence-nonconformant", False,
         delivery_without_input_hash),
        ("second Delivery in DELIVERED", 409, "wrong-state", False, second_delivery),
        # verdict
        ("Verdict with no recorded Delivery", 409, "no-recorded-delivery", False, verdict_without_delivery),
        ("Verdict signed by the seller", 422, "verifier-not-independent", False, verdict_by_seller),
        ("Verdict signed by the Facilitator", 422, "verifier-not-independent", False, verdict_by_facilitator),
        ("Verdict by a party the contract does not name", 422, "verifier-not-independent", False,
         verdict_by_unnamed_party),
        ("Verdict over another instrument", 422, "verdict-nonconformant", False, verdict_other_instrument),
        ("Verdict whose delivery_hash omits the signature", 422, "verdict-nonconformant", False,
         verdict_wrong_delivery_hash),
        ("Verdict signed with the Delivery typ", 401, "signature-invalid", False, verdict_with_delivery_typ),
        ("Verdict in DISPUTED without challenge_hash", 422, "verdict-nonconformant", False,
         verdict_in_disputed_without_challenge_hash),
        ("Verdict by the Challenger it answers", 422, "verifier-not-independent", False,
         verdict_by_the_challenger),
        ("Verdict after the terminal entry", 409, "wrong-state", False, verdict_after_terminal),
        # challenge
        ("Challenge before the window opens", 409, "challenge-window-closed", False, challenge_before_window),
        ("Challenge after the window closes", 409, "challenge-window-closed", False, challenge_after_window),
        ("Challenge signed by the seller", 422, "unexpected-signer", False, challenge_by_seller),
        ("Challenge whose proof names another instrument", 422, "proof-nonconformant", False,
         challenge_nonconformant),
        # trees
        ("child whose Buyer is not the parent's Seller", 422, "parent-unresolvable", False, child_wrong_buyer),
        ("child with L(child) not before L(parent)", 422, "finality-ordering-violation", False, child_timing),
        ("child Outcome Record over the wrong contract", 422, "child-outcome-invalid", False,
         child_outcome_wrong_hash),
        # retrieval
        ("GET an unknown contract", 404, "unknown-contract", False, lambda: c.status("vtc_nobody")),
        ("GET the Outcome Record before the terminal entry", 409, "wrong-state", False,
         lambda: c.outcome(h.funded()["id"])),
    ]


def acceptances(h: Harness) -> list[tuple[str, object]]:
    c = h.client

    def challenge_alone_does_not_settle():
        vtc, d, v, ch = h.disputed()
        st = h.status_of(vtc)
        return st["state"] == "DISPUTED" and st["trace"][-1]["event"] == "challenge"

    def resubmit_identical_contract():
        vtc = h.funded()
        code, body = c.propose(vtc)
        return code == 200 and body["type"] == "ContractStatus" and body["state"] == "FUNDED"

    def buyer_challenge_admissible():
        vtc, d, _ = h.window_open()
        code, body = c.challenge(agents.make_challenge(vtc, d, h.buyer, ["x"], costs=None))
        return code == 202 and body["state"] == "DISPUTED"

    def refusal_leaves_no_entry():
        vtc, d = h.delivered()
        before = h.status_of(vtc)["trace"]
        code, _ = c.verdict(agents.make_verdict(vtc, d, h.seller, "PASS"))
        after = h.status_of(vtc)["trace"]
        return code == 422 and before == after

    def pass_in_window_changes_nothing():
        vtc, d, v = h.window_open()
        again = agents.make_verdict(vtc, d, h.verifier, "PASS")
        again["evaluated_at"] = "2099-01-01T00:00:00Z"   # different bytes, or it is a replay
        again.pop("signature")
        code, body = c.verdict(h.verifier.sign_into(again, agents.MEDIA_VERDICT))
        return code == 201 and body["state"] == "WINDOW_OPEN" and body["trace"][-1]["supersedes"] == pc.digest_over(v)

    return [
        ("a Challenge alone settles nothing", challenge_alone_does_not_settle),
        ("resubmitting an identical contract returns 200 and the current Status",
         resubmit_identical_contract),
        ("a Buyer's Challenge is admissible", buyer_challenge_admissible),
        ("a refused request leaves no entry in the trace", refusal_leaves_no_entry),
        ("a second PASS inside the window changes the state of nothing",
         pass_in_window_changes_nothing),
    ]


def run_refusals(h: Harness) -> tuple[list[dict], list[dict]]:
    rows = []
    for name, status, kind, is_profile, fn in refusals(h):
        code, body = fn()
        base = terms.PROBLEM_BASE if is_profile else F.PROBLEM_BASE
        where = body.get("profile_section") if is_profile else body.get("section")
        ok = (code == status and body.get("type") == base + kind and bool(where)
              and (not is_profile or body.get("profile") == terms.ID))
        rows.append({"name": name, "expected": (status, kind), "got": (code, body.get("type", "?")),
                     "section": where, "ok": ok})
    accepted = []
    for name, fn in acceptances(h):
        accepted.append({"name": name, "ok": bool(fn())})
    return rows, accepted


# --------------------------------------------------------------------------
# Capability document and micro-benchmarks
# --------------------------------------------------------------------------

def run_capability(h: Harness) -> dict:
    code, doc = h.client.capability()
    ok, why = pc.verify_object(doc, h.resolver, agents.MEDIA_FACILITATOR, [h.fac.identity])
    assert code == 200 and ok, why
    listed = [p["profile_hash"] for p in doc["terms_profiles"]]
    return {"signed": ok, "flows": doc["flows"], "terms_profiles": doc["terms_profiles"],
            "bytes": len(json.dumps(doc, separators=(",", ":"))),
            "advertised_profile_reproduces": h.profile.profile_hash in listed}


def bench(fn, n: int) -> float:
    times = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t)
    return statistics.median(times) * 1e6


def run_micro(h: Harness) -> dict:
    vtc = h.contract()
    d = agents.make_delivery(vtc, h.seller, b"w", b"r")
    v = agents.make_verdict(vtc, d, h.verifier, "PASS")
    signable = pc.signable(v)
    vec = h.profile.vectors()[1]
    leaves = [bytes.fromhex(pc.h(str(i).encode())[7:]) for i in range(64)]
    return {
        "canonicalize contract (us)": bench(lambda: pc.jcs(vtc), 2000),
        "canonicalize + digest (us)": bench(lambda: pc.digest_over(vtc), 2000),
        "sign Verdict, Ed25519, incl. canonicalization (us)":
            bench(lambda: pc.sign(signable, h.verifier.key, agents.MEDIA_VERDICT), 500),
        "verify Verdict end to end (us)":
            bench(lambda: pc.verify_object(v, h.resolver, agents.MEDIA_VERDICT, [h.verifier.did]), 500),
        "normalize identifier (us)": bench(lambda: pc.norm("did:web:Buyer.example:agents:procure-1#k1"), 5000),
        "profile schedule over the overturned trace (us)":
            bench(lambda: h.profile.schedule(vec["contract"] | vtc, vec["trace"]), 500),
        "schema-validate a contract (us)": bench(lambda: h.fac.schemas.check(vtc, "vtc.schema.json"), 200),
        "RFC 9162 root, 2 leaves (us)": bench(lambda: pc.mth(leaves[:2]), 2000),
        "RFC 9162 root, 8 leaves (us)": bench(lambda: pc.mth(leaves[:8]), 2000),
        "RFC 9162 root, 64 leaves (us)": bench(lambda: pc.mth(leaves), 500),
    }


# --------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8412)
    ap.add_argument("--json", type=pathlib.Path, help="write the full result here")
    args = ap.parse_args()
    h = Harness(args.port)
    try:
        scenarios = [run_scenario(h, name, fn, vec) for name, fn, vec in SCENARIOS]
        refused, accepted = run_refusals(h)
        cap = run_capability(h)
        micro = run_micro(h)
    finally:
        h.close()

    hw = f"{platform.machine()}, {platform.system()} {platform.release()}, Python {platform.python_version()}"
    print(f"reference pair, draft-laxsharma-pact-02; {hw}; loopback, in-memory, clock advanced by the harness")
    print(f"terms profile {terms.ID}\n  profile_hash {h.profile.profile_hash}\n")
    print("PATHS")
    print(f"  {'path':58} {'exch':>4} {'out':>6} {'back':>6} {'ms':>6}  state / value moved")
    for s in scenarios:
        summary = ", ".join(f"{k} {v}" for k, v in s["summary"].items()) or "none"
        vec = "" if s["vector_reproduced"] is None else ("  [vector reproduced]" if s["vector_reproduced"] else "  [VECTOR MISMATCH]")
        print(f"  {s['name']:58} {s['exchanges']:4d} {s['bytes_out']:6d} {s['bytes_back']:6d} {s['ms']:6.1f}  "
              f"{s['state']}{' upheld' if s['challenge_upheld'] else ''}: {summary}{vec}")
    print("\n  every Outcome Record: Facilitator signature verifies; transfers recompute from the trace with the")
    print("  named profile; no-overdraft and closure hold; every Status received is a prefix of the final trace.")
    for s in scenarios[:1] + scenarios[3:4]:
        print(f"\n  messages, {s['name']}:")
        for m in s["messages"]:
            print(f"    {m[0]:4} {m[1]:34} {m[2]}  {m[3]:5d} out  {m[4]:5d} back")
    print("\nREFUSALS")
    bad = 0
    for r in refused:
        flag = "ok " if r["ok"] else "BAD"
        bad += not r["ok"]
        print(f"  {flag} {r['name']:56} {r['got'][0]} {r['got'][1].rsplit(':', 1)[-1]:36} section {r['section']}")
    print(f"  {len(refused)} refusals, {bad} wrong")
    print("\nACCEPTANCES")
    for a in accepted:
        print(f"  {'ok ' if a['ok'] else 'BAD'} {a['name']}")
        bad += not a["ok"]
    print("\nCAPABILITY DOCUMENT")
    print(f"  signed: {cap['signed']}; flows {cap['flows']}; {len(cap['terms_profiles'])} terms profile(s), "
          f"advertised profile reproduces its vectors: {cap['advertised_profile_reproduces']}; {cap['bytes']} bytes")
    print("\nMICRO (median)")
    for k, v in micro.items():
        print(f"  {k:56} {v:8.1f}")
    if args.json:
        args.json.write_text(json.dumps({
            "hardware": hw, "profile": terms.ID, "profile_hash": h.profile.profile_hash,
            "scenarios": scenarios, "refusals": refused, "acceptances": accepted,
            "capability": cap, "micro": micro}, indent=1))
        print(f"\nwrote {args.json}")
    if bad:
        print(f"\n{bad} check(s) failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
