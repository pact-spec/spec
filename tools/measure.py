"""Measure the reference pair end to end, on the -02 protocol.

Runs the Facilitator in-process on a loopback port with a clock the harness
advances, drives every path of Section 4 with real keys and real signatures,
and reports what each path cost on the wire and what the profile did with it.
Every Outcome Record is checked the way a party would check it: the
Facilitator's signature verifies, the transfer list recomputes from the trace
with the named profile, the invariants of Appendix A.5 hold, and every Status
received along the way is a prefix of the final trace. Where the profile
bundle carries a vector for the path, the run has to reproduce it. One path
puts a child at a second venue: another Facilitator, on a port of its own,
runs the child, and the child's Outcome Record reaches the parent by POST.

The refusals are the second half of the report: what the Facilitator turns
away, with which problem type and the section stating the rule it broke, and
that a refused request leaves no entry in any trace.

Run with a venv that has cryptography, jsonschema and referencing:

    python3 tools/measure.py            # the report
    python3 tools/measure.py --json out.json
"""

from __future__ import annotations

import argparse
import http.client
import json
import pathlib
import platform
import re
import socket
import statistics
import sys
import threading
import time
import urllib.parse
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
        self.port = port
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
        # A second venue: another reference Facilitator under the identity and key of
        # self.other, on a loopback port of its own, on the same clock and key resolver.
        # Its exchanges are recorded with the first venue's, so a path counts both.
        self.venue2 = F.Facilitator(self.other.did, self.other.key, self.resolver, now=self.clock.now)
        self.httpd2 = F.serve(self.venue2, 0)
        self.venue2.base_url = f"http://127.0.0.1:{self.httpd2.server_address[1]}"
        threading.Thread(target=self.httpd2.serve_forever, daemon=True).start()
        self.client2 = agents.Client(self.venue2.base_url)
        self.client2.wire = self.client.wire
        # The watcher's kid matches the profile vectors, so an upheld
        # Challenge reproduces the vector's transfer list exactly.
        self.watch = agents.Party("did:web:watch.example",
                                  self.resolver.register(pc.Key.generate("did:web:watch.example#k1")),
                                  self.client)
        self.profile = agents.default_profile()
        self.n = 0

    def close(self) -> None:
        for httpd in (self.httpd, self.httpd2):
            httpd.shutdown()
            httpd.server_close()

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

    def call(self, fn, obj: dict, expect: int, facilitator: str | None = None) -> dict:
        code, body = fn(obj)
        if code != expect:
            raise AssertionError(f"expected {expect}, got {code}: {json.dumps(body)[:400]}")
        w = self.client.wire[-1]
        if code == 201 and w.method == "POST" and w.path == f"{agents.BASE_PATH}/contracts":
            # Section 13: the contract is the resource the Location header names (audit A6)
            if w.location != F.contract_path(body["vtc_id"]):
                raise AssertionError(f"contract 201: Location {w.location!r}, "
                                     f"expected {F.contract_path(body['vtc_id'])!r}")
        if body.get("type") == "ContractStatus":
            ok, why = agents.check_status(body, self.resolver, facilitator or self.fac.identity)
            if not ok:
                raise AssertionError(f"Status signature: {why}")
        return body

    def outcome(self, vtc: dict, client: agents.Client | None = None, facilitator: str | None = None) -> dict:
        code, out = (client or self.client).outcome(vtc["id"])
        if code != 200:
            raise AssertionError(f"outcome: {code} {json.dumps(out)[:400]}")
        ok, why = agents.check_outcome(out, self.resolver, facilitator or self.fac.identity, vtc)
        if not ok:
            raise AssertionError(f"Outcome Record signature: {why}")
        if self.profile.schedule(vtc, out["trace"]) != out["terms_result"]["transfers"]:
            raise AssertionError("Outcome Record: the transfers do not recompute from its trace")
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


def scenario_fee(fund: str):
    """Audit A4: a verifier fee of 0.105 against a fund of 0.51 or 0.50. The
    -02 code signed 0.10 and 0.40 for both; with 0.51 the list then broke
    closure and every later call on the contract answered internal-error."""
    def run(h: Harness):
        vtc = h.contract(fund=fund, verifier_fee="0.105")
        st = [h.call(h.client.propose, vtc, 201)]
        d = agents.make_delivery(vtc, h.seller, b"customers-fee-" + fund.encode(), b"results")
        st.append(h.call(h.client.deliver, d, 202))
        st.append(h.call(h.client.verdict, agents.make_verdict(vtc, d, h.verifier, "PASS"), 201))
        h.clock.advance(WINDOW + 1)
        return vtc, h.outcome(vtc), st
    return run


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


def scenario_tree_second_venue(h: Harness):
    """A child at a second venue: its own Facilitator runs it to FINAL, and its
    Outcome Record is supplied to the parent's Facilitator by POST (Section 10.2),
    which records child-final and closes the parent over it."""
    parent = h.contract(days=7)
    st = [h.call(h.client.propose, parent, 201)]
    link = {"vtc_id": parent["id"], "vtc_hash": pc.digest_over(parent),
            "facilitator": h.fac.identity}
    v2 = h.venue2.identity
    child = h.contract(buyer=h.seller, seller=h.sub, days=1, parent=link, facilitator=v2)
    st.append(h.call(h.client2.propose, child, 201, v2))
    st.append(h.call(lambda c: h.client.register_child(parent["id"], c), child, 201))
    dc = agents.make_delivery(child, h.sub, b"child work, second venue", b"child results")
    st.append(h.call(h.client2.deliver, dc, 202, v2))
    st.append(h.call(h.client2.verdict, agents.make_verdict(child, dc, h.verifier, "PASS"), 201, v2))
    h.clock.advance(WINDOW + 1)
    child_out = h.outcome(child, h.client2, v2)
    st.append(h.call(lambda r: h.client.supply_child_outcome(parent["id"], pc.digest_over(child), r),
                     child_out, 200))
    last = st[-1]["trace"][-1]
    assert last["event"] == "child-final" and last["object"] == pc.digest_over(child_out), last
    dp = agents.make_delivery(parent, h.seller, b"parent work 4", b"parent results")
    st.append(h.call(h.client.deliver, dp, 202))
    st.append(h.call(h.client.verdict, agents.make_verdict(parent, dp, h.verifier, "PASS"), 201))
    h.clock.advance(WINDOW + 1)
    out = h.outcome(parent)
    events = [e["event"] for e in out["trace"]]
    root = "sha256:" + pc.mth([bytes.fromhex(pc.digest_over(child_out)[7:])]).hex()
    assert (out.get("children_merkle_root") == root and events.count("child-final") == 1
            and "child-unresolved" not in events), events
    return parent, out, st


SCENARIOS = [
    ("FINAL (verdict-first, PASS, window closes)", scenario_final, "FINAL: PASS"),
    ("SETTLED (the Verifier records FAIL)", scenario_settled, "SETTLED: the Verifier"),
    ("ABANDONED (deadline, no Delivery)", scenario_abandoned, "ABANDONED"),
    ("SETTLED (PASS overturned by a Challenge)", scenario_overturned, "SETTLED on an upheld Challenge (the"),
    ("SETTLED (overturned, restitution_basis price)",
     lambda h: scenario_overturned(h, restitution_basis="price"), "SETTLED on an upheld Challenge, basis"),
    ("FINAL after verdict-lapsed", scenario_verdict_lapsed, "FINAL after verdict-lapsed"),
    ("FINAL under delivery-first, principal at window-closed", scenario_delivery_first,
     "FINAL under delivery-first"),
    ("FINAL with a verifier fee of 0.105, fund 0.51", scenario_fee("0.51"),
     "FINAL with a verifier fee of 0.105, fund 0.51"),
    ("FINAL with a verifier fee of 0.105, fund 0.50", scenario_fee("0.50"),
     "FINAL with a verifier fee of 0.105, fund 0.50"),
    ("FINAL after dispute-lapsed (the PASS stands)", scenario_dispute_lapsed, None),
    ("FINAL with one child, in-venue (Merkle root)", scenario_tree, None),
    ("FINAL with one child unresolved at L(child)", scenario_tree_unresolved, None),
    ("FINAL with one child at a second venue (record by POST)", scenario_tree_second_venue, None),
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
        # a child's digest in a path differs on every run (fresh keys), so it is named, not printed
        "messages": [(w.method, w.path.rsplit("/", 1)[-1] if w.method == "GET"
                      else re.sub(r"/children/sha256:[0-9a-f]{64}$", "/children/{child_hash}",
                                  w.path.split("/pact/v2/")[-1]),
                      w.status, w.request_bytes, w.response_bytes) for w in wire],
        "events": [e["event"] for e in out["trace"]],
        # the kind only: a digest here would differ on every run (fresh keys)
        "verdict": out["outcome"]["verdict"] if out["outcome"]["verdict"] in ("none", "verdict-lapsed")
                   else "digest of the standing Verdict",
        "transfers": transfers, "summary": by_code,
        "vector": vector, "vector_reproduced": match,
    }


# --------------------------------------------------------------------------
# Refusals: (name, expected status, expected problem kind, expected section, profile problem?)
# --------------------------------------------------------------------------

def raw_request(port: int, request: bytes, **want: str) -> tuple[int, dict]:
    """One request sent as the bytes given, for what agents.Client cannot send: a
    method other than GET and POST, a Content-Length that is not a length, a
    transfer coding, a request line http.server refuses. Returns the status and
    the problem body; anything else that comes back (an HTML page, a missing
    header in want, no answer within five seconds) is returned as a body whose
    type names it, so the row fails."""
    method = request.split(b" ", 1)[0].decode("latin-1")
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(request)
        resp = http.client.HTTPResponse(s, method=method)
        try:
            resp.begin()
            data = resp.read()
        except (OSError, http.client.HTTPException) as exc:
            return 0, {"type": f"no response ({type(exc).__name__})"}
    return answer(resp, data, want)


def client_post(port: int, path: str, body: bytes, **want: str) -> tuple[int, dict]:
    """A POST sent through http.client, as most clients send one: the whole body
    goes out before the answer is read, and a connection reset meanwhile is an
    exception, so the answer is lost unless the server reads what it is sent
    (RFC 9112 Section 9.6). Returns what raw_request returns."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("POST", path, body=body, headers={"Content-Type": agents.MEDIA_CONTRACT})
        resp = conn.getresponse()
        data = resp.read()
    except (OSError, http.client.HTTPException) as exc:
        return 0, {"type": f"no response ({type(exc).__name__})"}
    finally:
        conn.close()
    return answer(resp, data, want)


def answer(resp: http.client.HTTPResponse, data: bytes, want: dict[str, str]) -> tuple[int, dict]:
    ctype = resp.getheader("Content-Type", "")
    if ctype != "application/problem+json":
        return resp.status, {"type": f"Content-Type {ctype}"}
    for name, value in want.items():
        if resp.getheader(name) != value:
            return resp.status, {"type": f"{name} {resp.getheader(name)!r}, not {value!r}"}
    body = json.loads(data)
    if body.get("type") == "about:blank" and body.get("title") != resp.reason:
        # the status line carries the phrase RFC 9457 Section 4.2.1 makes the title (audit F6)
        return resp.status, {"type": f"status phrase {resp.reason!r}, title {body.get('title')!r}"}
    return resp.status, body


def refusals(h: Harness) -> list[tuple[str, int, str, str | None, bool, object]]:
    c = h.client
    P = agents.Party

    def http_(head: str, body: bytes = b"", **want: str):
        request = head.replace("\n", "\r\n").encode() + b"Host: 127.0.0.1\r\n\r\n" + body
        return lambda: raw_request(h.port, request, **want)

    def alg_none_contract():
        vtc = h.contract(sign=False)
        header = pc.b64u(json.dumps({"alg": "none", "kid": h.buyer.key.kid,
                                     "typ": agents.MEDIA_CONTRACT}).encode())
        vtc["signatures"] = agents.sort_signatures([
            {"protected": header, "signature": ""},
            pc.sign(vtc, h.seller.key, agents.MEDIA_CONTRACT)])
        return c.propose(vtc)

    def jwk_in_header():
        vtc = h.contract()
        entry = vtc["signatures"][0]
        hdr = json.loads(pc.b64u_decode(entry["protected"]))
        hdr["jwk"] = {"kty": "OKP", "crv": "Ed25519", "x": pc.b64u(pc.public_bytes(h.buyer.key))}
        entry["protected"] = pc.b64u(json.dumps(hdr, separators=(",", ":")).encode())
        return c.propose(vtc)

    def second_verdict_no_challenge():
        vtc, d, v = h.window_open()
        again = agents.make_verdict(vtc, d, h.verifier, "FAIL")
        return c.verdict(again)

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

    def delivery_other_instrument():
        vtc = h.funded()
        d = agents.make_delivery(vtc, h.seller, b"w", b"r")
        d["evidence"]["instrument_hash"] = pc.h(b"another instrument")
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

    def verdict_under_kid_with_space():
        vtc, d = h.delivered(verifier=False)
        spaced = agents.make_party(h.seller.did + " ", h.resolver, c)
        return c.verdict(agents.make_verdict(vtc, d, spaced, "PASS"))

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

    def challenge_costs_three_places():
        vtc, d, _ = h.window_open()
        return c.challenge(agents.make_challenge(vtc, d, h.watch, ["x"], costs="1.205"))

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

    def child_outcome_after_terminal():
        parent = h.contract(days=7)
        h.call(c.propose, parent, 201)
        link = {"vtc_id": parent["id"], "vtc_hash": pc.digest_over(parent),
                "facilitator": h.fac.identity}
        child = h.contract(buyer=h.seller, seller=h.sub, days=1, parent=link,
                           facilitator=h.other.did)
        h.call(lambda x: c.register_child(parent["id"], x), child, 201)
        dp = agents.make_delivery(parent, h.seller, b"parent work 3", b"parent results")
        h.call(c.deliver, dp, 202)
        h.call(c.verdict, agents.make_verdict(parent, dp, h.verifier, "PASS"), 201)
        h.clock.advance(WINDOW + 1)
        h.clock.advance(F.latest_finality(child) - h.clock.t + 1)
        h.outcome(parent)   # FINAL, the child recorded unresolved
        record = {
            "pact": "0.3", "type": "OutcomeRecord", "vtc_id": child["id"],
            "vtc_hash": pc.digest_over(child), "parties": child["parties"],
            **pc.outcome_scope(child),
            "outcome": {"state": "FINAL", "challenge_upheld": False, "verdict": "none"},
            "trace": [{"event": "accepted", "at": iso(h.clock.t), "object": pc.digest_over(child)},
                      {"event": "terminal", "at": iso(h.clock.t), "state": "FINAL",
                       "challenge_upheld": False}],
            "terms_result": {"profile": terms.ID, "profile_hash": h.profile.profile_hash,
                             "currency": "USDC", "transfers": []},
        }
        return c.supply_child_outcome(parent["id"], pc.digest_over(child), record)

    # Audit A7: the raise sites of the types that report rules in more than
    # one section and that the refusals above do not reach.
    def contract_deadline_not_a_date():
        vtc = h.contract(sign=False)
        vtc["task"] = dict(vtc["task"], deadline="2027-02-30T00:00:00Z")
        return c.propose(agents.cosign(vtc, h.buyer, h.seller))

    def delivery_other_contract():
        vtc = h.funded()
        d = agents.make_delivery(vtc, h.seller, b"w", b"r")
        d["vtc_hash"] = pc.h(b"another contract")
        d.pop("signature")
        return c.deliver(h.seller.sign_into(d, agents.MEDIA_DELIVERY))

    def challenge_other_delivery():
        vtc, d, _ = h.window_open()
        ch = agents.make_challenge(vtc, d, h.watch, ["x"])
        ch["delivery_hash"] = pc.h(b"another delivery")
        ch.pop("signature")
        return c.challenge(h.watch.sign_into(ch, agents.MEDIA_CHALLENGE))

    def challenge_unresolvable_kid():
        vtc, d, _ = h.window_open()
        ghost = P("did:web:ghost.example", pc.Key.generate("did:web:ghost.example#k1"), c)
        return c.challenge(agents.make_challenge(vtc, d, ghost, ["x"]))

    def child_under_terminal_parent():
        parent = h.funded(days=1)
        h.clock.advance(DAY + 1)
        h.outcome(parent)   # ABANDONED
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
            "pact": "0.3", "type": "OutcomeRecord", "vtc_id": child["id"],
            "vtc_hash": pc.h(b"not the child"), "parties": child["parties"],
            **pc.outcome_scope(child),
            "outcome": {"state": "FINAL", "challenge_upheld": False, "verdict": "none"},
            "trace": [{"event": "accepted", "at": iso(h.clock.t), "object": pc.h(b"x")},
                      {"event": "terminal", "at": iso(h.clock.t), "state": "FINAL",
                       "challenge_upheld": False}],
            "terms_result": {"profile": terms.ID, "profile_hash": h.profile.profile_hash,
                             "currency": "USDC", "transfers": []},
        }
        record["signatures"] = [pc.sign(record, h.other.key, agents.MEDIA_OUTCOME)]
        return c.supply_child_outcome(parent["id"], pc.digest_over(child), record)

    def child_outcome_without_closes_at():
        """Audit A10: a record from the child's own venue, signed by it and
        over the right contract, whose window-opened entry lacks the closes_at
        Table 2 requires. Before the trace entry schema named each event's
        members, the parent recorded it as child-final."""
        parent = h.funded()
        link = {"vtc_id": parent["id"], "vtc_hash": pc.digest_over(parent),
                "facilitator": h.fac.identity}
        child = h.contract(buyer=h.seller, seller=h.sub, days=1, parent=link,
                           facilitator=h.other.did)
        h.call(lambda x: c.register_child(parent["id"], x), child, 201)
        t, verdict = iso(h.clock.t), pc.h(b"a child verdict")
        record = {
            "pact": "0.3", "type": "OutcomeRecord", "vtc_id": child["id"],
            "vtc_hash": pc.digest_over(child), "parties": child["parties"],
            **pc.outcome_scope(child),
            "outcome": {"state": "FINAL", "challenge_upheld": False, "verdict": verdict},
            "work_hash": pc.h(b"child work"),
            "trace": [{"event": "accepted", "at": t, "object": pc.digest_over(child)},
                      {"event": "funded", "at": t},
                      {"event": "delivered", "at": t, "object": pc.h(b"a child delivery")},
                      {"event": "verdict", "at": t, "object": verdict, "signer": h.verifier.key.kid,
                       "outcome": "PASS"},
                      {"event": "window-opened", "at": t},
                      {"event": "window-closed", "at": t},
                      {"event": "children-final", "at": t},
                      {"event": "terminal", "at": t, "state": "FINAL", "challenge_upheld": False}],
            "terms_result": {"profile": terms.ID, "profile_hash": h.profile.profile_hash,
                             "currency": "USDC", "transfers": []},
        }
        record["signatures"] = [pc.sign(record, h.other.key, agents.MEDIA_OUTCOME)]
        return c.supply_child_outcome(parent["id"], pc.digest_over(child), record)

    def child_outcome_other_verification():
        """Section 10.2: a record from the child's own venue, signed by it, over
        the right contract and sound against its own trace, whose verification
        is not the registered child's. Before the parent checked a record
        against the registered child contract, it recorded such a record."""
        parent = h.funded()
        link = {"vtc_id": parent["id"], "vtc_hash": pc.digest_over(parent),
                "facilitator": h.fac.identity}
        child = h.contract(buyer=h.seller, seller=h.sub, days=1, parent=link,
                           facilitator=h.other.did)
        h.call(lambda x: c.register_child(parent["id"], x), child, 201)
        t, verdict = iso(h.clock.t), pc.h(b"a child verdict")
        record = {
            "pact": "0.3", "type": "OutcomeRecord", "vtc_id": child["id"],
            "vtc_hash": pc.digest_over(child), "parties": child["parties"],
            **pc.outcome_scope(child),
            "outcome": {"state": "FINAL", "challenge_upheld": False, "verdict": verdict},
            "work_hash": pc.h(b"child work"),
            "trace": [{"event": "accepted", "at": t, "object": pc.digest_over(child)},
                      {"event": "funded", "at": t},
                      {"event": "delivered", "at": t, "object": pc.h(b"a child delivery")},
                      {"event": "verdict", "at": t, "object": verdict, "signer": h.verifier.key.kid,
                       "outcome": "PASS"},
                      {"event": "window-opened", "at": t, "closes_at": t},
                      {"event": "window-closed", "at": t},
                      {"event": "children-final", "at": t},
                      {"event": "terminal", "at": t, "state": "FINAL", "challenge_upheld": False}],
            "terms_result": {"profile": terms.ID, "profile_hash": h.profile.profile_hash,
                             "currency": "USDC", "transfers": []},
        }
        record["verification"] = dict(record["verification"], tier="T1-tee")
        record["signatures"] = [pc.sign(record, h.other.key, agents.MEDIA_OUTCOME)]
        return c.supply_child_outcome(parent["id"], pc.digest_over(child), record)

    return [
        # propose
        ("bond below the assurance constraint (q_min 0.5)", 422, "assurance-constraint-unsatisfied", "A.4", True,
         lambda: c.propose(h.contract(q_min=0.5))),
        ("bond above cap", 422, "parameters-inconsistent", "A.4", True,
         lambda: c.propose(h.contract(bond="200.00"))),
        ("window_seconds 0", 422, "schema-invalid", "14.2", False,
         lambda: c.propose(h.contract(window_seconds=0))),
        ("undefined member in the contract", 422, "schema-invalid", "14.2", False,
         lambda: c.propose(agents.cosign(h.contract(sign=False) | {"bonus": True}, h.buyer, h.seller))),
        ('contract id ".."', 422, "schema-invalid", "14.2", False,
         lambda: c.propose(agents.cosign(h.contract(sign=False) | {"id": ".."}, h.buyer, h.seller))),
        ("buyer equals seller", 422, "parties-not-distinct", "14.2", False,
         lambda: c.propose(h.contract(buyer=h.seller, seller=h.seller))),
        ("price with three decimals", 422, "amount-invalid", "14.2", False,
         lambda: c.propose(h.contract(price="180.005", bond="18.00"))),
        ("deadline already past", 422, "deadline-invalid", "14.2", False,
         lambda: c.propose(h.contract(days=-1))),
        ("another Facilitator named", 422, "facilitator-mismatch", "13.1", False,
         lambda: c.propose(h.contract(facilitator="did:web:elsewhere.example"))),
        ("named verifier is the seller", 422, "verifier-not-independent", "9.1", False,
         lambda: c.propose(agents.cosign(h.contract(sign=False) | {
             "parties": dict(h.contract(sign=False)["parties"], verifier=h.seller.did)}, h.buyer, h.seller))),
        ("named verifier is the seller, method name upper-cased", 422, "identifier-not-evaluable", "9.1", False,
         lambda: c.propose(agents.cosign(h.contract(sign=False) | {
             "parties": dict(h.contract(sign=False)["parties"], verifier=h.seller.did.replace("did:web", "did:WEB"))},
             h.buyer, h.seller))),
        ("named verifier is the seller with an unreserved escape", 422, "identifier-not-evaluable", "9.1", False,
         lambda: c.propose(agents.cosign(h.contract(sign=False) | {
             "parties": dict(h.contract(sign=False)["parties"], verifier=h.seller.did.replace(":etl", ":%65tl"))},
             h.buyer, h.seller))),
        ("settlement binding not advertised", 422, "settlement-unsupported", "13.1", False,
         lambda: c.propose(h.contract(settlement="https://elsewhere.example/bindings/x"))),
        ("flow no-window not implemented", 422, "flow-unsupported", "7.1", False,
         lambda: c.propose(h.contract(flow="no-window", principal_on="delivered", bond="200.00", price="180.00")
                           if False else h.contract(flow="no-window", principal_on="delivered"))),
        ("terms profile_hash not advertised", 422, "terms-unsupported", "5.3", False,
         lambda: c.propose(h.contract(profile_hash=pc.h(b"other bundle")))),
        ("terms parameters fail the profile schema", 422, "terms-parameters-invalid", "5.3", False,
         lambda: c.propose(h.contract(bond="eighteen"))),
        ("contract signed with alg none", 400, "algorithm-not-permitted", "14.1", False, alg_none_contract),
        ("contract with no signatures", 400, "signature-missing", "14.2", False,
         lambda: c.propose(h.contract(sign=False))),
        ("contract whose protected header embeds a jwk", 400, "signature-invalid", "14.1", False, jwk_in_header),
        ("second Verdict inside the window with no Challenge", 409, "wrong-state", "7.2", False, second_verdict_no_challenge),
        ("Challenge before any Delivery", 409, "challenge-window-closed", "7.3", False,
         lambda: c.challenge(agents.make_challenge(h.funded(), agents.make_delivery(h.contract(), h.seller, b"x", b"y"), h.watch, ["x"]))),
        ("a third party co-signs the contract", 422, "unexpected-signer", "14.2", False, third_party_signature),
        ("signature set out of order", 422, "signatures-unordered", "14.1", False, unsorted),
        ("same id, different contract", 409, "object-conflict", "13.2", False, altered_same_id),
        ("task.deadline on 30 February", 422, "deadline-invalid", "2", False, contract_deadline_not_a_date),
        # delivery
        ("Delivery signed by a lookalike seller", 422, "unexpected-signer", "6", False, lookalike_delivery),
        ("Delivery without evidence", 422, "evidence-nonconformant", "6", False, delivery_without_evidence),
        ("Delivery without input_hash under T0-reexec", 422, "evidence-nonconformant", "6", False,
         delivery_without_input_hash),
        ("Delivery whose evidence names another instrument", 422, "evidence-nonconformant", "6", False,
         delivery_other_instrument),
        ("second Delivery in DELIVERED", 409, "wrong-state", "6", False, second_delivery),
        ("Delivery whose vtc_hash is another contract's", 409, "object-conflict", "6", False,
         delivery_other_contract),
        # verdict
        ("Verdict with no recorded Delivery", 409, "no-recorded-delivery", "7.2", False, verdict_without_delivery),
        ("Verdict signed by the seller", 422, "verifier-not-independent", "7.2", False, verdict_by_seller),
        ("Verdict signed by the Facilitator", 422, "verifier-not-independent", "9.1", False, verdict_by_facilitator),
        ("Verdict under the seller's kid with a space before the fragment", 422, "identifier-not-evaluable", "9.1",
         False, verdict_under_kid_with_space),
        ("Verdict by a party the contract does not name", 422, "verifier-not-independent", "7.2", False,
         verdict_by_unnamed_party),
        ("Verdict over another instrument", 422, "verdict-nonconformant", "7.2", False, verdict_other_instrument),
        ("Verdict whose delivery_hash omits the signature", 422, "verdict-nonconformant", "7.2", False,
         verdict_wrong_delivery_hash),
        ("Verdict signed with the Delivery typ", 400, "signature-invalid", "14.1", False, verdict_with_delivery_typ),
        ("Verdict in DISPUTED without challenge_hash", 422, "verdict-nonconformant", "7.2", False,
         verdict_in_disputed_without_challenge_hash),
        ("Verdict by the Challenger it answers", 422, "verifier-not-independent", "7.3", False,
         verdict_by_the_challenger),
        ("Verdict after the terminal entry", 409, "wrong-state", "7.2", False, verdict_after_terminal),
        # challenge
        ("Challenge before the window opens", 409, "challenge-window-closed", "7.3", False, challenge_before_window),
        ("Challenge after the window closes", 409, "challenge-window-closed", "7.3", False, challenge_after_window),
        ("Challenge signed by the seller", 422, "unexpected-signer", "7.3", False, challenge_by_seller),
        ("Challenge whose proof names another instrument", 422, "proof-nonconformant", "7.3", False,
         challenge_nonconformant),
        ("Challenge whose costs carry three decimal places", 422, "amount-invalid", "14.2", False,
         challenge_costs_three_places),
        ("Challenge whose delivery_hash is not the recorded Delivery's", 409, "object-conflict", "7.3", False,
         challenge_other_delivery),
        ("Challenge signed under a kid that does not resolve", 400, "signature-invalid", "14.1.1", False,
         challenge_unresolvable_kid),
        # trees
        ("child whose Buyer is not the parent's Seller", 422, "parent-unresolvable", "10.2", False, child_wrong_buyer),
        ("child with L(child) not before L(parent)", 422, "finality-ordering-violation", "10.3", False, child_timing),
        ("child Outcome Record over the wrong contract", 422, "child-outcome-invalid", "10.2", False,
         child_outcome_wrong_hash),
        ("child Outcome Record whose verification is not the child's", 422, "child-outcome-invalid", "10.2",
         False, child_outcome_other_verification),
        ("child Outcome Record, window-opened without closes_at", 422, "schema-invalid", "14.2", False,
         child_outcome_without_closes_at),
        ("child Outcome Record supplied after the parent's terminal entry", 409, "wrong-state", "10.2", False,
         child_outcome_after_terminal),
        ("child registered under a terminal parent", 409, "wrong-state", "10.2", False,
         child_under_terminal_parent),
        # retrieval
        ("GET an unknown contract", 404, "unknown-contract", "13", False, lambda: c.status("vtc_nobody")),
        ("GET the Outcome Record before the terminal entry", 409, "wrong-state", "13", False,
         lambda: c.outcome(h.funded()["id"])),
        # HTTP: a body this server will not read closes the connection; a failure no
        # rule of the document names is about:blank with no section (Section 13.3)
        ("POST over the body limit, closing the connection", 413, "payload-too-large", "13", False,
         http_(f"POST /pact/v2/contracts HTTP/1.1\nContent-Length: {F.MAX_BODY + 1}\n", Connection="close")),
        ("POST over the body limit with the body sent", 413, "payload-too-large", "13", False,
         lambda: client_post(h.port, "/pact/v2/contracts", b"x" * (F.MAX_BODY + 1), Connection="close")),
        ("Content-Length of 4301 digits, closing the connection", 413, "payload-too-large", "13", False,
         http_("POST /pact/v2/contracts HTTP/1.1\nContent-Length: " + "9" * 4301 + "\n", Connection="close")),
        ("Content-Length of 4301 zeros, read as an empty body", 400, "signature-missing", "14.2", False,
         http_("POST /pact/v2/contracts HTTP/1.1\nContent-Length: " + "0" * 4301 + "\n")),
        ("PUT on a contract (method not implemented)", 501, "about:blank", None, False,
         http_("PUT /pact/v2/contracts/vtc_x HTTP/1.1\nContent-Length: 2\n", b"{}", Connection="close")),
        ("DELETE on a contract (method not implemented)", 501, "about:blank", None, False,
         http_("DELETE /pact/v2/contracts/vtc_x HTTP/1.1\n", Connection="close")),
        ("Content-Length that is not a decimal length", 400, "about:blank", None, False,
         http_("POST /pact/v2/contracts HTTP/1.1\nContent-Length: abc\n", b"{}", Connection="close")),
        ("Content-Length -1", 400, "about:blank", None, False,
         http_("POST /pact/v2/contracts HTTP/1.1\nContent-Length: -1\n", b"{}", Connection="close")),
        ("two Content-Length fields that differ", 400, "about:blank", None, False,
         http_("POST /pact/v2/contracts HTTP/1.1\nContent-Length: 2\nContent-Length: 40\n", b"{}",
               Connection="close")),
        ("a chunked body", 411, "about:blank", None, False,
         http_("POST /pact/v2/contracts HTTP/1.1\nTransfer-Encoding: chunked\n", b"2\r\n{}\r\n0\r\n\r\n",
               Connection="close")),
        ("GET a path with no resource", 404, "about:blank", None, False, http_("GET /pact/v2/nothing HTTP/1.1\n")),
        ("GET on the Delivery collection", 405, "about:blank", None, False,
         http_("GET /pact/v2/deliveries HTTP/1.1\n", Allow="POST")),
        ("POST to an Outcome Record", 405, "about:blank", None, False,
         http_("POST /pact/v2/outcomes/vtc_x HTTP/1.1\nContent-Length: 2\n", b"{}", Allow="GET")),
        # request lines http.server refuses before it records a version: answered in
        # HTTP/1.1 form, not as a bare HTTP/0.9 body
        ("request line naming HTTP/2.0", 505, "about:blank", None, False,
         http_("GET /pact/v2/contracts HTTP/2.0\n", Connection="close")),
        ("request line whose version does not parse", 400, "about:blank", None, False,
         http_("GET /pact/v2/contracts HTTP/1.x\n", Connection="close")),
        ("request line of four words", 400, "about:blank", None, False,
         http_("GET /pact/v2/contracts HTTP/1.1 extra\n", Connection="close")),
        ("request line of one word", 400, "about:blank", None, False, http_("GARBAGE\n", Connection="close")),
        ("request line over 65,536 bytes", 414, "about:blank", None, False,
         http_("GET /pact/v2/contracts/" + "x" * 65536 + " HTTP/1.1\n", Connection="close")),
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

    def location_names_the_contract():
        vtc = h.contract(sign=False)
        vtc["id"] = f"vtc m/{h.n:04d}"   # the schema admits nearly any string as an id; this one must be encoded
        agents.cosign(vtc, h.buyer, h.seller)
        code, _ = c.propose(vtc)
        loc = c.wire[-1].location
        if code != 201 or loc != F.contract_path(vtc["id"]) or not loc.endswith("vtc%20m%2F" + vtc["id"][-4:]):
            return False
        # RFC 9110 Section 10.2.2: a relative Location is resolved against the target URI
        target = urllib.parse.urljoin(c.base + f"{agents.BASE_PATH}/contracts", loc)
        if not target.startswith(c.base + "/"):
            return False
        code2, st = c.get(target[len(c.base):])
        ok, _ = agents.check_status(st, h.resolver, h.fac.identity)
        return code2 == 200 and ok and st["vtc_id"] == vtc["id"] and st["vtc_hash"] == pc.digest_over(vtc)

    def head_501_without_content_length():
        # HEAD is not implemented, so it is answered 501, and RFC 9110 Section 8.6
        # forbids a Content-Length other than the one a GET would carry
        with socket.create_connection(("127.0.0.1", h.port), timeout=5) as s:
            s.sendall(b"HEAD /pact/v2/contracts/vtc_x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            resp = http.client.HTTPResponse(s, method="HEAD")
            resp.begin()
            body = resp.read()
        return (resp.status == 501 and resp.getheader("Content-Type") == "application/problem+json"
                and resp.getheader("Content-Length") is None and resp.getheader("Connection") == "close"
                and body == b"")

    def named_verifier_answers_own_challenge():
        vtc, d, v = h.window_open()
        ch = agents.make_challenge(vtc, d, h.verifier, ["row_count"], costs=None)
        code1, _ = c.challenge(ch)
        code2, body = c.verdict(agents.make_verdict(vtc, d, h.verifier, "FAIL", ch))
        return code1 == 202 and code2 == 201 and body["state"] == "SETTLED" and body["trace"][-1]["challenge_upheld"] is True

    return [
        ("a Challenge alone settles nothing", challenge_alone_does_not_settle),
        ("resubmitting an identical contract returns 200 and the current Status",
         resubmit_identical_contract),
        ("a Buyer's Challenge is admissible", buyer_challenge_admissible),
        ("a refused request leaves no entry in the trace", refusal_leaves_no_entry),
        ("a named Verifier answers its own Challenge and the FAIL settles the contract",
         named_verifier_answers_own_challenge),
        ("a contract's 201 names it in Location, and a GET there returns its Status",
         location_names_the_contract),
        ("HEAD is answered 501 with no Content-Length", head_501_without_content_length),
    ]


def run_refusals(h: Harness) -> tuple[list[dict], list[dict]]:
    rows = []
    for name, status, kind, section, is_profile, fn in refusals(h):
        code, body = fn()
        if kind == "about:blank":
            # RFC 9457 Section 4.2.1: the status phrase as title; no section to name
            ok = (code == status and body.get("type") == kind and body.get("status") == status
                  and body.get("title") == F.BLANK_TITLES[status] and "section" not in body)
            rows.append({"name": name, "expected": (status, kind, section), "got": (code, body.get("type", "?")),
                         "section": None, "ok": ok})
            continue
        base = terms.PROBLEM_BASE if is_profile else F.PROBLEM_BASE
        where = body.get("profile_section") if is_profile else body.get("section")
        # Section 13.3: the section stating the rule this refusal reports,
        # which for some types differs from one refusal to the next (audit A7)
        ok = (code == status and body.get("type") == base + kind and where == section
              and (not is_profile or body.get("profile") == terms.ID))
        rows.append({"name": name, "expected": (status, kind, section), "got": (code, body.get("type", "?")),
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
    vec = next(v for v in h.profile.vectors() if v["name"].startswith("SETTLED on an upheld Challenge (the"))
    leaves = [bytes.fromhex(pc.h(str(i).encode())[7:]) for i in range(64)]
    return {
        "canonicalize contract (us)": bench(lambda: pc.jcs(vtc), 2000),
        "json.dumps contract, sorted keys (us)":
            bench(lambda: json.dumps(vtc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(), 2000),
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
    print("\n  outcome.verdict by path (Section 12): the standing Verdict's digest, verdict-lapsed, or none")
    for s in scenarios:
        print(f"    {s['name']:58} {s['state']:9} {s['verdict']}")
    for s in scenarios[:1] + scenarios[3:4]:
        print(f"\n  messages, {s['name']}:")
        for m in s["messages"]:
            print(f"    {m[0]:4} {m[1]:34} {m[2]}  {m[3]:5d} out  {m[4]:5d} back")
    print("\nREFUSALS")
    bad = 0
    for r in refused:
        flag = "ok " if r["ok"] else "BAD"
        bad += not r["ok"]
        got = r["got"][1] if r["got"][1] == "about:blank" else r["got"][1].rsplit(":", 1)[-1]
        where = f"section {r['section']}" if r["section"] else "no section"
        print(f"  {flag} {r['name']:56} {r['got'][0]} {got:36} {where}")
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
