#!/usr/bin/env python3
"""Check the committed examples against draft-laxsharma-pact-03.

Every value the draft prints comes from examples/ and profiles/, and this
program is how the repository knows those files still say what the document
says. It checks each object against its schema, recomputes every digest the
objects commit to, verifies every signature with the public keys in
examples/keys/, replays the profile's vectors, and runs the negative
conformance vectors of Section 14.3 through the reference Facilitator.

    python3 tools/validate.py

Needs jsonschema and referencing; needs cryptography for the signature
section and the vectors that go through the Facilitator (those print [skip]
without it and are not counted).
"""

from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import sys
from decimal import Decimal

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import pactcore as pc  # noqa: E402
import profile as terms  # noqa: E402

try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

from jsonschema import Draft202012Validator  # noqa: E402
from referencing import Registry, Resource  # noqa: E402

EX = ROOT / "examples"
MEDIA = {
    "vtc": "application/vnd.pact.contract+json",
    "delivery": "application/vnd.pact.delivery+json",
    "verdict": "application/vnd.pact.verdict+json",
    "challenge": "application/vnd.pact.challenge+json",
    "status": "application/vnd.pact.status+json",
    "outcome": "application/vnd.pact.outcome+json",
    "facilitator": "application/vnd.pact.facilitator+json",
}


class Report:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.sections: list[tuple[str, int]] = []
        self._current = None
        self._count = 0

    def section(self, title: str) -> None:
        if self._current is not None:
            self.sections.append((self._current, self._count))
        self._current, self._count = title, 0
        print(f"\n{title}")

    def check(self, cond: bool, label: str, detail: str = "") -> bool:
        self._count += 1
        if cond:
            self.passed += 1
            print(f"  [ok]   {label}")
        else:
            self.failed += 1
            print(f"  [FAIL] {label}" + (f": {detail}" if detail else ""))
        return bool(cond)

    def skip(self, label: str) -> None:
        self.skipped += 1
        print(f"  [skip] {label} (needs cryptography)")

    def done(self) -> int:
        if self._current is not None:
            self.sections.append((self._current, self._count))
        total = self.passed + self.failed
        print(f"\n{total} checks: {self.passed} passed, {self.failed} failed"
              + (f", {self.skipped} skipped" if self.skipped else ""))
        print("  " + "; ".join(f"{n} {t}" for t, n in self.sections))
        return 1 if self.failed else 0


def load(name: str) -> dict:
    return json.loads((EX / name).read_text())


def instant(ts: str) -> tuple[str, Decimal]:
    """A Section 2 timestamp as an instant: the fixed-width date and time, then
    the fraction of a second compared exactly. Compared as strings,
    09:14:30.5Z sorts before 09:14:30Z, and 30.50Z differs from 30.5Z. Call it
    only on a timestamp that has passed the schema."""
    return ts[:19], Decimal("0" + ts[19:-1])


def main() -> int:
    r = Report()
    taskspec = load("taskspec.json")
    vtc = load("vtc.json")
    delivery = load("delivery.json")
    verdict = load("verdict.json")
    challenge = load("challenge.json")
    verdict2 = load("verdict-on-challenge.json")
    status = load("status.json")
    outcome = load("outcome.json")
    facdoc = load("well-known/pact-facilitator.json")
    keys = load("keys/public-keys.json")
    prof = terms.BondedRestitution()

    # -- 1. schemas ---------------------------------------------------------
    r.section("schema conformance")
    docs = {p.name: json.loads(p.read_text()) for p in (ROOT / "schemas").glob("*.schema.json")}
    registry = Registry().with_resources([(n, Resource.from_contents(s)) for n, s in docs.items()])
    registry = registry.with_resources([(s["$id"], Resource.from_contents(s)) for s in docs.values()])
    validators = {n: Draft202012Validator(s, registry=registry) for n, s in docs.items()}

    def conforms(obj, schema) -> tuple[bool, str]:
        errs = sorted(validators[schema].iter_errors(obj), key=lambda e: list(e.path))
        if not errs:
            return True, ""
        e = errs[0]
        return False, f"{e.message[:120]} at /{'/'.join(map(str, e.path))}"

    for name, obj, schema in [("taskspec.json", taskspec, "taskspec.schema.json"),
                              ("vtc.json", vtc, "vtc.schema.json"),
                              ("delivery.json", delivery, "delivery.schema.json"),
                              ("verdict.json", verdict, "verdict.schema.json"),
                              ("challenge.json", challenge, "challenge.schema.json"),
                              ("verdict-on-challenge.json", verdict2, "verdict.schema.json"),
                              ("status.json", status, "status.schema.json"),
                              ("outcome.json", outcome, "outcome.schema.json"),
                              ("well-known/pact-facilitator.json", facdoc, "facilitator.schema.json")]:
        ok, why = conforms(obj, schema)
        r.check(ok, f"{name} validates against {schema}", why)
    r.check(prof.parameters_error(vtc["terms"]["parameters"]) is None,
            "vtc.terms.parameters validate against the profile's parameters.schema.json")
    pp = vtc["parties"]
    r.check(not conforms(vtc | {"parties": dict(pp, seller="did:web:caf\u00e9.example")}, "vtc.schema.json")[0]
            and not conforms(vtc | {"parties": dict(pp, verifier=pp["seller"] + " #x")}, "vtc.schema.json")[0]
            and not conforms(vtc | {"parties": dict(pp, verifier=pp["seller"] + "\n")}, "vtc.schema.json")[0],
            "the party pattern admits %x21-7E only: a U-label, a space, a final newline fail (V-33, V-34)")
    no_work = {k: v for k, v in outcome.items() if k != "work_hash"}
    abandoned_trace = [e for e in outcome["trace"] if e["event"] in ("accepted", "funded")] + [
        {"event": "deadline-passed", "at": "2026-11-14T00:00:01Z"},
        {"event": "children-final", "at": "2026-11-14T00:00:01Z"},
        {"event": "terminal", "at": "2026-11-14T00:00:01Z", "state": "ABANDONED", "challenge_upheld": False}]
    r.check(not conforms(no_work, "outcome.schema.json")[0]
            and not conforms(outcome | {"trace": abandoned_trace}, "outcome.schema.json")[0]
            and conforms(no_work | {"trace": abandoned_trace,
                                    "outcome": dict(outcome["outcome"], verdict="none")}, "outcome.schema.json")[0]
            and not conforms(outcome | {"outcome": dict(outcome["outcome"], verdict="lapsed")}, "outcome.schema.json")[0]
            and not conforms({k: v for k, v in outcome.items() if k != "verification"}, "outcome.schema.json")[0],
            "the Outcome Record schema: work_hash present exactly when a delivered entry is, outcome.verdict a "
            "digest, verdict-lapsed or none, the copied members required (Section 12)")

    def entry_changed(obj: dict, event: str, drop: tuple = (), **add) -> dict:
        """A copy of obj whose first trace entry for event lacks drop and carries add."""
        obj = copy.deepcopy(obj)
        entry = next(e for e in obj["trace"] if e["event"] == event)
        for member in drop:
            del entry[member]
        entry.update(add)
        return obj
    closes = next(e for e in status["trace"] if e["event"] == "window-opened")["closes_at"]
    costs = next(e for e in outcome["trace"] if e["event"] == "challenge")["costs"]
    r.check(not conforms(entry_changed(status, "window-opened", ("closes_at",)), "status.schema.json")[0]
            and not conforms(entry_changed(outcome, "terminal", ("state",)), "outcome.schema.json")[0]
            and not conforms(entry_changed(outcome, "challenge", ("signer",)), "outcome.schema.json")[0]
            and conforms(entry_changed(status, "funded", ref="binding-ref-1"), "status.schema.json")[0],
            "V-51 a trace entry omitting a member Table 2 requires for its event (closes_at, state, signer) fails "
            "the schema; the optional ref does not have to be there (Section 4.2)")
    r.check(not conforms(entry_changed(status, "accepted", closes_at=closes), "status.schema.json")[0]
            and not conforms(entry_changed(outcome, "verdict", costs=costs), "outcome.schema.json")[0]
            and not conforms(entry_changed(outcome, "funded", state="FINAL"), "outcome.schema.json")[0],
            "V-52 a trace entry carrying a member Table 2 does not list for its event (closes_at on accepted, "
            "costs on verdict, state on funded) fails the schema (Section 4.2)")

    # -- 2. canonicalization -----------------------------------------------
    r.section("canonicalization (RFC 8785)")
    r.check(pc.jcs({"b": 1, "a": [1, 2], "aa": "x"}) == b'{"a":[1,2],"aa":"x","b":1}',
            "members sorted, no whitespace")
    r.check(pc.jcs({"q": 1.0, "n": 180, "s": "é "}) == '{"n":180,"q":1,"s":"é "}'.encode(),
            "V-25 ES6 number formatting (the float 1.0 serializes as 1) and raw non-ASCII")
    r.check(pc.jcs([1e21, 1e20, 1e-7, 0.000001, 0.5, -0.0, 123.456, 5e-324]) ==
            b"[1e+21,100000000000000000000,1e-7,0.000001,0.5,0,123.456,5e-324]",
            "V-25 at the edges: exponent form only above 1e21 and below 1e-6, negative zero as 0")
    r.check(pc.jcs({"\U0001F600": 1, "ﬁ": 2}) == '{"\U0001F600":1,"ﬁ":2}'.encode(),
            "keys ordered by UTF-16 code units, not code points (V-18)")

    # -- 3. digests ---------------------------------------------------------
    r.section("hash commitments")
    spec_hash = pc.digest_over(taskspec)
    r.check(vtc["task"]["spec_hash"] == spec_hash, "task.spec_hash is the digest over taskspec.json")
    criteria = pc.manifest_digest(EX / "acceptance-harness")
    r.check(vtc["verification"]["criteria_hash"] == criteria,
            "verification.criteria_hash is the manifest digest over examples/acceptance-harness/")
    r.check(taskspec["acceptance"]["harness_hash"] == criteria,
            "taskspec.acceptance.harness_hash is the same manifest digest")
    for member, path in (("inputs.schema_hash", "customers.schema.json"),
                         ("inputs.sample_hash", "sample-10k.csv"),
                         ("deliverable.schema_hash", "output.schema.json")):
        a, b = member.split(".")
        r.check(taskspec[a][b] == pc.h((EX / "task-content" / path).read_bytes()),
                f"taskspec.{member} is the digest of task-content/{path}")
    profile_hash = pc.manifest_digest(ROOT / "profiles" / "bonded-restitution")
    r.check(prof.profile_hash == profile_hash, "the profile's hash is the manifest digest over its bundle")
    r.check(vtc["terms"]["profile_hash"] == profile_hash, "vtc.terms.profile_hash commits to that bundle")
    r.check(any(p["id"] == terms.ID and p["profile_hash"] == profile_hash for p in facdoc["terms_profiles"]),
            "the capability document advertises the same profile and hash")
    r.check(outcome["terms_result"]["profile_hash"] == profile_hash and outcome["terms_result"]["profile"] == terms.ID,
            "outcome.terms_result names the same profile and hash")
    vtc_hash = pc.digest_over(vtc)
    r.check(all(o["vtc_hash"] == vtc_hash for o in (delivery, status, outcome)),
            "vtc_hash in delivery, status and outcome is the digest over the signed contract")
    delivery_hash = pc.digest_over(delivery)
    r.check(all(o["delivery_hash"] == delivery_hash for o in (verdict, challenge, verdict2)),
            "delivery_hash in both Verdicts and the Challenge covers the Delivery's signature")
    r.check(pc.digest_over({k: v for k, v in delivery.items() if k != "signature"}) != delivery_hash,
            "a digest over the unsigned Delivery is a different value (V-23)")
    r.check(verdict2["challenge_hash"] == pc.digest_over(challenge),
            "verdict-on-challenge.challenge_hash is the digest over the Challenge")
    tr = outcome["trace"]
    r.check(tr[0]["object"] == vtc_hash and tr[2]["object"] == delivery_hash,
            "trace entries accepted and delivered carry the contract and Delivery digests")
    r.check(tr[3]["object"] == pc.digest_over(verdict) and tr[5]["object"] == pc.digest_over(challenge),
            "trace entries verdict and challenge carry the object digests")
    r.check(tr[6]["object"] == pc.digest_over(verdict2) and tr[6]["answers"] == pc.digest_over(challenge)
            and tr[6]["supersedes"] == pc.digest_over(verdict),
            "the second verdict entry answers the Challenge and supersedes the first Verdict")
    r.check(outcome["work_hash"] == delivery["work_hash"] and verdict["results_hash"] == delivery["evidence"]["results_hash"],
            "work_hash and results_hash carry through unchanged")

    # -- 4. rules -----------------------------------------------------------
    r.section("rules of the document")
    parties = vtc["parties"]
    r.check(not pc.same_party(parties["buyer"], parties["seller"]), "buyer and seller are distinct after normalization")
    r.check(pc.norm("did:web:a.example:agents:X") != pc.norm("did:web:a.example:agents:x"),
            "normalization keeps path case (V-19)")
    r.check(pc.norm("https://a.example/") == pc.norm("HTTPS://A.example") == pc.norm("https://a.example#k1"),
            "normalization folds scheme and host, strips fragment and trailing slash (V-07)")

    def not_evaluable(ident: str) -> bool:
        try:
            pc.norm(ident)
        except pc.NotEvaluable:
            return True
        return False

    W = "did:web:seller.example:agents:etl-3"
    r.check(pc.norm("did:web:Seller.Example:agents:etl-3") == pc.norm(W), "host case is folded (V-27)")
    r.check(pc.norm("did:web:seller.example.:agents:etl-3") == pc.norm(W)
            and pc.norm("https://seller.example./jwks") == pc.norm("https://seller.example/jwks"),
            "a trailing dot is removed from the host, not only from the end (V-28)")
    r.check(pc.norm("https://seller.example:443/jwks") == pc.norm("https://seller.example/jwks")
            and pc.norm("https://seller.example:8443/jwks") != pc.norm("https://seller.example/jwks"),
            "https default port 443 is removed, any other kept (V-29)")
    r.check(pc.norm("did:web:seller.example%3A443:agents:etl-3") == pc.norm(W)
            == pc.norm("did:web:seller.example%3a443:agents:etl-3"),
            "did:web %3A443 is removed after the escape is upper-cased (V-30)")
    r.check(not_evaluable("did:web:seller.example:agents:%41") and not_evaluable("https://seller.example/%7ealice")
            and pc.norm("https://seller.example/a%2fb") == pc.norm("https://seller.example/a%2Fb"),
            "an unreserved escape is not evaluable; other escapes compare upper-cased (V-31)")
    r.check(pc.norm("did:web:seller.example:agents:%2541") != pc.norm("did:web:seller.example:agents:A")
            and not_evaluable("did:web:sel%2541ler.example") and not_evaluable("https://sel%2541ler.example/jwks"),
            "%2541 in a path segment is read once, as %25 then 41, and never decoded; in a host it is not evaluable (V-32)")
    r.check(not_evaluable("did:web:caf\u00e9.example") and not_evaluable("did:web:caf%C3%A9.example"),
            "a U-label host, written raw or escaped, is not evaluable (V-33)")
    r.check(not_evaluable(W + " #k1") and not_evaluable(" " + W) and not_evaluable(W + "\n"),
            "whitespace anywhere, before a fragment included, is not evaluable (V-34)")
    r.check(not_evaluable("did:WEB:seller.example") and not_evaluable("did:web:") and not_evaluable("https:seller.example")
            and not_evaluable("urn:example:seller"),
            "an identifier that does not parse, or is in neither form of 14.1.1, is not evaluable (V-35, V-36)")
    r.check(all(not_evaluable(x) for x in ("https://seller.example\\jwks", "https://seller.example/a|b",
                                           'https://seller.example/"a"', "https://seller.example/{a}",
                                           "https://seller.example/[a]", "https://[]/jwks", "https://[v1]/jwks")),
            "an https identifier that is not an RFC 3986 URI is not evaluable (V-37)")
    r.check(all(not_evaluable(x) for x in ("https://@seller.example/jwks", "https://:@seller.example/jwks",
                                           "https://u@seller.example/jwks", "https://seller.example\\@other.example")),
            "userinfo in an https identifier is not evaluable (V-38)")
    r.check(not_evaluable("https://seller.example:0443/jwks") and not_evaluable("https://seller.example:0/jwks")
            and not_evaluable(W.replace("example", "example%3A0443", 1))
            and pc.norm("https://seller.example:8443/jwks") == "https://seller.example:8443/jwks",
            "a port that begins with 0 is not evaluable and is never read as 443 (V-39)")
    r.check(all(not_evaluable(x) for x in ("https://seller.example/./jwks", "https://seller.example/x/../jwks",
                                           "https://seller.example/jwks/.", "https://seller.example/jwks/../",
                                           "did:web:seller.example:x:..:agents:etl-3", "did:web:seller.example:.:agents")),
            "a '.' or '..' segment is not evaluable and is never removed (V-40)")
    r.check(not pc.kid_covers("did:web:host.example:alice.#k1", "did:web:host.example:alice")
            and not pc.kid_covers("https://host.example/alice.#k1", "https://host.example/alice")
            and pc.norm("did:web:seller.example.") == pc.norm("did:web:seller.example")
            == pc.norm("did:web:seller.example./"),
            "a '.' at the end of a path segment stays; only the host's is removed (V-41)")
    r.check(all(not_evaluable(x) for x in ("did:web:seller.example:agents:etl-3%", "did:web:seller.example:agents:%4",
                                           "https://seller.example/a%zz", "https://seller.example/a?b=%")),
            "a '%' that does not begin an escape of two hexadecimal digits is not evaluable (V-42)")
    r.check(pc.norm("https://seller.example/?a=1") == pc.norm("https://seller.example?a=1")
            == pc.norm("https://seller.example:443/?a=1#k1") == "https://seller.example?a=1",
            "an https path of exactly '/' is removed when a query follows it too (V-43)")
    r.check(all(not_evaluable(x) for x in ("https://[2001:db8::1]/jwks", "https://[2001:DB8::1]:443/jwks",
                                           "https://[v1.x]/jwks")),
            "a host that is an IP literal is not evaluable, IPv6 or IPvFuture (V-57)")
    r.check(all(not_evaluable(x) for x in ("https://192.0.2.1/jwks", "https://192.000.002.001/jwks",
                                           "https://0300.0.2.1/jwks", "https://0xc0.0.2.1/jwks",
                                           "https://192.0.2.1./jwks", "did:web:192.0.2.1:agents:etl-3"))
            and pc.norm("https://1a.example/jwks") == "https://1a.example/jwks",
            "a host whose last non-empty label begins with a digit, as an IPv4 address in decimal, octal or "
            "hexadecimal does, is not evaluable; a digit that begins another label is not refused (V-58)")
    r.check(all(not_evaluable(x) for x in ("https://seller.example/jwks?", "https://seller.example?",
                                           "https://seller.example/?#k1", "https://seller.example/jwks?/"))
            and pc.norm("https://seller.example/jwks?a") == "https://seller.example/jwks?a",
            "an empty query is not evaluable, also where step 4 removed a '/' that ended it (V-59)")
    r.check(all(not_evaluable(x) for x in ("https://seller.example//jwks", "https://seller.example/a//b?c",
                                           "did:web:seller.example:agents::etl-3"))
            and pc.norm("https://seller.example/a//") == pc.norm("https://seller.example/a")
            and pc.norm("https://seller.example/a/?b") == "https://seller.example/a/?b",
            "an empty segment between two separators is not evaluable; a '/' at the end goes by step 4, "
            "and one before a query is kept (V-60)")
    errs = pc.outcome_errors(outcome, vtc, delivery)
    r.check(not errs and outcome["outcome"]["verdict"] == pc.digest_over(verdict2),
            "the example Outcome Record copies task.spec_hash, verification and flow, names the standing FAIL "
            "in outcome.verdict and carries the recorded Delivery's work_hash (Section 12)", "; ".join(errs))
    r.check(pc.outcome_errors(outcome | {"work_hash": pc.h(b"other bytes")}, vtc, delivery) != []
            and pc.outcome_errors(outcome | {"work_hash": delivery["evidence"]["results_hash"]}, None, delivery) != [],
            "V-44 an Outcome Record whose work_hash is not that of the Delivery its delivered entry names is rejected")

    def verdict_vector(trace: list, right: str, wrong: tuple) -> bool:
        base = {"trace": trace, "outcome": {"verdict": right}}
        if any(e["event"] == "delivered" for e in trace):
            base["work_hash"] = delivery["work_hash"]
        return (pc.outcome_errors(base) == []
                and all(pc.outcome_errors(base | {"outcome": {"verdict": w}}) for w in wrong))
    vec_trace = {v["name"]: v["trace"] for v in prof.vectors() if "trace" in v}
    final_tr = next(t for n, t in vec_trace.items() if n.startswith("FINAL: PASS"))
    lapsed_tr = next(t for n, t in vec_trace.items() if n.startswith("FINAL after verdict-lapsed"))
    pass_digest = next(e["object"] for e in final_tr if e["event"] == "verdict")
    nowin_tr = [e for e in final_tr if e["event"] in ("accepted", "funded", "delivered")] + [
        {"event": "children-final", "at": final_tr[2]["at"]},
        {"event": "terminal", "at": final_tr[2]["at"], "state": "FINAL", "challenge_upheld": False}]
    r.check(verdict_vector(final_tr, pass_digest, ("none", "verdict-lapsed")),
            "V-45 FINAL on a standing PASS: outcome.verdict must be that Verdict's digest, not none or verdict-lapsed")
    r.check(verdict_vector(lapsed_tr, "verdict-lapsed", ("none", pass_digest)),
            "V-46 FINAL after verdict-lapsed with no Verdict: outcome.verdict must be verdict-lapsed")
    r.check(verdict_vector(nowin_tr, "none", ("verdict-lapsed", pass_digest)),
            "V-47 FINAL under no-window: outcome.verdict must be none; three FINAL records, three values")
    ok, why = pc.signatures_ordered(vtc)
    r.check(ok, "contract signatures are sorted by normalized kid", why)

    def ordered(*kids_: str) -> bool:
        entries = [{"protected": pc.b64u(json.dumps({"alg": "EdDSA", "kid": k}).encode()), "signature": ""}
                   for k in kids_]
        return pc.signatures_ordered({"signatures": entries})[0]
    B_ = parties["buyer"]
    B_up = B_.replace(B_.split(":")[2], B_.split(":")[2].upper())
    r.check(ordered(B_ + "#k1", B_ + "#k2") and not ordered(B_ + "#k2", B_ + "#k1")
            and ordered(B_up + "#k1", B_ + "#k1") and not ordered(B_ + "#k1", B_up + "#k1"),
            "A11 a tie on the normalized kid is broken by the unnormalized kid, by code point: #k1 before #k2 "
            "of one identifier, an upper-case host before the same host in lower case (Section 14.1)")
    kids = pc.signer_kids(vtc)
    r.check(len(kids) == 2 and any(pc.kid_covers(k, parties["buyer"]) for k in kids)
            and any(pc.kid_covers(k, parties["seller"]) for k in kids),
            "exactly one kid covers the buyer and one the seller")

    def headers_ok(obj, typ) -> tuple[bool, str]:
        for entry in pc.signature_entries(obj):
            hdr = json.loads(pc.b64u_decode(entry["protected"]))
            if hdr.get("alg") not in pc.ALLOWED_ALGS:
                return False, f"alg {hdr.get('alg')}"
            if "kid" not in hdr or hdr.get("typ") != typ:
                return False, f"typ {hdr.get('typ')}"
        return True, ""
    for name, obj, typ in (("vtc", vtc, "vtc"), ("delivery", delivery, "delivery"), ("verdict", verdict, "verdict"),
                           ("challenge", challenge, "challenge"), ("verdict-on-challenge", verdict2, "verdict"),
                           ("status", status, "status"), ("outcome", outcome, "outcome"),
                           ("facilitator document", facdoc, "facilitator")):
        ok, why = headers_ok(obj, MEDIA[typ])
        r.check(ok, f"{name}: protected header carries an allowed alg, a kid and typ {MEDIA[typ]}", why)
    r.check(all(pc.kid_covers(k, parties["verifier"]) for k in pc.signer_kids(verdict) + pc.signer_kids(verdict2)),
            "both Verdicts are signed by the named verifier")
    r.check(not any(pc.kid_covers(k, parties["seller"]) for k in pc.signer_kids(challenge)),
            "the Challenge is not signed by the seller")
    r.check(all(pc.kid_covers(k, parties["facilitator"]) for o in (status, outcome, facdoc) for k in pc.signer_kids(o)),
            "Status, Outcome Record and capability document are signed by the Facilitator")
    r.check(status["trace"] == outcome["trace"][:len(status["trace"])],
            "the Status trace is a prefix of the Outcome Record trace (Section 11)")
    r.check(tr[-1]["event"] == "terminal" and tr[-1]["state"] == outcome["outcome"]["state"] == "SETTLED",
            "the terminal entry is last and names the recorded state")
    standing = [e for e in tr if e["event"] == "verdict"][-1]
    r.check(standing["outcome"] == "FAIL" and ("answers" in standing) == outcome["outcome"]["challenge_upheld"],
            "challenge_upheld is true exactly when the standing FAIL answers a Challenge")
    ats = [instant(e["at"]) for e in tr]
    r.check(ats == sorted(ats) and instant(status["issued_at"]) >= instant(status["trace"][-1]["at"]),
            "trace timestamps never decrease and issued_at is not earlier than the last entry (Section 4.2)")
    r.check(instant("2026-11-10T09:14:30.5Z") > instant("2026-11-10T09:14:30Z")
            and instant("2026-11-10T09:14:30.50Z") == instant("2026-11-10T09:14:30.5Z")
            and instant("2026-11-10T09:14:29.999999999999999999Z") < instant("2026-11-10T09:14:30Z"),
            "A11 timestamps compare as instants: 30.5Z is after 30Z and equal to 30.50Z, and a fraction of "
            "eighteen nines stays before the next second (as strings the first two comparisons fail)")
    r.check(status["state"] == "WINDOW_OPEN" and status["trace"][-1]["event"] == "window-opened",
            "the example Status is the window-opened moment")

    # -- 5. signatures -------------------------------------------------------
    r.section("signature verification")
    resolver = None
    if HAVE_CRYPTO:
        resolver = pc.KeyResolver()
        for role, jwk in keys.items():
            resolver.register(pc.Key.from_public_bytes(jwk["kid"], "Ed25519", pc.b64u_decode(jwk["x"])))
        for name, obj, typ, required in (
                ("vtc", vtc, "vtc", [parties["buyer"], parties["seller"]]),
                ("delivery", delivery, "delivery", [parties["seller"]]),
                ("verdict", verdict, "verdict", [parties["verifier"]]),
                ("challenge", challenge, "challenge", []),
                ("verdict-on-challenge", verdict2, "verdict", [parties["verifier"]]),
                ("status", status, "status", [parties["facilitator"]]),
                ("outcome", outcome, "outcome", [parties["facilitator"]]),
                ("facilitator document", facdoc, "facilitator", [parties["facilitator"]])):
            ok, why = pc.verify_object(obj, resolver, MEDIA[typ], required)
            r.check(ok, f"{name}: every signature verifies with examples/keys/public-keys.json", why)
        r.check(pc.digest_over(vtc) == vtc_hash and pc.signable(vtc) == {k: v for k, v in vtc.items() if k != "signatures"},
                "the signing input excludes the signature set and the digest includes it")
    else:
        for _ in range(9):
            r.skip("signature verification")

    # -- 6. the terms profile ----------------------------------------------
    r.section("terms profile: bonded-restitution")
    ok, why = prof.reproduces()
    r.check(ok, "profiles/bonded-restitution/vectors.json reproduces from the schedule", why)
    vecs = prof.vectors()

    def tup(ts):
        return [(t["event"], t["from"], t["to"], t["amount"], t["code"]) for t in ts]
    final_printed = [(1, "buyer", "escrow", "180.00", "lock"), (1, "seller", "bond", "18.00", "bond"),
                     (1, "seller", "fund", "0.50", "fund"), (3, "escrow", "seller", "180.00", "principal"),
                     (7, "bond", "seller", "18.00", "return"), (7, "fund", "seller", "0.50", "fund-return")]
    overturned_printed = [(1, "buyer", "escrow", "180.00", "lock"), (1, "seller", "bond", "18.00", "bond"),
                          (1, "seller", "fund", "0.50", "fund"), (3, "escrow", "seller", "180.00", "principal"),
                          (8, "fund", "challenger:did:web:watch.example#k1", "0.50", "costs"),
                          (8, "bond", "buyer", "18.00", "restitution")]
    by_name = lambda prefix: next(v for v in vecs if v["name"].startswith(prefix))
    r.check(tup(by_name("FINAL: PASS")["transfers"]) == final_printed, "Appendix A.6, the FINAL list, is the bundle's verdict-first vector verbatim")
    r.check(tup(by_name("SETTLED on an upheld Challenge (the")["transfers"]) == overturned_printed, "Appendix A.6, the overturned list, is the bundle's dispute-path vector verbatim")
    r.check(sum("admission" in v for v in vecs) == 3 and len(vecs) == 12,
            "the bundle carries twelve vectors, three of them admission vectors")
    a3 = next(v for v in vecs if v["name"].startswith("admission: refused, q_min 0.3333333333333333 on 0.01"))
    r.check(a3["admission"] == {"refused": "assurance-constraint-unsatisfied"}
            and not pc.assurance_holds("0.01", "0.020000000000000003", 0.3333333333333333)
            and pc.assurance_holds("0.01", "0.020000000000000004", 0.3333333333333333),
            "A3 the admission bound is exact: at P 0.01 and q 0.3333333333333333 a bond whose B*q falls 1e-34 "
            "short of P*(1-q) is refused, the next amount up admitted (a 28-digit decimal context admitted both)")
    fee = {v["name"]: tup(v["transfers"]) for v in vecs if v["name"].startswith("FINAL with a verifier fee")}
    r.check(fee.get("FINAL with a verifier fee of 0.105, fund 0.51") ==
            [(1, "buyer", "escrow", "180.00", "lock"), (1, "seller", "bond", "18.00", "bond"),
             (1, "seller", "fund", "0.51", "fund"), (3, "fund", "verifier", "0.105", "verification"),
             (3, "escrow", "seller", "180.00", "principal"), (7, "bond", "seller", "18.00", "return"),
             (7, "fund", "seller", "0.405", "fund-return")],
            "A4 fund 0.51 and fee 0.105: the entries are 0.105 and 0.405, exact, and close (rounded to cents they "
            "were 0.10 and 0.40 and broke closure)")
    r.check(("fee", (3, "fund", "verifier", "0.105", "verification")) == ("fee", fee.get(
                "FINAL with a verifier fee of 0.105, fund 0.50", [None] * 4)[3])
            and (7, "fund", "seller", "0.395", "fund-return") in fee.get("FINAL with a verifier fee of 0.105, fund 0.50", []),
            "A4 fund 0.50 and fee 0.105: the entries are 0.105 and 0.395 (rounded to cents they were 0.10 and 0.40, "
            "which closed and were wrong)")
    r.check(outcome["terms_result"]["transfers"] == prof.schedule(vtc, outcome["trace"]),
            "outcome.terms_result.transfers is the schedule over the example trace")
    ok, why = prof.check(vtc, outcome["terms_result"]["transfers"], terminal=True)
    r.check(ok, "the example result satisfies no-overdraft and closure", why)
    try:
        prof.admit(vtc)
        r.check(True, "the example contract passes the admission rule")
    except terms.ProfileRefusal as exc:
        r.check(False, "the example contract passes the admission rule", exc.detail)

    def admits(bond: str, q: float) -> bool:
        v = copy.deepcopy(vtc)
        v["terms"]["parameters"]["seller_bond"] = bond
        v["terms"]["parameters"]["assurance"]["q_min"] = q
        try:
            prof.admit(v)
            return True
        except terms.ProfileRefusal:
            return False
    r.check(admits("18.00", 0.9091) and not admits("17.99", 0.9091),
            "assurance constraint is two-sided at q_min 0.9091: 18.00 admitted, 17.99 refused")
    r.check(not admits("18.00", 0.5), "q_min 0.5 with an 18.00 bond on 180.00 is refused")
    bad = copy.deepcopy(outcome["terms_result"]["transfers"])
    bad.append({"event": 8, "from": "escrow", "to": "seller", "amount": "0.01", "code": "principal"})
    ok, _ = prof.check(vtc, bad, terminal=True)
    r.check(not ok, "an extra transfer from an emptied account fails no-overdraft (V-24)")
    r.check(prof.parameters_error({"seller_bond": "abc"}) is not None,
            "parameters that fail the profile schema are named (V-13)")
    huge = "9" * 4400 + ".00"     # Section 2 bounds no integer part; Python's int-to-str stops at 4300 digits
    try:
        written = pc.amount_str(huge)
    except ValueError as exc:
        written = f"ValueError: {str(exc)[:60]}"
    r.check(written == huge, "an amount of 4,400 integer digits is written back exactly by the schedule's "
            "amount form", written[:80])

    # -- 7. Merkle ------------------------------------------------------------
    r.section("Merkle tree hash (RFC 9162)")
    d = [hashlib.sha256(bytes([i])).digest() for i in range(8)]
    H = lambda b: hashlib.sha256(b).digest()  # noqa: E731
    r.check(pc.mth([]) == H(b""), "MTH of the empty tree is SHA-256 of the empty string")
    r.check(pc.mth(d[:1]) == H(b"\x00" + d[0]), "single leaf is hashed with the 0x00 prefix")
    r.check(pc.mth(d[:2]) == H(b"\x01" + H(b"\x00" + d[0]) + H(b"\x00" + d[1])),
            "two leaves join under the 0x01 prefix")
    r.check(pc.mth(d[:3]) == H(b"\x01" + pc.mth(d[:2]) + pc.mth(d[2:3])),
            "three leaves split at k=2, the largest power of two below n")
    r.check(pc.mth(d[:5]) == H(b"\x01" + pc.mth(d[:4]) + pc.mth(d[4:5])), "five leaves split at k=4")
    r.check(pc.mth(d[:7]) == H(b"\x01" + pc.mth(d[:4]) + pc.mth(d[4:7])), "seven leaves split at k=4")

    # -- 8. negative vectors through the Facilitator --------------------------
    r.section("conformance vectors of Section 14.3, through the reference Facilitator")
    r.check(pc.CURVE_ORDER["ES256"] == 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
            "P-256 group order is the SEC 2 value")
    r.check(pc.CURVE_ORDER["ES384"] == int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
                                            "581A0DB248B0A77AECEC196ACCC52973", 16),
            "P-384 group order is the SEC 2 value")
    if not HAVE_CRYPTO:
        for _ in range(73):
            r.skip("negative vector")
        return r.done()

    import agents  # noqa: E402
    import facilitator as F  # noqa: E402
    import mint_examples as mint  # noqa: E402
    clock = F.parse_rfc3339("2026-11-01T09:00:00Z")
    fac = F.Facilitator("did:web:settle.example", mint.key_for("did:web:settle.example"), resolver,
                        now=lambda: clock)
    kb = mint.key_for(parties["buyer"])
    ks = mint.key_for(parties["seller"])
    kv = mint.key_for(parties["verifier"])
    ksub = pc.Key.generate("did:web:sub.example#k1")
    resolver.register(ksub)

    def cosign(obj: dict, *keys_) -> dict:
        obj = {k: v for k, v in obj.items() if k != "signatures"}
        entries = [pc.sign(obj, k, MEDIA["vtc"]) for k in keys_]
        obj["signatures"] = agents.sort_signatures(entries)     # Section 14.1, the raw-kid tie-break included
        return obj

    def resign(obj: dict, key, typ: str) -> dict:
        obj = {k: v for k, v in obj.items() if k != "signature"}
        obj["signature"] = pc.sign(obj, key, typ)
        return obj

    def refused(label: str, fn, kinds: tuple[str, ...]) -> None:
        try:
            fn()
        except F.Refuse as exc:
            r.check(exc.kind in kinds, f"{label}: refused as {exc.kind}", exc.detail)
            return
        except terms.ProfileRefusal as exc:
            r.check(exc.kind in kinds, f"{label}: refused by the profile as {exc.kind}", exc.detail)
            return
        r.check(False, f"{label}: refused", "accepted")

    def with_header(obj: dict, **changes) -> dict:
        obj = copy.deepcopy(obj)
        entry = obj["signatures"][0]
        hdr = json.loads(pc.b64u_decode(entry["protected"]))
        hdr.update(changes)
        entry["protected"] = pc.b64u(json.dumps(hdr, separators=(",", ":")).encode())
        return obj

    fresh = {k: v for k, v in vtc.items() if k != "signatures"}
    refused("V-02 alg none", lambda: fac.propose(with_header(vtc, alg="none")), ("algorithm-not-permitted",))
    refused("V-03 alg HS256", lambda: fac.propose(with_header(vtc, alg="HS256")), ("algorithm-not-permitted",))
    def kid_outside() -> dict:
        obj = copy.deepcopy(vtc)
        entry = obj["signatures"][0]
        hdr = json.loads(pc.b64u_decode(entry["protected"]))
        entry["kid"] = hdr.pop("kid")
        entry["protected"] = pc.b64u(json.dumps(hdr, separators=(",", ":")).encode())
        return obj
    refused("V-04 kid moved outside the protected header", lambda: fac.propose(kid_outside()),
            ("schema-invalid", "signature-invalid"))
    refused("V-05 typ of another media type", lambda: fac.propose(with_header(vtc, typ=MEDIA["delivery"])),
            ("signature-invalid",))
    refused("V-06 buyer and seller the same identifier",
            lambda: fac.propose(cosign(fresh | {"id": "vtc_v06", "parties": dict(parties, seller=parties["buyer"])}, kb, ks)),
            ("parties-not-distinct",))
    # The Seller part is signed under a key published for the Seller as written, so an
    # implementation that does not normalize accepts this contract instead of refusing it
    # for an unexpected signer, and fails the vector on reject or accept alone
    kslash = resolver.register(pc.Key.generate(parties["buyer"] + "/#k1"))
    refused("V-07 seller differs from buyer by a trailing slash only, its signature under a key published "
            "for that identifier as written",
            lambda: fac.propose(cosign(fresh | {"id": "vtc_v07", "parties": dict(parties, seller=parties["buyer"] + "/")}, kb, kslash)),
            ("parties-not-distinct",))
    refused("V-08 two buyer signatures, no seller", lambda: fac.propose(cosign(fresh | {"id": "vtc_v08"}, kb, kb)),
            ("unexpected-signer",))
    refused("V-09 window_seconds 0",
            lambda: fac.propose(cosign(fresh | {"id": "vtc_v09", "challenge": dict(vtc["challenge"], window_seconds=0)}, kb, ks)),
            ("schema-invalid",))
    r.check(not conforms(taskspec | {"acceptance": {}}, "taskspec.schema.json")[0],
            "V-10 an empty acceptance object fails the TaskSpec schema")
    r.check(not conforms(taskspec | {"acceptance": {k: v for k, v in taskspec["acceptance"].items() if k != "harness_hash"}},
                         "taskspec.schema.json")[0],
            "V-11 harness_uri without harness_hash fails the TaskSpec schema")
    # The same rule for the other four URI members the schema pairs with a hash. The example
    # carries no rubric, so that vector starts from the example with a rubric pair added.
    with_rubric = taskspec | {"acceptance": dict(taskspec["acceptance"], rubric_uri="https://buyer.example/specs/rubric.json",
                                                 rubric_hash=pc.h(b"rubric"))}
    sib = []
    for part, uri, base in (("inputs", "schema_uri", taskspec), ("inputs", "sample_uri", taskspec),
                            ("deliverable", "schema_uri", taskspec), ("acceptance", "rubric_uri", with_rubric)):
        cut = base | {part: {k: v for k, v in base[part].items() if k != uri.replace("_uri", "_hash")}}
        if not conforms(base, "taskspec.schema.json")[0]:
            sib.append(f"{part} with {uri} and its hash fails")
        elif conforms(cut, "taskspec.schema.json")[0]:
            sib.append(f"{part}.{uri} without its hash conforms")
    r.check(not sib, "V-53 inputs.schema_uri, inputs.sample_uri, deliverable.schema_uri and acceptance.rubric_uri "
            "without their sibling hashes each fail the TaskSpec schema, and conform with them", "; ".join(sib))
    refused("V-12 profile_hash the Facilitator does not advertise",
            lambda: fac.propose(cosign(fresh | {"id": "vtc_v12", "terms": dict(vtc["terms"], profile_hash=pc.h(b"other"))}, kb, ks)),
            ("terms-unsupported",))
    refused("V-13 parameters that fail the profile schema",
            lambda: fac.propose(cosign(fresh | {"id": "vtc_v13", "terms": dict(vtc["terms"], parameters={"seller_bond": "abc"})}, kb, ks)),
            ("terms-parameters-invalid",))
    case_seller = parties["buyer"].replace("procure-1", "Procure-1")
    kcase = resolver.register(pc.Key.generate(case_seller + "#k1"))
    try:
        code, _ = fac.propose(cosign(fresh | {"id": "vtc_case01", "parties": dict(parties, seller=case_seller)}, kb, kcase))
    except F.Refuse as exc:
        code = exc.kind
    r.check(code == 201, "V-19 buyer and seller differing only in did:web path case are accepted as distinct")
    forbidden = {"jwk": {"kty": "OKP"}, "jku": "https://keys.example/jwks", "x5c": ["MIIB"], "x5u": "https://keys.example/c.pem",
                 "x5t": "abc", "x5t#S256": "abc", "crit": ["b64"]}
    bad = []
    for member, value in forbidden.items():
        try:
            fac.propose(with_header(vtc, **{member: value})); bad.append(member + " accepted")
        except F.Refuse as exc:
            if exc.kind != "signature-invalid": bad.append(f"{member}: {exc.kind}")
    r.check(not bad, "V-26 a protected header carrying jwk, jku, x5c, x5u, x5t, x5t#S256 or crit is refused as signature-invalid", "; ".join(bad))
    refused("V-20 undefined member", lambda: fac.propose(cosign(fresh | {"id": "vtc_v20", "bonus": True}, kb, ks)), ("schema-invalid",))
    dots = []
    for dot in (".", ".."):
        try:
            fac.propose(cosign(fresh | {"id": dot}, kb, ks))
            dots.append(f"{dot!r} accepted")
        except F.Refuse as exc:
            if exc.kind != "schema-invalid":
                dots.append(f"{dot!r}: {exc.kind}")
    r.check(not dots, 'V-56 a contract whose id is "." or ".." is refused as schema-invalid', "; ".join(dots))
    def as_verifier(label: str, ident: str, kinds: tuple[str, ...], seller_key=None, seller=None) -> None:
        pp = dict(parties, verifier=ident) if seller is None else dict(parties, seller=seller, verifier=ident)
        vid = "vtc_v" + label[2:4]    # its own contract id, so one regression cannot mask the next vector
        refused(label, lambda: fac.propose(cosign(fresh | {"id": vid, "parties": pp}, kb, seller_key or ks)), kinds)
    S_ = parties["seller"]
    host = S_.split(":")[2]
    NI = ("verifier-not-independent",)
    NE = ("identifier-not-evaluable",)
    as_verifier("V-27 parties.verifier is the seller with its host upper-cased", S_.replace(host, host.upper()), NI)
    as_verifier("V-28 ... the seller with a dot at the end of its host, before a path", S_.replace(host, host + "."), NI)
    hs = "https://dataforge.example/agents/etl-3"
    khs = resolver.register(pc.Key.generate(hs + "#k1"))
    as_verifier("V-29 ... the https seller with an explicit :443", "https://dataforge.example:443/agents/etl-3", NI, khs, hs)
    as_verifier("V-30 ... the seller with %3A443 after its did:web host", S_.replace(host, host + "%3A443"), NI)
    as_verifier("V-31 ... the seller with one unreserved character escaped", S_.replace(":etl", ":%65tl"), NE)
    try:
        code, _ = fac.propose(cosign(fresh | {"id": "vtc_pct01", "parties": dict(parties, verifier=S_.replace(":etl", ":%2565tl"))}, kb, ks))
    except F.Refuse as exc:
        code = exc.kind
    r.check(code == 201, "V-32 parties.verifier carrying %2565 in a path segment where the seller carries e is accepted as distinct", str(code))
    as_verifier("V-33 a party identifier with a U-label host", "did:web:caf\u00e9.example", NE)
    as_verifier("V-34 parties.verifier is the seller followed by a space and a fragment", S_ + " #x", NE)
    as_verifier("V-35 parties.verifier is the seller with the DID method name upper-cased",
                S_.replace("did:web", "did:WEB"), NE)
    as_verifier("V-37 ... the https seller with a backslash in place of a slash",
                hs.replace(".example/", ".example\\"), NE, khs, hs)
    as_verifier("V-38 ... the https seller with userinfo", hs.replace("https://", "https://@"), NE, khs, hs)
    as_verifier("V-39 ... the https seller with a port of 0443", hs.replace(".example/", ".example:0443/"), NE, khs, hs)
    as_verifier("V-40 ... the seller with a '..' segment that cancels an added one",
                S_.replace(":etl-3", ":x:..:etl-3"), NE)
    kdot = resolver.register(pc.Key.generate(S_ + ".#k1"))     # another identifier's own key
    refused("V-41 a seller signature under a kid whose identifier differs from the seller by a '.' at the end of a path segment",
            lambda: fac.propose(cosign(fresh | {"id": "vtc_v41"}, kb, kdot)), ("unexpected-signer",))
    as_verifier("V-42 parties.verifier is the seller with a '%' added that begins no escape", S_ + "%", NE)
    hq = "https://dataforge.example?agent=etl-3"
    khq = resolver.register(pc.Key.generate(hq + "#k1"))
    as_verifier("V-43 ... the https seller with a query, with a path of '/' before the query",
                "https://dataforge.example/?agent=etl-3", NI, khq, hq)
    as_verifier("V-57 parties.verifier whose host is an IPv6 literal", "https://[2001:db8::1]/agents/etl-3", NE)
    as_verifier("V-58 parties.verifier whose host is an IPv4 address with leading zeros",
                "https://192.000.002.001/agents/etl-3", NE)
    as_verifier("V-59 ... the https seller with an empty query", hs + "?", NE, khs, hs)
    as_verifier("V-60 ... the seller with an empty segment", S_.replace(":etl-3", "::etl-3"), NE)
    refused("V-21 signatures out of order",
            lambda: fac.propose(vtc | {"signatures": list(reversed(vtc["signatures"]))}), ("signatures-unordered",))

    # ES256 high-S (V-22): sign, flip s to n - s, expect the verifier to refuse it
    k256 = pc.Key.generate("did:web:t.example#k1", "ES256")
    sig = k256.sign_bytes(b"pact")
    n = pc.CURVE_ORDER["ES256"]
    high = sig[:32] + (n - int.from_bytes(sig[32:], "big")).to_bytes(32, "big")
    try:
        k256.verify_bytes(high, b"pact")
        r.check(False, "V-22 a high-S ECDSA signature is refused", "accepted")
    except Exception:
        try:
            k256.verify_bytes(sig, b"pact")
            r.check(True, "V-22 a high-S ECDSA signature is refused and the low-S original verifies")
        except Exception as exc:  # pragma: no cover
            r.check(False, "V-22 a high-S ECDSA signature is refused", f"low-S original failed too: {exc}")

    # The example contract, then the Delivery-level and Verdict-level vectors
    try:
        code, _ = fac.propose(vtc)
    except F.Refuse as exc:
        code = f"refused as {exc.kind}: {exc.detail}"
    if not r.check(code == 201, "V-01 the example contract is accepted by the reference Facilitator", str(code)):
        return r.done()     # every later vector runs on this contract
    before = len(fac.get_status(vtc["id"])[1]["trace"])
    refused("V-14 Delivery without evidence",
            lambda: fac.submit_delivery(resign({k: v for k, v in delivery.items() if k != "evidence"}, ks, MEDIA["delivery"])),
            ("evidence-nonconformant",))
    r.check(len(fac.get_status(vtc["id"])[1]["trace"]) == before, "V-14: the refused Delivery left no entry in the trace")
    refused("V-48 Delivery whose evidence.instrument_hash is not verification.criteria_hash",
            lambda: fac.submit_delivery(resign(delivery | {"evidence": dict(delivery["evidence"], instrument_hash=pc.h(b"another"))},
                                               ks, MEDIA["delivery"])),
            ("evidence-nonconformant",))
    code, _ = fac.submit_delivery(delivery)
    r.check(code == 202, "the example Delivery is accepted after the nonconformant one was refused")
    refused("V-17 Verdict signed by the seller", lambda: fac.record_verdict(resign(verdict, ks, MEDIA["verdict"])),
            ("verifier-not-independent",))
    unsigned_hash = pc.digest_over({k: v for k, v in delivery.items() if k != "signature"})
    refused("V-23 Verdict whose delivery_hash omits the Delivery's signature",
            lambda: fac.record_verdict(resign(verdict | {"delivery_hash": unsigned_hash}, kv, MEDIA["verdict"])),
            ("verdict-nonconformant",))
    nov = cosign(fresh | {"id": "vtc_nov01", "parties": {k: v for k, v in parties.items() if k != "verifier"}}, kb, ks)
    code, _ = fac.propose(nov)
    dnov = resign(delivery | {"vtc_id": nov["id"], "vtc_hash": pc.digest_over(nov)}, ks, MEDIA["delivery"])
    code2, _ = fac.submit_delivery(dnov)
    kup = resolver.register(pc.Key.generate(parties["seller"].replace("did:web", "did:WEB") + "#k1"))
    refused("V-36 on a contract naming no verifier, a Verdict under a kid that does not parse",
            lambda: fac.record_verdict(resign(verdict | {"vtc_id": nov["id"], "delivery_hash": pc.digest_over(dnov)}, kup, MEDIA["verdict"])),
            ("identifier-not-evaluable",))
    link = {"vtc_id": vtc["id"], "vtc_hash": vtc_hash, "facilitator": parties["facilitator"]}
    child_base = copy.deepcopy(fresh) | {"id": "vtc_child01", "parent": link,
                                         "task": dict(vtc["task"], deadline="2026-11-10T00:00:00Z")}
    child_wrong_buyer = cosign(child_base | {"parties": dict(parties, buyer=parties["buyer"], seller="did:web:sub.example")}, kb, ksub)
    refused("V-15 child whose Buyer is not the parent's Seller",
            lambda: fac.register_child(vtc["id"], child_wrong_buyer), ("parent-unresolvable",))
    child_late = cosign(child_base | {"parties": dict(parties, buyer=parties["seller"], seller="did:web:sub.example"),
                                      "task": dict(vtc["task"])}, ks, ksub)
    refused("V-16 child whose latest finality is not before the parent's",
            lambda: fac.register_child(vtc["id"], child_late), ("finality-ordering-violation",))
    child_ok = cosign(child_base | {"parties": dict(parties, buyer=parties["seller"], seller="did:web:sub.example")}, ks, ksub)
    code, st = fac.register_child(vtc["id"], child_ok)
    r.check(code == 201 and st["trace"][-1]["event"] == "child-registered",
            "a conformant child registers and the parent's trace records it")
    # Section 3 excludes the ids "." and ".." (V-56), and registration checks a child
    # against the same schema as Propose
    n_parent = len(fac.contracts[vtc["id"]].trace)
    dots_child = []
    for dot in (".", ".."):
        try:
            fac.register_child(vtc["id"], cosign(child_base | {
                "id": dot, "parties": dict(parties, buyer=parties["seller"], seller="did:web:sub.example")}, ks, ksub))
            dots_child.append(f"{dot!r} accepted")
        except F.Refuse as exc:
            if exc.kind != "schema-invalid":
                dots_child.append(f"{dot!r}: {exc.kind}")
    r.check(not dots_child and len(fac.contracts[vtc["id"]].trace) == n_parent,
            'V-56 as a child: a child contract whose id is "." or ".." is refused at registration as '
            "schema-invalid and adds no entry to the parent's trace", "; ".join(dots_child))

    # Section 14.2: a latest finality instant (Section 10.3) a timestamp cannot write
    refused("V-50 a contract whose latest finality instant falls after the year 9999",
            lambda: fac.propose(cosign(fresh | {"id": "vtc_v50", "challenge": dict(vtc["challenge"], window_seconds=10**12)},
                                       kb, ks)),
            ("deadline-invalid",))
    span = (vtc["verification"]["max_verdict_seconds"] + vtc["challenge"]["window_seconds"]
            + vtc["challenge"]["max_dispute_seconds"])
    edge = []
    year_10000 = 253402300800     # 10000-01-01T00:00:00Z, the first instant a four-digit year cannot write
    for vid, latest in (("vtc_v50last", year_10000 - 1), ("vtc_v50after", year_10000)):
        try:
            edge.append(fac.propose(cosign(fresh | {"id": vid, "task": dict(vtc["task"], deadline=F.iso(latest - span))},
                                           kb, ks))[0])
        except F.Refuse as exc:
            edge.append(exc.kind)
    r.check(edge == [201, "deadline-invalid"],
            "V-50 at the edge: L at 9999-12-31T23:59:59Z is accepted, one second later refused as deadline-invalid",
            str(edge))
    child_far = cosign(child_base | {"id": "vtc_child50",
                                     "parties": dict(parties, buyer=parties["seller"], seller="did:web:sub.example"),
                                     "verification": dict(vtc["verification"], max_verdict_seconds=10**12)}, ks, ksub)
    refused("V-50 as a child: L after the year 9999 is not earlier than the parent's, and the refusal is not internal-error",
            lambda: fac.register_child(vtc["id"], child_far), ("finality-ordering-violation",))

    # Section 10.2 across venues: a second reference Facilitator runs a child to FINAL, and the
    # child's Outcome Record is posted to the parent's Facilitator, which holds it only when the
    # Facilitator the registration recorded signed it and it matches the registered child
    # (V-54, V-55, V-61)
    clock3 = [F.parse_rfc3339("2026-11-01T09:00:00Z")]
    fp = F.Facilitator("did:web:settle.example", mint.key_for("did:web:settle.example"), resolver,
                       now=lambda: clock3[0])
    fo = F.Facilitator("did:web:other.example", resolver.register(pc.Key.generate("did:web:other.example#k1")),
                       resolver, now=lambda: clock3[0])
    p52 = cosign(fresh | {"id": "vtc_v52parent"}, kb, ks)
    c52 = cosign(child_base | {
        "id": "vtc_v52child",
        "parent": {"vtc_id": p52["id"], "vtc_hash": pc.digest_over(p52), "facilitator": fp.identity},
        "parties": dict(parties, buyer=parties["seller"], seller="did:web:sub.example", facilitator=fo.identity)},
        ks, ksub)
    d52 = resign(delivery | {"vtc_id": c52["id"], "vtc_hash": pc.digest_over(c52)}, ksub, MEDIA["delivery"])
    steps = []
    try:
        steps += [fp.propose(p52)[0], fo.propose(c52)[0], fp.register_child(p52["id"], c52)[0],
                  fo.submit_delivery(d52)[0],
                  fo.record_verdict(resign(verdict | {"vtc_id": c52["id"], "delivery_hash": pc.digest_over(d52)},
                                           kv, MEDIA["verdict"]))[0]]
        clock3[0] += c52["challenge"]["window_seconds"] + 1
        code, rec = fo.get_outcome(c52["id"])
        steps.append(code)
    except F.Refuse as exc:
        steps.append(f"{exc.kind}: {exc.detail}")
        rec = None
    if r.check(steps == [201, 201, 201, 202, 201, 200] and rec["outcome"]["state"] == "FINAL",
               "a child at a second venue is registered with the parent's Facilitator and run to FINAL by its own",
               str(steps)):
        child52 = pc.digest_over(c52)
        unsigned = {k: v for k, v in rec.items() if k != "signatures"}
        forged = unsigned | {"signatures": [pc.sign(unsigned, fp.key, MEDIA["outcome"])]}
        events0 = [e["event"] for e in fp.contracts[p52["id"]].trace]
        refused("V-55 a child's Outcome Record signed by a Facilitator other than the one its registration recorded",
                lambda: fp.supply_child_outcome(p52["id"], child52, forged), ("child-outcome-invalid",))
        tampered = unsigned | {"verification": dict(rec["verification"], tier="T1-tee")}
        tampered["signatures"] = [pc.sign(tampered, fo.key, MEDIA["outcome"])]
        refused("V-61 a child's Outcome Record, signed by the Facilitator its registration recorded, whose "
                "verification is not the registered child contract's",
                lambda: fp.supply_child_outcome(p52["id"], child52, tampered), ("child-outcome-invalid",))
        events1 = [e["event"] for e in fp.contracts[p52["id"]].trace]

        def post52() -> tuple:
            try:
                return fp.supply_child_outcome(p52["id"], child52, rec)
            except F.Refuse as exc:
                return exc.kind, {"trace": []}
        (code, st), (code2, st2) = post52(), post52()
        last = (st["trace"] or [{}])[-1]
        r.check(code == 200 and events1 == events0 and [e["event"] for e in st["trace"]] == events0 + ["child-final"]
                and last.get("object") == pc.digest_over(rec) and last.get("child") == child52
                and code2 == 200 and st2["trace"] == st["trace"],
                "V-54 that child's Outcome Record, posted to the parent's Facilitator, is recorded as child-final; "
                "the refused V-55 and V-61 records left no entry, and the same record posted again adds none",
                f"{code} {code2} {events0} {[e['event'] for e in st['trace']]}")
        other = {k: v for k, v in rec.items() if k != "signatures"} | {"work_hash": pc.h(b"other child work")}
        other["signatures"] = [pc.sign(other, fo.key, MEDIA["outcome"])]
        n52 = len(fp.contracts[p52["id"]].trace)
        try:
            fp.supply_child_outcome(p52["id"], child52, other)
            got = "accepted"
        except F.Refuse as exc:
            got = f"{exc.kind} {exc.section}"
        r.check(got == "object-conflict 10.2" and len(fp.contracts[p52["id"]].trace) == n52,
                "a different Outcome Record for that child, signed by the same Facilitator, is refused as "
                "object-conflict citing Section 10.2 and adds no entry", got)

    # Sections 4.2, 10.2 and 12.2: a child this venue holds records its own due entries before the
    # parent reads it, so one that its clock ended before L(child) is child-final, never
    # child-unresolved; a child's record that arrives after its child-unresolved entry and before the
    # parent's terminal entry is still recorded as child-final, posted from another venue or picked up
    # from this one, and the root covers it; no child is marked twice. Each child's marks are compared
    # on their own: the order between children is CHOICES C6, which the text does not fix
    clock4 = [F.parse_rfc3339("2026-11-01T09:00:00Z")]
    fp4 = F.Facilitator("did:web:settle.example", mint.key_for("did:web:settle.example"), resolver,
                        now=lambda: clock4[0])
    fo4 = F.Facilitator("did:web:other.example", fo.key, resolver, now=lambda: clock4[0])
    p4 = cosign(fresh | {"id": "vtc_late_parent"}, kb, ks)
    link4 = {"vtc_id": p4["id"], "vtc_hash": pc.digest_over(p4), "facilitator": fp4.identity}

    def child4(cid: str, deadline: str, venue: str) -> dict:
        return cosign(child_base | {"id": cid, "parent": link4, "task": dict(vtc["task"], deadline=deadline),
                                    "parties": dict(parties, buyer=parties["seller"], seller="did:web:sub.example",
                                                     facilitator=venue)}, ks, ksub)
    ca = child4("vtc_late_a", "2026-11-05T00:00:00Z", fo4.identity)   # posts its record late
    cc = child4("vtc_late_c", "2026-11-05T00:00:00Z", fp4.identity)   # this venue, ends on time, never read
    cd = child4("vtc_late_d", "2026-11-05T00:00:00Z", fp4.identity)   # this venue, its Verdict lapses unread
    cb = child4("vtc_late_b", "2026-11-08T00:00:00Z", fo4.identity)   # never reports
    late, out4, recs = [], {"trace": []}, []
    try:
        late += [fp4.propose(p4)[0], fo4.propose(ca)[0], fp4.propose(cc)[0], fp4.propose(cd)[0]]
        late += [fp4.register_child(p4["id"], x)[0] for x in (ca, cc, cd, cb)]
        for f_, x in ((fo4, ca), (fp4, cc), (fp4, cd)):
            dx = resign(delivery | {"vtc_id": x["id"], "vtc_hash": pc.digest_over(x)}, ksub, MEDIA["delivery"])
            late.append(f_.submit_delivery(dx)[0])
            if x is not cd:
                late.append(f_.record_verdict(resign(verdict | {"vtc_id": x["id"],
                                                                "delivery_hash": pc.digest_over(dx)},
                                                     kv, MEDIA["verdict"]))[0])
        clock4[0] = F.latest_finality(ca) + 1          # past L(A), L(C) and L(D), before L(B)
        late.append(fp4.get_status(p4["id"])[0])        # C ends now: child-final; A and D child-unresolved
        code, rec_a = fo4.get_outcome(ca["id"])
        late += [code, fp4.supply_child_outcome(p4["id"], pc.digest_over(ca), rec_a)[0]]
        clock4[0] += cd["challenge"]["window_seconds"]   # D's window, opened only then, has closed
        late.append(fp4.get_status(p4["id"])[0])        # and the parent picks D's record up
        clock4[0] = max(F.latest_finality(cb), F.parse_rfc3339(p4["task"]["deadline"])) + 1
        code, out4 = fp4.get_outcome(p4["id"])
        late.append(code)
        (code, rec_c), (code2, rec_d) = fp4.get_outcome(cc["id"]), fp4.get_outcome(cd["id"])
        late += [code, code2]
        recs = [rec_a, rec_c, rec_d]
    except F.Refuse as exc:
        late.append(f"{exc.kind}: {exc.detail}")
    da, dc4, dd4, db4 = (pc.digest_over(x) for x in (ca, cc, cd, cb))
    marks: dict[str, list[str]] = {}
    for e in out4["trace"]:
        if "child" in e:
            marks.setdefault(e["child"], []).append(e["event"])
    root4 = "sha256:" + pc.mth(sorted(bytes.fromhex(pc.digest_over(x)[7:]) for x in recs)).hex()
    r.check(late == [201] * 8 + [202, 201] * 2 + [202] + [200] * 7
            and marks == {da: ["child-unresolved", "child-final"], dc4: ["child-final"],
                          dd4: ["child-unresolved", "child-final"], db4: ["child-unresolved"]}
            and len(recs) == 3 and out4.get("children_merkle_root") == root4,
            "a child at this venue whose clock ended it before L(child) has its own entries recorded when "
            "the parent is read and is child-final, never child-unresolved (Section 4.2); a child's record "
            "that arrives after child-unresolved, posted from another venue or picked up from this one, is "
            "recorded as child-final before the parent's terminal entry; the root covers all three records, "
            "and no child is marked unresolved twice (Sections 10.2 and 12.2)",
            f"{late} {marks}")

    # A5: every document-level amount meets the binding, not the price alone
    code, st = fac.record_verdict(verdict)
    r.check(code == 201 and st["state"] == "WINDOW_OPEN", "the example Verdict is recorded and opens the window")
    kc = mint.key_for(mint.CHALLENGER)
    refused("V-49 Challenge whose costs.amount has more decimal places than the settlement binding supports",
            lambda: fac.open_challenge(resign(challenge | {"costs": {"amount": "1.205", "currency": "USDC"}}, kc,
                                              MEDIA["challenge"])),
            ("amount-invalid",))
    code, st = fac.open_challenge(challenge)
    r.check(code == 202 and st["state"] == "DISPUTED", "the example Challenge, costs 1.20, is accepted beside V-49")

    # Checks of this implementation's own choices and fixes, not vectors of Table 3
    r.section("reference implementation checks")
    parent_c4 = cosign(fresh | {"id": "vtc_c4parent"}, kb, ks)
    fac.propose(parent_c4)
    child_foreign = cosign(child_base | {
        "id": "vtc_child_c4",
        "parent": {"vtc_id": parent_c4["id"], "vtc_hash": pc.digest_over(parent_c4), "facilitator": parties["facilitator"]},
        "parties": dict(parties, buyer=parties["seller"], seller="did:web:sub.example", facilitator="did:web:other.example"),
        "price": dict(vtc["price"], amount="10.001", settlement="https://other.example/bindings/ledger-6")}, ks, ksub)
    try:
        code = fac.register_child(parent_c4["id"], child_foreign)[0]
    except F.Refuse as exc:
        code = f"{exc.kind}: {exc.detail}"
    r.check(code == 201, "CHOICES C4: a child at another venue, priced 10.001 under a binding not advertised here, "
            "registers (Section 10.2 leaves that binding to its own Facilitator)", str(code))

    # A11: the max_contract_value cap compares exact amounts, so under a binding of more
    # than two places a price is compared with the cap instead of failing internally
    f3 = F.Facilitator("did:web:settle.example", mint.key_for("did:web:settle.example"), resolver,
                       now=lambda: clock)
    f3.binding_places = {b: 3 for b in f3.binding_places}

    def at_cap(vid: str, amount: str) -> str:
        try:
            return str(f3.propose(cosign(fresh | {"id": vid, "price": dict(vtc["price"], amount=amount)}, kb, ks))[0])
        except F.Refuse as exc:
            return f"{exc.kind} {exc.section}"
        except terms.ProfileRefusal as exc:
            return f"profile {exc.kind}"
    caps = [at_cap("vtc_cap1", "180.001"), at_cap("vtc_cap2", "50000.001"), at_cap("vtc_cap3", "50000.000")]
    r.check(caps == ["201", "settlement-unsupported 13.1", "201"],
            "A11 max_contract_value 50000.00 is compared exactly under a binding of three places: prices of "
            "180.001 and 50000.000 are accepted, and 50000.001 is refused as settlement-unsupported citing 13.1",
            "; ".join(caps))

    # A7: a refusal names the section stating the rule it reports (Section
    # 13.3), which for these types differs from one rule to the next
    def section_of(fn) -> str:
        try:
            fn()
        except F.Refuse as exc:
            return f"{exc.kind} {exc.section}"
        return "accepted"
    cites = [
        (section_of(lambda: fac.open_challenge(resign(challenge, ks, MEDIA["challenge"]))), "unexpected-signer 7.3"),
        (section_of(lambda: fac.open_challenge(resign(challenge | {"delivery_hash": pc.h(b"another")}, kc,
                                                       MEDIA["challenge"]))), "object-conflict 7.3"),
        (section_of(lambda: fac.submit_delivery(resign(delivery | {"work_hash": pc.h(b"again")}, ks,
                                                        MEDIA["delivery"]))), "wrong-state 6"),
        (section_of(lambda: fac.submit_delivery(resign(delivery | {"vtc_hash": pc.h(b"another")}, ks,
                                                        MEDIA["delivery"]))), "object-conflict 6"),
        (section_of(lambda: fac.record_verdict(resign(verdict | {"challenge_hash": pc.digest_over(challenge),
                                                                  "outcome": "FAIL"}, kc, MEDIA["verdict"]))),
         "verifier-not-independent 7.2"),
        (section_of(lambda: fac.get_outcome(vtc["id"])), "wrong-state 13"),
    ]
    r.check(all(got == want for got, want in cites),
            "A7 each refusal names the section stating its rule: a Seller-signed Challenge 7.3, a Challenge on "
            "another Delivery 7.3, a second Delivery 6, a Delivery for another contract 6, a Verdict not by "
            "the named verifier 7.2, an Outcome Record before the terminal entry 13",
            "; ".join(f"{got} (want {want})" for got, want in cites if got != want))

    # A4: an operation whose terms result would break an invariant records nothing
    class Broken(terms.BondedRestitution):
        def schedule(self, vtc_, trace):
            return [t for t in super().schedule(vtc_, trace) if t["code"] != "fund-return"]
    clock2 = [F.parse_rfc3339("2026-11-01T09:00:00Z")]
    fb = F.Facilitator("did:web:settle.example", mint.key_for("did:web:settle.example"), resolver,
                       now=lambda: clock2[0])
    fb.profiles = {k: Broken() for k in fb.profiles}
    vb = cosign(fresh | {"id": "vtc_a4rollback"}, kb, ks)
    fb.propose(vb)
    db = resign(delivery | {"vtc_id": vb["id"], "vtc_hash": pc.digest_over(vb)}, ks, MEDIA["delivery"])
    fb.submit_delivery(db)
    vpass = resign(verdict | {"vtc_id": vb["id"], "delivery_hash": pc.digest_over(db)}, kv, MEDIA["verdict"])
    fb.record_verdict(vpass)
    clock2[0] += vtc["challenge"]["window_seconds"] + 1
    n0 = len(fb.contracts[vb["id"]].trace)
    kinds = []
    for _ in range(3):
        try:
            fb.get_outcome(vb["id"]); kinds.append("200")
        except F.Refuse as exc:
            kinds.append(exc.kind)
    c_b = fb.contracts[vb["id"]]
    r.check(kinds == ["internal-error"] * 3 and len(c_b.trace) == n0 and c_b.outcome is None
            and c_b.state == "WINDOW_OPEN",
            "A4 a terms result that breaks closure: every call answers internal-error and the trace keeps nothing "
            "it caused (no window-closed, no repeated children-final)", f"{kinds}, {len(c_b.trace)} entries, was {n0}")
    vb2 = cosign(fresh | {"id": "vtc_a4rollback2"}, kb, ks)
    fb.propose(vb2)
    db2 = resign(delivery | {"vtc_id": vb2["id"], "vtc_hash": pc.digest_over(vb2)}, ks, MEDIA["delivery"])
    fb.submit_delivery(db2)
    n1 = len(fb.contracts[vb2["id"]].trace)
    vfail = resign(verdict | {"vtc_id": vb2["id"], "delivery_hash": pc.digest_over(db2), "outcome": "FAIL"}, kv,
                   MEDIA["verdict"])
    outcomes = []
    for _ in range(2):
        try:
            outcomes.append(fb.record_verdict(vfail)[0])
        except F.Refuse as exc:
            outcomes.append(exc.kind)
    r.check(outcomes == ["internal-error"] * 2 and len(fb.contracts[vb2["id"]].trace) == n1
            and fb.contracts[vb2["id"]].state == "DELIVERED",
            "A4 a FAIL Verdict whose terminal entry would break closure is answered internal-error twice, not "
            "recorded, and not taken for a replay the second time", f"{outcomes}")

    # A4 through a parent: a child this venue holds whose terminal entry would break closure fails
    # the parent's read with it, rolled back whole, so neither trace keeps an entry no Status
    # carried; once the profile is sound again, the parent's next read finishes the child
    clock5 = [F.parse_rfc3339("2026-11-01T09:00:00Z")]
    f5 = F.Facilitator("did:web:settle.example", mint.key_for("did:web:settle.example"), resolver,
                       now=lambda: clock5[0])
    sound = f5.profiles
    f5.profiles = {k: Broken() for k in sound}
    p5 = cosign(fresh | {"id": "vtc_a4parent"}, kb, ks)
    c5 = cosign(child_base | {"id": "vtc_a4child",
                              "parent": {"vtc_id": p5["id"], "vtc_hash": pc.digest_over(p5),
                                         "facilitator": f5.identity},
                              "task": dict(vtc["task"], deadline="2026-11-05T00:00:00Z"),
                              "parties": dict(parties, buyer=parties["seller"], seller="did:web:sub.example",
                                              facilitator=f5.identity)}, ks, ksub)
    f5.propose(p5)
    f5.propose(c5)
    f5.register_child(p5["id"], c5)
    d5 = resign(delivery | {"vtc_id": c5["id"], "vtc_hash": pc.digest_over(c5)}, ksub, MEDIA["delivery"])
    f5.submit_delivery(d5)
    f5.record_verdict(resign(verdict | {"vtc_id": c5["id"], "delivery_hash": pc.digest_over(d5)}, kv,
                             MEDIA["verdict"]))
    clock5[0] += vtc["challenge"]["window_seconds"] + 1     # the child's window has closed, unread
    cp5, cc5 = f5.contracts[p5["id"]], f5.contracts[c5["id"]]

    def held5() -> tuple:
        return list(cp5.trace), list(cc5.trace), cc5.state, list(cc5.transfers), cc5.outcome
    was5 = held5()
    kinds5 = []
    for _ in range(2):
        try:
            kinds5.append(str(f5.get_status(p5["id"])[0]))
        except F.Refuse as exc:
            kinds5.append(exc.kind)
    kept5 = held5() == was5
    f5.profiles = sound
    try:
        code5 = str(f5.get_status(p5["id"])[0])
    except F.Refuse as exc:
        code5 = exc.kind
    ev5 = [e["event"] for e in cc5.trace]
    marks5 = [e["event"] for e in cp5.trace if e.get("child") == pc.digest_over(c5)]
    r.check(kinds5 == ["internal-error"] * 2 and kept5 and code5 == "200" and cc5.state == "FINAL"
            and [ev5.count(x) for x in ("window-closed", "children-final", "terminal")] == [1, 1, 1]
            and marks5 == ["child-final"],
            "A4 through a parent: a child this venue holds whose terminal entry would break closure fails "
            "the parent's read with it, twice, and neither the parent nor the child keeps an entry it "
            "caused; once the profile is sound again, the parent's next read ends the child FINAL, each "
            "entry once, and records child-final",
            f"{kinds5}, kept {kept5}, then {code5}, child {cc5.state} {ev5}, parent's marks {marks5}")

    # A9: a record this Facilitator built that fails its own schema is its own
    # defect. The failure is forced by swapping one compiled validator for the
    # schema `false`, so the real check runs and fails.
    clock9 = [F.parse_rfc3339("2026-11-01T09:00:00Z")]
    f9 = F.Facilitator("did:web:settle.example", mint.key_for("did:web:settle.example"), resolver,
                       now=lambda: clock9[0])
    real = dict(f9.schemas._v)

    def forced(fn, schema: str) -> str:
        f9.schemas._v[schema] = Draft202012Validator(False)
        try:
            fn()
            return "accepted"
        except F.Refuse as exc:
            return exc.kind
        finally:
            f9.schemas._v[schema] = real[schema]

    v9 = cosign(fresh | {"id": "vtc_a9"}, kb, ks)
    kind = forced(lambda: f9.propose(v9), "status.schema.json")
    held = v9["id"] in f9.contracts
    code = f9.propose(v9)[0]
    r.check(kind == "internal-error" and not held and code == 201,
            "A9 a Status that fails its own schema: Propose answers internal-error, the contract is not held, "
            "and the same contract is then accepted (201, not a replay)", f"{kind}, held {held}, then {code}")
    d9 = resign(delivery | {"vtc_id": v9["id"], "vtc_hash": pc.digest_over(v9)}, ks, MEDIA["delivery"])
    f9.submit_delivery(d9)
    f9.record_verdict(resign(verdict | {"vtc_id": v9["id"], "delivery_hash": pc.digest_over(d9)}, kv,
                             MEDIA["verdict"]))
    clock9[0] += vtc["challenge"]["window_seconds"] + 1
    c9 = f9.contracts[v9["id"]]
    n9 = len(c9.trace)
    kind = forced(lambda: f9.get_outcome(v9["id"]), "outcome.schema.json")
    kept = (len(c9.trace), c9.state, c9.outcome)
    code, rec = f9.get_outcome(v9["id"])
    r.check(kind == "internal-error" and kept == (n9, "WINDOW_OPEN", None)
            and code == 200 and rec["outcome"]["state"] == "FINAL",
            "A9 an Outcome Record that fails its own schema: internal-error, no window-closed, children-final or "
            "terminal kept, and the next GET returns the record (FINAL)", f"{kind}, {kept[:2]}, then {code}")
    kind = forced(f9.capability_document, "facilitator.schema.json")
    r.check(kind == "internal-error",
            "A9 a capability document that fails its own schema is internal-error, never schema-invalid", kind)
    clock9[0] += 10 * 86400     # ten days after the last operation
    doc9 = f9.capability_document()
    r.check(doc9["issued_at"] == F.iso(clock9[0]),
            "A9 the capability document's issued_at is the instant it is signed, not the last operation's "
            "(Section 3.9)", f"issued_at {doc9['issued_at']}, clock {F.iso(clock9[0])}")
    return r.done()


if __name__ == "__main__":
    sys.exit(main())
