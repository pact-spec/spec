#!/usr/bin/env python3
"""Check the committed examples against draft-laxsharma-pact-02.

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
    r.check(pc.norm("https://a.example/") == pc.norm("https://A.example") == pc.norm(" https://a.example# "),
            "normalization folds scheme and host, strips fragment, trailing slash and whitespace (V-07)")
    ok, why = pc.signatures_ordered(vtc)
    r.check(ok, "contract signatures are sorted by normalized kid", why)
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
    ats = [e["at"] for e in tr]
    r.check(ats == sorted(ats) and status["issued_at"] >= status["trace"][-1]["at"],
            "trace timestamps never decrease and issued_at is not earlier than the last entry (Section 4.2)")
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
    r.check(sum("admission" in v for v in vecs) == 2 and len(vecs) == 9, "the bundle carries nine vectors, two of them admission vectors")
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
        for _ in range(26):
            r.skip("negative vector")
        return r.done()

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
        obj["signatures"] = sorted(entries, key=lambda e: pc.norm(json.loads(pc.b64u_decode(e["protected"]))["kid"]))
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
            lambda: fac.propose(cosign(fresh | {"parties": dict(parties, seller=parties["buyer"])}, kb, ks)),
            ("parties-not-distinct",))
    refused("V-07 seller differs from buyer by a trailing slash only",
            lambda: fac.propose(cosign(fresh | {"parties": dict(parties, seller=parties["buyer"] + "/")}, kb, ks)),
            ("parties-not-distinct",))
    refused("V-08 two buyer signatures, no seller", lambda: fac.propose(cosign(fresh, kb, kb)),
            ("unexpected-signer",))
    refused("V-09 window_seconds 0",
            lambda: fac.propose(cosign(fresh | {"challenge": dict(vtc["challenge"], window_seconds=0)}, kb, ks)),
            ("schema-invalid",))
    r.check(not conforms(taskspec | {"acceptance": {}}, "taskspec.schema.json")[0],
            "V-10 an empty acceptance object fails the TaskSpec schema")
    r.check(not conforms(taskspec | {"acceptance": {k: v for k, v in taskspec["acceptance"].items() if k != "harness_hash"}},
                         "taskspec.schema.json")[0],
            "V-11 harness_uri without harness_hash fails the TaskSpec schema")
    refused("V-12 profile_hash the Facilitator does not advertise",
            lambda: fac.propose(cosign(fresh | {"terms": dict(vtc["terms"], profile_hash=pc.h(b"other"))}, kb, ks)),
            ("terms-unsupported",))
    refused("V-13 parameters that fail the profile schema",
            lambda: fac.propose(cosign(fresh | {"terms": dict(vtc["terms"], parameters={"seller_bond": "abc"})}, kb, ks)),
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
    refused("V-20 undefined member", lambda: fac.propose(cosign(fresh | {"bonus": True}, kb, ks)), ("schema-invalid",))
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
    code, _ = fac.propose(vtc)
    r.check(code == 201, "V-01 the example contract is accepted by the reference Facilitator")
    before = len(fac.get_status(vtc["id"])[1]["trace"])
    refused("V-14 Delivery without evidence",
            lambda: fac.submit_delivery(resign({k: v for k, v in delivery.items() if k != "evidence"}, ks, MEDIA["delivery"])),
            ("evidence-nonconformant",))
    r.check(len(fac.get_status(vtc["id"])[1]["trace"]) == before, "V-14: the refused Delivery left no entry in the trace")
    code, _ = fac.submit_delivery(delivery)
    r.check(code == 202, "the example Delivery is accepted after the nonconformant one was refused")
    refused("V-17 Verdict signed by the seller", lambda: fac.record_verdict(resign(verdict, ks, MEDIA["verdict"])),
            ("verifier-not-independent",))
    unsigned_hash = pc.digest_over({k: v for k, v in delivery.items() if k != "signature"})
    refused("V-23 Verdict whose delivery_hash omits the Delivery's signature",
            lambda: fac.record_verdict(resign(verdict | {"delivery_hash": unsigned_hash}, kv, MEDIA["verdict"])),
            ("verdict-nonconformant",))
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
    return r.done()


if __name__ == "__main__":
    sys.exit(main())
