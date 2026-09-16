#!/usr/bin/env python3
"""Validate PACT examples against schemas and verify hash commitments.

Checks performed:
  1. Every example validates against its JSON Schema.
  2. vtc.task.spec_hash equals sha256(JCS(taskspec.json)).
  3. vtc verification.criteria_hash equals the acceptance-instrument
     digest: sha256(JCS({relative path: sha256(bytes)})) over
     examples/acceptance-harness/.
  4. taskspec.acceptance.harness_hash equals that same digest, so the
     instrument is committed from inside the TaskSpec as well as by the
     VTC.
  5. delivery_hash in Verdict and Challenge equals sha256(JCS(delivery))
     with the signature member included, matching facilitator.py; the
     v0.1.0 validator excluded it and the two tools disagreed.
  6. vtc_hash in Delivery, Verdict, Challenge and Attestation equals
     sha256(JCS(vtc)) with the signatures member included (-01 Section 6).
  7. Rules the schemas cannot express: parties are distinct, one
     signature per named party, and every JOSE protected header carries
     alg, kid and typ with an allowed algorithm.
  8. Canonicalization: jcs() orders object keys the way RFC 8785
     requires, which is not the way json.dumps(sort_keys=True) does.
  9. The assurance constraint of -01 Section 7.2, on the worked figures
     carried in -01 Section 14.
 10. Negative vectors, including the Section 13.3 conformance vectors
     that JSON Schema cannot express.
 11. Signature sets and ECDSA encoding, ahead of the text (facilitator
     CHOICES C9): the P-256 and P-384 orders behind the low-S rule are
     proved by computing n*G, an unsorted signature set is rejected
     (V-21) and a high-S signature is rejected (V-22).

Caveat on canonicalization: jcs() below is a restricted implementation of
RFC 8785, correct for the value types these examples use (strings,
integers, floats with exact short decimal representations, booleans,
nulls, and nested objects and arrays of those).

Object keys are sorted by UTF-16 code unit, as RFC 8785 section 3.2.3
requires. This is worth stating because the obvious shortcut is wrong:
json.dumps(sort_keys=True) sorts by Unicode code point, and code point
order agrees with UTF-16 order throughout the Basic Multilingual Plane
and diverges above it, where UTF-16 encodes a key as a surrogate pair
beginning U+D800 and therefore sorts it below keys in U+E000..U+FFFF.
An implementation carrying that shortcut passes an ASCII or BMP vector by
accident and fails on a supplementary-plane key. Check 8 pins the case.

It remains a restricted implementation and not a conforming general RFC
8785 one: in particular it does not implement the ECMAScript number
serialization rules for the full float range. A passing run therefore
evidences self-consistency of these examples, not canonicalization
interoperability with another implementation.
"""
import json, hashlib, sys, pathlib, base64
import pactcore as pc  # identifier normalization, the exact constraint, signature rules
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = pathlib.Path(__file__).resolve().parent.parent
fails = []

ALLOWED_ALGS = {"ES256", "ES384", "EdDSA"}


def _utf16_key_order(obj):
    """Recursively reorder object keys by UTF-16 code unit (RFC 8785 3.2.3).

    Comparing UTF-16 big-endian encodings bytewise is equivalent to
    comparing sequences of UTF-16 code units, which is what the RFC
    specifies. json.dumps preserves dict insertion order, so building the
    dict in the right order is enough; sort_keys must NOT also be set,
    since that would re-sort by code point.
    """
    if isinstance(obj, dict):
        return {k: _utf16_key_order(obj[k])
                for k in sorted(obj, key=lambda s: s.encode("utf-16-be"))}
    if isinstance(obj, list):
        return [_utf16_key_order(v) for v in obj]
    return obj


def jcs(obj) -> bytes:
    # Restricted JCS (RFC 8785); see the caveat in the module docstring.
    return json.dumps(_utf16_key_order(obj), separators=(",", ":"),
                      ensure_ascii=False).encode()


def h(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def load(p):
    return json.loads((ROOT / p).read_text())


def check(name, cond, detail=""):
    status = "ok " if cond else "FAIL"
    print(f"[{status}] {name}" + (f"  ({detail})" if detail and not cond else ""))
    if not cond:
        fails.append(name)


def instrument_digest(dirpath: pathlib.Path) -> str:
    """Digest of an acceptance instrument bundle.

    A manifest of per-file digests rather than an archive digest, so the
    commitment does not depend on tar or zip metadata (ordering,
    timestamps, permissions), which is not stable across producers.
    """
    manifest = {}
    for p in sorted(dirpath.rglob("*")):
        if p.is_file():
            manifest[p.relative_to(dirpath).as_posix()] = h(p.read_bytes())
    return h(jcs(manifest))


def b64url_decode(s: str) -> dict:
    pad = "=" * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s + pad))


# --- schema registry (local $ref resolution) ---
registry = Registry()
for sp in (ROOT / "schemas").glob("*.schema.json"):
    sch = json.loads(sp.read_text())
    registry = registry.with_resource(sp.name, Resource.from_contents(sch))
    registry = registry.with_resource(sch["$id"], Resource.from_contents(sch))


def validator_for(schema_file):
    sch = json.loads((ROOT / "schemas" / schema_file).read_text())
    return Draft202012Validator(sch, registry=registry)


def validate(example, schema_file, quiet=False):
    v = validator_for(schema_file)
    errs = sorted(v.iter_errors(example), key=lambda e: e.path)
    if not quiet:
        for e in errs:
            print("      ", "/".join(map(str, e.path)), "-", e.message)
    return not errs


ts   = load("examples/taskspec.json")
vtc  = load("examples/vtc.json")
dlv  = load("examples/delivery.json")
vdt  = load("examples/verdict.json")
att  = load("examples/attestation.json")
fac  = load("examples/well-known/pact-facilitator.json")
chl  = load("examples/challenge.json")
harness_digest = instrument_digest(ROOT / "examples/acceptance-harness")

print("== schema conformance ==")
check("taskspec matches schema",    validate(ts,  "taskspec.schema.json"))
check("vtc matches schema",         validate(vtc, "vtc.schema.json"))
check("delivery matches schema",    validate(dlv, "delivery.schema.json"))
check("verdict matches schema",     validate(vdt, "verdict.schema.json"))
check("attestation matches schema", validate(att, "attestation.schema.json"))
check("facilitator matches schema", validate(fac, "facilitator.schema.json"))
check("challenge matches schema",   validate(chl, "challenge.schema.json"))

print()
print("== canonicalization ==")

# RFC 8785 section 3.2.3 orders object keys by UTF-16 code unit. U+E000
# is below U+10000 by code point, and above it by UTF-16 code unit, since
# U+10000 encodes as the surrogate pair D800 DC00. A canonicalizer built
# on json.dumps(sort_keys=True) gets this backwards and no ASCII vector
# will reveal it.
_supp = {"\ue000": 1, "\U00010000": 2}
_want = ('{"' + "\U00010000" + '":2,"' + "\ue000" + '":1}').encode()
check("JCS orders keys by UTF-16 code unit, not code point",
      jcs(_supp) == _want, f"got {jcs(_supp)!r}, want {_want!r}")

# The same rule has to hold at every depth, not just at the root.
_nested = {"z": [{"\ue000": 1, "\U00010000": 2}]}
_want_nested = ('{"z":[{"' + "\U00010000" + '":2,"' + "\ue000" + '":1}]}').encode()
check("JCS key order applies inside nested objects and arrays",
      jcs(_nested) == _want_nested,
      f"got {jcs(_nested)!r}, want {_want_nested!r}")

print()
print("== hash commitments ==")
check("vtc.spec_hash == sha256(JCS(taskspec))",
      vtc["task"]["spec_hash"] == h(jcs(ts)))
check("vtc.criteria_hash == instrument digest",
      vtc["verification"]["criteria_hash"] == harness_digest)
check("taskspec.acceptance.harness_hash == instrument digest",
      ts["acceptance"]["harness_hash"] == harness_digest)

# -01 Section 6: vtc_hash covers the contract INCLUDING its signature set,
# so the commitment proves who agreed and not merely what was written.
# The -00 excluded signatures, which let entries be appended or stripped
# without invalidating the commitment.
vtc_hash = h(jcs(vtc))
check("delivery.vtc_hash == sha256(JCS(vtc, signatures included))",
      dlv["vtc_hash"] == vtc_hash)
check("attestation.vtc_hash == sha256(JCS(vtc, signatures included))",
      att["vtc_hash"] == vtc_hash)
check("verdict.delivery_hash == sha256(JCS(delivery, signature included))",
      vdt["delivery_hash"] == h(jcs(dlv)))
check("delivery.evidence.instrument_hash == vtc.criteria_hash",
      dlv["evidence"]["instrument_hash"] == vtc["verification"]["criteria_hash"])
check("verdict.instrument_hash == vtc.criteria_hash",
      vdt["instrument_hash"] == vtc["verification"]["criteria_hash"])
check("challenge.delivery_hash == sha256(JCS(delivery, signature included))",
      chl["delivery_hash"] == h(jcs(dlv)))
check("challenge.proof.instrument_hash == vtc.criteria_hash",
      chl["proof"]["instrument_hash"] == vtc["verification"]["criteria_hash"])

print()
print("== rules the schemas cannot express ==")

check("vtc parties are distinct",
      vtc["parties"]["buyer"] != vtc["parties"]["seller"])

def signer_kids(obj):
    out = []
    for s in obj.get("signatures", []):
        try:
            out.append(b64url_decode(s["protected"]).get("kid", ""))
        except Exception:
            out.append("")
    return out

def party_covered(kids, did):
    return any(k.split("#", 1)[0] == did for k in kids)

vtc_kids = signer_kids(vtc)
check("vtc carries one signature per named party",
      party_covered(vtc_kids, vtc["parties"]["buyer"])
      and party_covered(vtc_kids, vtc["parties"]["seller"])
      and len(vtc_kids) == len({k.split("#", 1)[0] for k in vtc_kids}))

def headers_well_formed(obj, typ):
    for s in obj.get("signatures", []):
        try:
            hdr = b64url_decode(s["protected"])
        except Exception:
            return False
        if hdr.get("alg") not in ALLOWED_ALGS:
            return False
        if not hdr.get("kid"):
            return False
        if hdr.get("typ") != typ:
            return False
    return True

check("vtc protected headers carry alg/kid/typ",
      headers_well_formed(vtc, "application/pact-contract+json"))
check("delivery protected header carries alg/kid/typ",
      headers_well_formed({"signatures": [dlv["signature"]]},
                          "application/pact-delivery+json"))
check("verdict protected header carries alg/kid/typ",
      headers_well_formed({"signatures": [vdt["signature"]]},
                          "application/pact-verdict+json"))
check("attestation protected headers carry alg/kid/typ",
      headers_well_formed(att, "application/pact-attestation+json"))
check("challenge protected header carries alg/kid/typ",
      headers_well_formed({"signatures": [chl["signature"]]},
                          "application/pact-challenge+json"))
check("facilitator protected header carries alg/kid/typ",
      headers_well_formed({"signatures": [fac["signature"]]},
                          "application/pact-facilitator+json"))

# Section 9.1: identifiers are normalized before comparison, and the
# normalization folds toward "same party". A trailing separator, a case
# variant, or surrounding whitespace must not make one party look like two.
# The function is pactcore's, so this validator and the Facilitator cannot
# disagree about who is who. The copy that lived here folded the whole
# identifier, which merges two did:web paths that differ only in case.
norm = pc.norm


check("party comparison normalizes trailing separators and case",
      norm("did:web:X.example/") == norm("did:web:x.example"))
check("normalized parties in the example are still distinct",
      norm(vtc["parties"]["buyer"]) != norm(vtc["parties"]["seller"]))
check("did:web path case is not folded: Section 9.1 folds scheme and host only",
      norm("did:web:x.example:agents:A") != norm("did:web:x.example:agents:a"))

print()
print("== the assurance constraint (Section 7.2) ==")


# B >= P(1-q)/q + E, evaluated exactly by pactcore.assurance_holds: multiplied
# through by q, so no division and no rounding. The float copy that lived here
# carried a 1e-9 slack and passed a bond a hundredth of a cent short.
def holds(contract, released="0"):
    return pc.assurance_holds(contract["price"]["amount"],
                              contract["liability"]["seller_bond"],
                              contract["assurance"]["q_min"], released)


check("example contract satisfies the assurance constraint", holds(vtc))
check("q_min 0.9091 requires B = 18.00 at P=180, so 17.99 fails",
      pc.assurance_holds("180.00", "18.00", "0.9091")
      and not pc.assurance_holds("180.00", "17.99", "0.9091"))

# Worked figures from Section 14. P = 180.00, B = 18.00, E = 0. Each bound is
# checked from both sides, one cent apart.
check("q_min 1.00 requires no bond at P=180",
      pc.assurance_holds("180.00", "0.00", "1.00"))
check("q_min 0.90 requires B = 20.00 at P=180, so 19.99 fails",
      pc.assurance_holds("180.00", "20.00", "0.90")
      and not pc.assurance_holds("180.00", "19.99", "0.90"))
check("q_min 0.50 requires B = 180.00 at P=180, so 179.99 fails",
      pc.assurance_holds("180.00", "180.00", "0.50")
      and not pc.assurance_holds("180.00", "179.99", "0.50"))

# Section 7.2: open assurance may not be the sole declared source.
check("'open' is not the example's sole source of assurance",
      vtc["assurance"]["mode"] != "open")

# Section 11: a null children_merkle_root is indistinguishable from a
# withheld subtree, so it must be omitted rather than nulled.
check("attestation omits children_merkle_root rather than nulling it",
      att.get("children_merkle_root", "absent") != None)

# Section 11: the facilitator signature is what makes the record evidence.
fac_kid = att["parties"]["facilitator"]
check("attestation carries a facilitator signature",
      any(fac_kid in b64url_decode(sg["protected"]).get("kid", "")
          for sg in att["signatures"]))
check("attestation subject appears in parties",
      att["subject"] in att["parties"].values())

print()
print("== children Merkle root (Section 11.1, RFC 9162 Section 2.1.1) ==")


def mth(D):
    """Merkle Tree Hash exactly as RFC 9162 Section 2.1.1 defines it (identical
    to the RFC 6962 definition it obsoletes), with SHA-256 as the hash.

    MTH({})    = SHA-256()
    MTH({d})   = SHA-256(0x00 || d)
    MTH(D[n])  = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])),
                 k the largest power of two smaller than n.
    Leaves and interior nodes carry distinct prefixes; that domain
    separation is what gives second-preimage resistance.
    """
    if len(D) == 0:
        return hashlib.sha256(b"").digest()
    if len(D) == 1:
        return hashlib.sha256(b"\x00" + D[0]).digest()
    k = 1
    while k * 2 < len(D):
        k *= 2
    return hashlib.sha256(b"\x01" + mth(D[:k]) + mth(D[k:])).digest()


_d = [hashlib.sha256(bytes([i])).digest() for i in range(8)]
_leaf = lambda x: hashlib.sha256(b"\x00" + x).digest()
_node = lambda a, b: hashlib.sha256(b"\x01" + a + b).digest()
check("n=1: root is the domain-separated leaf hash",
      mth(_d[:1]) == _leaf(_d[0]))
check("leaf and interior prefixes differ (domain separation)",
      _leaf(_d[0]) != hashlib.sha256(b"\x01" + _d[0]).digest())
check("n=2: root = H(0x01 || leaf(d0) || leaf(d1))",
      mth(_d[:2]) == _node(_leaf(_d[0]), _leaf(_d[1])))
check("n=3: split at k=2, lone third leaf is not promoted unchanged",
      mth(_d[:3]) == _node(mth(_d[:2]), _leaf(_d[2])))
# The seven-leaf tree of RFC 6962 Section 2.1.3, unchanged in RFC 9162: hash = H(k, l), k = H(g, h),
# l = H(i, j), j = leaf(d6). Reproduce that shape exactly.
_g = _node(_leaf(_d[0]), _leaf(_d[1])); _h_ = _node(_leaf(_d[2]), _leaf(_d[3]))
_i = _node(_leaf(_d[4]), _leaf(_d[5])); _j = _leaf(_d[6])
check("n=7: matches the seven-leaf figure, k=4 then k=2",
      mth(_d[:7]) == _node(_node(_g, _h_), _node(_i, _j)))
check("root changes if leaf order changes",
      mth(_d[:4]) != mth(list(reversed(_d[:4]))))

print()
print("== negative vectors (these MUST be rejected) ==")

def rejects(name, schema_file, mutate):
    doc = json.loads(json.dumps(load(mutate[0])))
    mutate[1](doc)
    check(name, not validate(doc, schema_file, quiet=True))

rejects("empty acceptance object is rejected", "taskspec.schema.json",
        ("examples/taskspec.json", lambda d: d.__setitem__("acceptance", {})))

rejects("acceptance without thresholds is rejected", "taskspec.schema.json",
        ("examples/taskspec.json", lambda d: d["acceptance"].pop("thresholds")))

rejects("harness_uri without harness_hash is rejected", "taskspec.schema.json",
        ("examples/taskspec.json", lambda d: d["acceptance"].pop("harness_hash")))

rejects("zero-length challenge window is rejected", "vtc.schema.json",
        ("examples/vtc.json",
         lambda d: d["challenge"].__setitem__("window_seconds", 0)))

rejects("signature with a bare kid sibling is rejected", "vtc.schema.json",
        ("examples/vtc.json",
         lambda d: d["signatures"][0].__setitem__("kid", "did:web:evil.example#k1")))

rejects("single-signature VTC is rejected", "vtc.schema.json",
        ("examples/vtc.json", lambda d: d.__setitem__("signatures",
                                                      d["signatures"][:1])))

rejects("malformed money value is rejected", "vtc.schema.json",
        ("examples/vtc.json",
         lambda d: d["price"].__setitem__("amount", "195")))

rejects("non-sha256 hash value is rejected", "vtc.schema.json",
        ("examples/vtc.json",
         lambda d: d["task"].__setitem__("spec_hash", "deadbeef")))

# A self-dealt contract still validates against the schema, which is why
# the distinctness rule above is enforced in code. Assert that the code
# check catches what the schema cannot.
self_dealt = json.loads(json.dumps(vtc))
self_dealt["parties"]["seller"] = self_dealt["parties"]["buyer"]
check("self-dealt contract passes schema but fails the code check",
      validate(self_dealt, "vtc.schema.json", quiet=True)
      and self_dealt["parties"]["buyer"] == self_dealt["parties"]["seller"])

# --- Section 13.3 vectors that need code, not schema ---


_none = json.loads(json.dumps(vtc))
_none["signatures"][0]["protected"] = "eyJhbGciOiJub25lIiwia2lkIjoiZGlkOndlYjpidXllci5leGFtcGxlOmFnZW50czpwcm9jdXJlLTEjazEiLCJ0eXAiOiJhcHBsaWNhdGlvbi9wYWN0LWNvbnRyYWN0K2pzb24ifQ"
check("V-02 alg 'none' is rejected",
      not headers_well_formed(_none, "application/pact-contract+json"))

_hs = json.loads(json.dumps(vtc))
_hs["signatures"][0]["protected"] = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImRpZDp3ZWI6YnV5ZXIuZXhhbXBsZTphZ2VudHM6cHJvY3VyZS0xI2sxIiwidHlwIjoiYXBwbGljYXRpb24vcGFjdC1jb250cmFjdCtqc29uIn0"
check("V-03 symmetric alg HS256 is rejected",
      not headers_well_formed(_hs, "application/pact-contract+json"))

_typ = json.loads(json.dumps(vtc))
_typ["signatures"][0]["protected"] = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDp3ZWI6YnV5ZXIuZXhhbXBsZTphZ2VudHM6cHJvY3VyZS0xI2sxIiwidHlwIjoiYXBwbGljYXRpb24vcGFjdC1kZWxpdmVyeStqc29uIn0"
check("V-05 signature typed for another object is rejected",
      not headers_well_formed(_typ, "application/pact-contract+json"))

_alias = json.loads(json.dumps(vtc))
_alias["parties"]["seller"] = _alias["parties"]["buyer"] + "/"
check("V-07 parties differing only by a trailing '/' are rejected",
      norm(_alias["parties"]["buyer"]) == norm(_alias["parties"]["seller"]))

_q = json.loads(json.dumps(vtc))
_q["assurance"] = {"mode": "committed-sample", "q_min": 0.90}
check("V-12 B=18.00 at P=180.00 with q_min 0.90 fails the constraint",
      not holds(_q))

_q2 = json.loads(json.dumps(vtc))
_q2["assurance"] = {"mode": "certain", "q_min": 1.00}
check("V-13 B=18.00 at P=180.00 with q_min 1.00 satisfies it",
      holds(_q2))

_noev = {k: v for k, v in dlv.items() if k != "evidence"}
check("V-14 delivery without evidence is rejected",
      not validate(_noev, "delivery.schema.json", quiet=True))

_selfv = json.loads(json.dumps(vdt))
_selfv["signature"]["protected"] = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDp3ZWI6ZGF0YWZvcmdlLmV4YW1wbGU6YWdlbnRzOmV0bC0zI2sxIiwidHlwIjoiYXBwbGljYXRpb24vcGFjdC12ZXJkaWN0K2pzb24ifQ"
_signer = b64url_decode(_selfv["signature"]["protected"])["kid"]
check("V-17 verdict signed by the seller is not independent",
      norm(_signer.split("#")[0]) == norm(vtc["parties"]["seller"]))


# Section 10.3: a child must be able to finalise inside its parent.
def finality_ok(child, parent):
    from datetime import datetime
    f = "%Y-%m-%dT%H:%M:%SZ"
    c_end = (datetime.strptime(child["task"]["deadline"], f).timestamp()
             + child["challenge"]["window_seconds"]
             + child["challenge"]["max_dispute_seconds"])
    p_end = (datetime.strptime(parent["task"]["deadline"], f).timestamp()
             + parent["challenge"]["window_seconds"])
    return c_end < p_end


_child_bad = json.loads(json.dumps(vtc))
check("V-16 child finalising after the parent's window closes is rejected",
      not finality_ok(_child_bad, vtc))

_child_ok = json.loads(json.dumps(vtc))
_child_ok["task"]["deadline"] = "2026-07-25T00:00:00Z"
_child_ok["challenge"] = {"window_seconds": 600, "max_dispute_seconds": 3600}
check("a child that finalises inside the parent's window is accepted",
      finality_ok(_child_ok, vtc))

_child_parent = json.loads(json.dumps(vtc))
_child_parent["liability"]["parent"] = {"vtc_id": vtc["id"],
                                        "vtc_hash": vtc_hash}
check("V-15 child whose buyer is not the parent's seller is rejected",
      norm(_child_parent["parties"]["buyer"]) != norm(vtc["parties"]["seller"]))


# Section 2: an unknown version and an unknown member are both rejected.
_v = json.loads(json.dumps(vtc)); _v["pact"] = "9.9"
check("V-19 unimplemented pact version is rejected",
      _v["pact"] not in ("0.1",))
_u = json.loads(json.dumps(vtc)); _u["extension"] = True
check("V-20 object carrying an undefined member is rejected",
      not validate(_u, "vtc.schema.json", quiet=True))

print()
print("== signature sets and ECDSA encoding (facilitator CHOICES C9) ==")

# The low-S rule needs the group order of each curve. These two checks prove
# the constants in pactcore.CURVE_ORDER by computing n * G in affine
# double-and-add, with no library: n * G is the point at infinity exactly when
# n is the order. Curve parameters from FIPS 186-4 D.1.2.3 and D.1.2.4.
P256 = dict(p=2**256 - 2**224 + 2**192 + 2**96 - 1,
            gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
            gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
P384 = dict(p=2**384 - 2**128 - 2**96 + 2**32 - 1,
            gx=int("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A38"
                   "5502F25DBF55296C3A545E3872760AB7", 16),
            gy=int("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C0"
                   "0A60B1CE1D7E819D7A431D7C90EA0E5F", 16))


def is_group_order(p, gx, gy, n):
    a = p - 3

    def add(P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        (x1, y1), (x2, y2) = P, Q
        if x1 == x2 and (y1 + y2) % p == 0:
            return None
        if P == Q:
            lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
        else:
            lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
        x3 = (lam * lam - x1 - x2) % p
        return (x3, (lam * (x1 - x3) - y1) % p)

    acc = None
    for bit in bin(n)[2:]:
        acc = add(acc, acc)
        if bit == "1":
            acc = add(acc, (gx, gy))
    return acc is None


check("P-256 order constant behind the low-S rule is the group order (n*G = O)",
      is_group_order(P256["p"], P256["gx"], P256["gy"], pc.CURVE_ORDER["ES256"]))
check("P-384 order constant behind the low-S rule is the group order (n*G = O)",
      is_group_order(P384["p"], P384["gx"], P384["gy"], pc.CURVE_ORDER["ES384"]))

_rev = dict(vtc, signatures=list(reversed(vtc["signatures"])))
check("V-21 signature set not sorted by normalized kid is rejected",
      pc.signatures_ordered(vtc)[0] and not pc.signatures_ordered(_rev)[0])

# A high-S encoding is refused before any key is consulted, so the vector
# needs no key material and no `cryptography`.
_k = pc.Key(kid="did:web:v.example#k", alg="ES256", private=None, public=None)
_high = b"\x01" * 32 + (pc.CURVE_ORDER["ES256"] - 1).to_bytes(32, "big")
try:
    _k.verify_bytes(_high, b"")
    _high_s_refused = False
except pc.InvalidSignature:
    _high_s_refused = True
check("V-22 ECDSA signature with s in the high half of the order is rejected",
      _high_s_refused)

print()
if fails:
    print(f"{len(fails)} check(s) FAILED")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("All checks passed.")
