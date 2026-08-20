#!/usr/bin/env python3
"""Validate PACT examples against schemas and verify hash commitments.

Checks performed:
  1. Every example validates against its JSON Schema.
  2. cfb.task.spec_hash and vtc.task.spec_hash equal
     sha256(JCS(taskspec.json)).
  3. cfb/vtc verification.criteria_hash equals the acceptance-instrument
     digest: sha256(JCS({relative path: sha256(bytes)})) over
     examples/acceptance-harness/.
  4. taskspec.acceptance.harness_hash equals that same digest, so the
     instrument is committed from inside the TaskSpec as well as by the
     CFB and the VTC.
  5. bid.commitment equals sha256(JCS(bid-reveal.reveal)).
  6. attestation.vtc_hash equals sha256(JCS(vtc without signatures)).
  7. Rules the schemas cannot express: parties are distinct, one
     signature per named party, and every JOSE protected header carries
     alg, kid and typ with an allowed algorithm.
  8. Canonicalization: jcs() orders object keys the way RFC 8785
     requires, which is not the way json.dumps(sort_keys=True) does.
  9. Negative vectors: mutations that MUST be rejected actually are.

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
cfb  = load("examples/cfb.json")
bid  = load("examples/bid.json")
rev  = load("examples/bid-reveal.json")
vtc  = load("examples/vtc.json")
att  = load("examples/attestation.json")
wk   = load("examples/well-known/pact.json")
harness_digest = instrument_digest(ROOT / "examples/acceptance-harness")

print("== schema conformance ==")
check("taskspec matches schema",    validate(ts,  "taskspec.schema.json"))
check("cfb matches schema",         validate(cfb, "cfb.schema.json"))
check("bid matches schema",         validate(bid, "bid.schema.json"))
check("vtc matches schema",         validate(vtc, "vtc.schema.json"))
check("attestation matches schema", validate(att, "attestation.schema.json"))
check("well-known matches schema",  validate(wk,  "wellknown.schema.json"))

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
check("cfb.spec_hash == sha256(JCS(taskspec))",
      cfb["task"]["spec_hash"] == h(jcs(ts)))
check("vtc.spec_hash == sha256(JCS(taskspec))",
      vtc["task"]["spec_hash"] == h(jcs(ts)))
check("cfb.criteria_hash == instrument digest",
      cfb["verification"]["criteria_hash"] == harness_digest)
check("vtc.criteria_hash == instrument digest",
      vtc["verification"]["criteria_hash"] == harness_digest)
check("taskspec.acceptance.harness_hash == instrument digest",
      ts["acceptance"]["harness_hash"] == harness_digest)
check("bid.commitment == sha256(JCS(reveal))",
      bid["commitment"] == h(jcs(rev["reveal"])))
core = {k: v for k, v in vtc.items() if k != "signatures"}
check("attestation.vtc_hash == sha256(JCS(vtc-sans-signatures))",
      att["vtc_hash"] == h(jcs(core)))

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

check("cfb protected headers carry alg/kid/typ",
      headers_well_formed(cfb, "application/pact-cfb+json"))
check("bid protected headers carry alg/kid/typ",
      headers_well_formed(bid, "application/pact-bid+json"))
check("vtc protected headers carry alg/kid/typ",
      headers_well_formed(vtc, "application/pact-contract+json"))
check("attestation protected headers carry alg/kid/typ",
      headers_well_formed(att, "application/pact-attestation+json"))

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

print()
if fails:
    print(f"{len(fails)} check(s) FAILED")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("All checks passed.")
