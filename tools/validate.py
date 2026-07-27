#!/usr/bin/env python3
"""Validate PACT examples against schemas and verify hash commitments.

Checks performed:
  1. Every example validates against its JSON Schema.
  2. cfb.task.spec_hash and vtc.task.spec_hash equal
     sha256(JCS(taskspec.json)).
  3. cfb/vtc verification.criteria_hash equals
     sha256(acceptance-tests file).
  4. bid.commitment equals sha256(JCS(bid-reveal.reveal)).
  5. attestation.vtc_hash equals sha256(JCS(vtc without signatures)).
"""
import json, hashlib, sys, pathlib
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = pathlib.Path(__file__).resolve().parent.parent
fails = []

def jcs(obj) -> bytes:
    # JCS (RFC 8785) for objects limited to strings, integers,
    # booleans, nulls, and nested objects/arrays thereof.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
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

# --- schema registry (local $ref resolution) ---
registry = Registry()
for sp in (ROOT / "schemas").glob("*.schema.json"):
    sch = json.loads(sp.read_text())
    registry = registry.with_resource(sp.name, Resource.from_contents(sch))
    registry = registry.with_resource(sch["$id"], Resource.from_contents(sch))

def validate(example, schema_file):
    sch = json.loads((ROOT / "schemas" / schema_file).read_text())
    v = Draft202012Validator(sch, registry=registry)
    errs = sorted(v.iter_errors(example), key=lambda e: e.path)
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
harness = (ROOT / "examples/acceptance-tests.txt").read_bytes()

check("taskspec matches schema",    validate(ts,  "taskspec.schema.json"))
check("cfb matches schema",         validate(cfb, "cfb.schema.json"))
check("bid matches schema",         validate(bid, "bid.schema.json"))
check("vtc matches schema",         validate(vtc, "vtc.schema.json"))
check("attestation matches schema", validate(att, "attestation.schema.json"))
check("well-known matches schema",  validate(wk,  "wellknown.schema.json"))

check("cfb.spec_hash == sha256(JCS(taskspec))",
      cfb["task"]["spec_hash"] == h(jcs(ts)))
check("vtc.spec_hash == sha256(JCS(taskspec))",
      vtc["task"]["spec_hash"] == h(jcs(ts)))
check("cfb.criteria_hash == sha256(harness)",
      cfb["verification"]["criteria_hash"] == h(harness))
check("vtc.criteria_hash == sha256(harness)",
      vtc["verification"]["criteria_hash"] == h(harness))
check("bid.commitment == sha256(JCS(reveal))",
      bid["commitment"] == h(jcs(rev["reveal"])))
core = {k: v for k, v in vtc.items() if k != "signatures"}
check("attestation.vtc_hash == sha256(JCS(vtc-sans-signatures))",
      att["vtc_hash"] == h(jcs(core)))

print()
if fails:
    print(f"{len(fails)} check(s) FAILED"); sys.exit(1)
print("All checks passed.")
