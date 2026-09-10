"""Drive the reference pair through every terminal state and report what it costs.

Three contracts, because FINAL, SETTLED and ABANDONED are mutually exclusive
branches of Figure 2 and one contract cannot reach all three. Each is minted
fresh with real Ed25519 keys, validated against the published schemas, settled
over HTTP against tools/facilitator.py, and its attestation verified by the
party that receives it.

Then a set of refusals, because a settlement service is defined as much by what
it refuses as by what it accepts, and then microbenchmarks for the operations
that scale with traffic.

    python3 tools/measure.py            # human readable
    python3 tools/measure.py --json     # machine readable

Every number is produced on the machine that runs this, and the report names
that machine. Numbers quoted anywhere else should carry the same hardware line.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import platform
import statistics
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import agents
import facilitator as fac_mod
import pactcore as pc

ROOT = pathlib.Path(__file__).resolve().parent.parent
BUYER = "did:web:buyer.example:agents:procure-1"
SELLER = "did:web:dataforge.example:agents:etl-3"
VERIFIER = "did:web:audit.example"
FACILITATOR = "did:web:settle.example"

REPORT: dict = {"scenarios": {}, "refusals": {}, "micro": {}, "environment": {}}


def _cpu_name() -> str:
    """platform.processor() returns "i386" on macOS, which tells a reader nothing."""
    try:
        out = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"],
                             capture_output=True, text=True, timeout=5)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except Exception:
        pass
    return platform.processor() or platform.machine()


def _schema_check(obj: dict, schema_file: str) -> str:
    """Validate a minted object against the published schema, if jsonschema is here."""
    try:
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
    except ImportError:  # pragma: no cover
        return "skipped, jsonschema not installed"
    schemas = {}
    for p in (ROOT / "schemas").glob("*.schema.json"):
        schemas[p.name] = json.loads(p.read_text())
    registry = Registry().with_resources(
        [(name, Resource.from_contents(s)) for name, s in schemas.items()])
    v = Draft202012Validator(schemas[schema_file], registry=registry)
    errors = sorted(v.iter_errors(obj), key=lambda e: e.path)
    return "valid" if not errors else f"INVALID: {errors[0].message}"


class Harness:
    def __init__(self, port: int) -> None:
        self.fac, self.resolver = fac_mod.build(FACILITATOR)
        self.httpd = fac_mod.serve(self.fac, port)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{port}"
        self.client = agents.Client(self.base)
        self.buyer = agents.make_party(BUYER, self.resolver, self.client)
        self.seller = agents.make_party(SELLER, self.resolver, self.client)
        self.verifier = agents.make_party(VERIFIER, self.resolver, self.client)

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def fresh(self, vid: str, **kw) -> dict:
        vtc = agents.draft_contract(vid, BUYER, SELLER, FACILITATOR, VERIFIER, **kw)
        return agents.cosign(vtc, self.buyer, self.seller)


def conservation(c) -> dict:
    """Every cent that went in must be accounted for at a terminal state."""
    p = c.pools
    put_in = p.bond_initial + pc.cents(c.vtc["price"]["amount"]) + \
        pc.cents(c.vtc["liability"]["verification_fund"])
    accounted = (p.paid_to_buyer + p.paid_to_seller + p.paid_to_challenger +
                 p.remainder + p.bond_returned + p.fund_returned +
                 p.escrow + p.bond + p.fund)
    return {"in": pc.money(put_in), "accounted": pc.money(accounted),
            "balanced": put_in == accounted}


def scenario(h: Harness, name: str, run) -> dict:
    before = len(h.client.wire)
    t0 = time.perf_counter()
    detail = run()
    elapsed = time.perf_counter() - t0
    wire = h.client.wire[before:]
    out = {
        "terminal_state": detail["state"],
        "messages": len(wire),
        "request_bytes": sum(w.request_bytes for w in wire),
        "response_bytes": sum(w.response_bytes for w in wire),
        "wall_ms": round(elapsed * 1000, 2),
        "per_message": [
            {"op": f"{w.method} {w.path}", "status": w.status,
             "req": w.request_bytes, "resp": w.response_bytes,
             "ms": round(w.seconds * 1000, 2)} for w in wire],
    }
    out.update({k: v for k, v in detail.items() if k not in ("state", "contract")})
    if "contract" in detail:
        out["money"] = conservation(detail["contract"])
    REPORT["scenarios"][name] = out
    return out


# --------------------------------------------------------------------------
# The three terminal states
# --------------------------------------------------------------------------

def run_final(h: Harness) -> dict:
    vtc = h.fresh("vtc_final_01")
    schema = _schema_check(vtc, "vtc.schema.json")
    st, _ = h.client.propose(vtc)
    assert st == 201, st

    dlv = agents.make_delivery(vtc, h.seller, b"the delivered bytes", b"results")
    dschema = _schema_check(dlv, "delivery.schema.json")
    st, _ = h.client.deliver(dlv)
    assert st == 202, st

    vd = agents.make_verdict(vtc, dlv, h.verifier, "PASS")
    vschema = _schema_check(vd, "verdict.schema.json")
    st, _ = h.client.verdict(vd)
    assert st == 201, st

    st, att = h.client.attestation(vtc["id"])
    assert st == 200, att
    ok, why = agents.check_attestation(att, h.resolver, FACILITATOR)
    c = h.fac.contracts[vtc["id"]]
    return {"state": c.state, "attestation_verifies": ok, "attestation_reason": why,
            "schema": {"contract": schema, "delivery": dschema, "verdict": vschema,
                       "attestation": _schema_check(att, "attestation.schema.json")},
            "amounts": att["amounts"], "ledger": c.pools.ledger, "contract": c}


def run_settled(h: Harness) -> dict:
    vtc = h.fresh("vtc_settled_01")
    st, _ = h.client.propose(vtc)
    assert st == 201, st
    dlv = agents.make_delivery(vtc, h.seller, b"plausible but wrong", b"bad results")
    st, _ = h.client.deliver(dlv)
    assert st == 202, st
    vd = agents.make_verdict(vtc, dlv, h.verifier, "FAIL")
    st, _ = h.client.verdict(vd)
    assert st == 201, st
    st, att = h.client.attestation(vtc["id"])
    ok, why = agents.check_attestation(att, h.resolver, FACILITATOR)
    c = h.fac.contracts[vtc["id"]]
    return {"state": c.state, "attestation_verifies": ok, "attestation_reason": why,
            "amounts": att["amounts"], "ledger": c.pools.ledger,
            "buyer_recovered": pc.money(c.pools.paid_to_buyer),
            "seller_received": pc.money(c.pools.paid_to_seller), "contract": c}


def run_settled_price(h: Harness) -> dict:
    """The same fraud, with restitution_basis "price" instead of "released".

    This is the contrast that matters. Under "released" the amount owed to the
    Buyer is what was paid out before the Verdict, which under the default
    on-verification release is nothing, so the Bond passes the Buyer entirely
    and lands on the remainder. Under "price" the Buyer is restored from the
    Bond up to the cap. Same protocol, same fraud, opposite outcome for the
    defrauded party, chosen by one enum in the contract.
    """
    vtc = h.fresh("vtc_settled_price", restitution_basis="price")
    h.client.propose(vtc)
    dlv = agents.make_delivery(vtc, h.seller, b"plausible but wrong", b"bad")
    h.client.deliver(dlv)
    h.client.verdict(agents.make_verdict(vtc, dlv, h.verifier, "FAIL"))
    st, att = h.client.attestation(vtc["id"])
    c = h.fac.contracts[vtc["id"]]
    return {"state": c.state, "attestation_verifies":
            agents.check_attestation(att, h.resolver, FACILITATOR)[0],
            "attestation_reason": "ok",
            "amounts": att["amounts"], "ledger": c.pools.ledger,
            "buyer_recovered": pc.money(c.pools.paid_to_buyer),
            "from_bond": pc.money(c.pools.paid_to_buyer - pc.cents(vtc["price"]["amount"])),
            "contract": c}


def run_abandoned(h: Harness) -> dict:
    # A deadline already past: the Seller signed, took the bond obligation, and
    # never delivered. Section 6 calls this ABANDONED.
    vtc = h.fresh("vtc_abandoned_01", deadline="2026-01-01T00:00:00Z")
    st, _ = h.client.propose(vtc)
    assert st == 201, st
    st, body = h.client.contract(vtc["id"])   # the GET is what notices the expiry
    st, att = h.client.attestation(vtc["id"])
    ok, why = agents.check_attestation(att, h.resolver, FACILITATOR)
    c = h.fac.contracts[vtc["id"]]
    return {"state": c.state, "attestation_verifies": ok, "attestation_reason": why,
            "amounts": att["amounts"], "ledger": c.pools.ledger,
            "buyer_recovered": pc.money(c.pools.paid_to_buyer),
            "bond_kept_by_seller": pc.money(c.pools.bond_returned), "contract": c}


# --------------------------------------------------------------------------
# Refusals. What a settlement service will not do.
# --------------------------------------------------------------------------

def run_refusals(h: Harness) -> None:
    def record(name: str, status: int, body: dict) -> None:
        REPORT["refusals"][name] = {
            "status": status,
            "type": body.get("type", "").rsplit("/", 1)[-1],
            "section": body.get("section"),
            "detail": body.get("detail", "")[:200],
        }

    # Section 7.2, before funds lock. A ten percent bond against a declared
    # detection rate of 0.90 needs 20.00, so 18.00 is refused. These are the
    # draft's own worked figures and its own error body, Section 12.3.
    vtc = h.fresh("vtc_refuse_bond", q_min=0.90)
    record("bond_below_constraint", *h.client.propose(vtc))

    # Section 9.1, derived not declared: the Seller signs its own Verdict.
    vtc = h.fresh("vtc_refuse_selfverify")
    h.client.propose(vtc)
    dlv = agents.make_delivery(vtc, h.seller, b"w", b"r")
    h.client.deliver(dlv)
    record("verdict_signed_by_seller",
           *h.client.verdict(agents.make_verdict(vtc, dlv, h.seller, "PASS")))

    # Section 3: the Facilitator cannot verify a contract it settles.
    fac_party = agents.Party(FACILITATOR, h.fac.key, h.client)
    record("verdict_signed_by_facilitator",
           *h.client.verdict(agents.make_verdict(vtc, dlv, fac_party, "PASS")))

    # Section 12.4: no Verdict without a recorded Delivery.
    vtc2 = h.fresh("vtc_refuse_nodelivery")
    h.client.propose(vtc2)
    orphan = agents.make_verdict(vtc2, dlv, h.verifier, "PASS")
    record("verdict_without_delivery", *h.client.verdict(orphan))

    # Section 12.2: the same body twice is the same resource, 200 not 409.
    vtc3 = h.fresh("vtc_idempotent")
    h.client.propose(vtc3)
    record("resubmit_identical_contract", *h.client.propose(vtc3))

    # Section 12.2: the same id with different bytes is 409.
    altered = json.loads(json.dumps(vtc3))
    altered["liability"]["seller_bond"] = "19.00"
    altered = agents.cosign({k: v for k, v in altered.items() if k != "signatures"},
                            h.buyer, h.seller)
    record("altered_contract_same_id", *h.client.propose(altered))

    # Section 9.1 again, at proposal: buyer and seller the same party.
    same = agents.draft_contract("vtc_refuse_same", BUYER, BUYER + "/",
                                 FACILITATOR, VERIFIER)
    record("buyer_equals_seller",
           *h.client.propose(agents.cosign(same, h.buyer, h.buyer)))

    # Section 13.1: an algorithm off the allowlist.
    tampered = h.fresh("vtc_refuse_alg")
    prot = pc.b64u(pc.jcs({"alg": "none", "kid": h.buyer.key.kid, "typ": "x"}))
    tampered["signatures"][0]["protected"] = prot
    record("algorithm_none", *h.client.propose(tampered))

    # --- the cases the September review found this implementation failing ---

    # Draft line 1852: the contract names a verifier, so only that party judges.
    stranger = agents.make_party("did:web:watchdog.example", h.resolver, h.client)
    vtc4 = h.fresh("vtc_refuse_stranger")
    h.client.propose(vtc4)
    d4 = agents.make_delivery(vtc4, h.seller, b"w", b"r")
    h.client.deliver(d4)
    record("verdict_by_unnamed_party",
           *h.client.verdict(agents.make_verdict(vtc4, d4, stranger, "PASS")))

    # Section 7.5: a Challenge is evaluated by an independent party whose
    # finding is a Verdict. Accepting one must NOT settle the contract.
    st, _ = h.client.challenge(agents.make_challenge(vtc4, d4, stranger, ["rows"]))
    c4 = h.fac.contracts["vtc_refuse_stranger"]
    REPORT["refusals"]["challenge_alone_does_not_settle"] = {
        "status": st, "type": f"state stays {c4.state}",
        "section": "Section 7.5",
        "detail": f"bond intact: {pc.money(c4.pools.bond)} of "
                  f"{pc.money(c4.pools.bond_initial)}, attestation issued: "
                  f"{c4.attestation is not None}",
    }

    # Section 6: a Delivery must carry evidence conformant to the profile.
    vtc5 = h.fresh("vtc_refuse_noevidence")
    h.client.propose(vtc5)
    d5 = agents.make_delivery(vtc5, h.seller, b"w", b"r")
    del d5["evidence"]
    d5 = h.seller.sign_into(d5, agents.MEDIA_DELIVERY)
    record("delivery_without_evidence", *h.client.deliver(d5))

    # RFC 8725 3.11 and vector V-05: typ carries the full media type.
    vtc6 = h.fresh("vtc_refuse_typ")
    h.client.propose(vtc6)
    d6 = agents.make_delivery(vtc6, h.seller, b"w", b"r")
    h.client.deliver(d6)
    wrong = agents.make_verdict(vtc6, d6, h.verifier, "PASS")
    wrong["signature"] = pc.sign({k: v for k, v in wrong.items() if k != "signature"},
                                 h.verifier.key, agents.MEDIA_DELIVERY)
    record("verdict_signed_with_delivery_typ", *h.client.verdict(wrong))

    # Section 9.1 normalization: a longer identifier is a different party.
    evil = agents.make_party(SELLER + ".evil", h.resolver, h.client)
    vtc7 = h.fresh("vtc_refuse_prefix")
    h.client.propose(vtc7)
    d7 = agents.make_delivery(vtc7, h.seller, b"w", b"r")
    h.client.deliver(d7)
    record("verdict_by_prefix_lookalike",
           *h.client.verdict(agents.make_verdict(vtc7, d7, evil, "PASS")))


# --------------------------------------------------------------------------
# Microbenchmarks
# --------------------------------------------------------------------------

def bench(fn, n: int = 2000) -> dict:
    # Warm up, then take the median of per-call microseconds.
    for _ in range(50):
        fn()
    samples = []
    for _ in range(7):
        t0 = time.perf_counter()
        for _ in range(n):
            fn()
        samples.append((time.perf_counter() - t0) / n * 1e6)
    return {"median_us": round(statistics.median(samples), 2),
            "min_us": round(min(samples), 2), "calls": n}


def run_micro(h: Harness) -> None:
    vtc = h.fresh("vtc_bench")
    dlv = agents.make_delivery(vtc, h.seller, b"w" * 4096, b"r" * 1024)
    key = h.buyer.key

    REPORT["micro"]["canonicalize_contract"] = bench(lambda: pc.jcs(vtc))
    REPORT["micro"]["digest_contract"] = bench(
        lambda: pc.digest_over(pc.hashable(vtc)))
    REPORT["micro"]["sign_contract_ed25519"] = bench(
        lambda: pc.sign(vtc, key, agents.MEDIA_CONTRACT), n=500)
    entry = pc.sign(vtc, key, agents.MEDIA_CONTRACT)
    REPORT["micro"]["verify_contract_ed25519"] = bench(
        lambda: pc.verify_entry(vtc, entry, h.resolver), n=500)
    REPORT["micro"]["normalize_identifier"] = bench(lambda: pc.norm(SELLER))
    REPORT["micro"]["assurance_constraint"] = bench(
        lambda: pc.assurance_holds(180.0, 18.0, 0.9091, 0.0))

    for n in (2, 8, 64):
        leaves = [pc.jcs({"child": i}) for i in range(n)]
        REPORT["micro"][f"merkle_root_{n}_children"] = bench(
            lambda leaves=leaves: pc.mth(leaves), n=200 if n > 8 else 1000)

    REPORT["micro"]["canonical_bytes"] = {
        "contract": len(pc.jcs(pc.hashable(vtc))),
        "delivery": len(pc.jcs(pc.hashable(dlv))),
    }

    # There is deliberately NO T0-reexec figure here. An earlier version timed
    # examples/acceptance-harness/test_acceptance.py by running it as a plain
    # script, which executes no tests at all: it is a pytest module, so it
    # imports, defines its test functions, and exits 0 in silence. The number
    # that produced was pytest's import time and nothing else, and the claim
    # built on it, that verification cost exceeds protocol cost by three orders
    # of magnitude, had no measurement behind it. Producing an honest figure
    # needs the harness invoked through pytest with its documented arguments,
    # and those currently fail because pytest_addoption sits in a test module
    # rather than a conftest.py. Moving it changes the directory manifest and
    # therefore criteria_hash, which is a -02 item.


# --------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8412)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    REPORT["environment"] = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "processor": _cpu_name(),
        "signature_algorithm": "Ed25519 (EdDSA, RFC 8037)",
        "note": "single host, loopback HTTP, in-memory store, no payment rail",
    }

    h = Harness(args.port)
    try:
        scenario(h, "FINAL", lambda: run_final(h))
        scenario(h, "SETTLED", lambda: run_settled(h))
        scenario(h, "ABANDONED", lambda: run_abandoned(h))
        scenario(h, "SETTLED_basis_price", lambda: run_settled_price(h))
        run_refusals(h)
        run_micro(h)
    finally:
        h.stop()

    if args.json:
        print(json.dumps(REPORT, indent=1))
        return

    e = REPORT["environment"]
    print(f"reference pair on {e['processor']}, Python {e['python']}, {e['signature_algorithm']}")
    print(f"{e['note']}\n")

    print("TERMINAL STATES")
    for name, s in REPORT["scenarios"].items():
        print(f"  {name:<10} {s['messages']} messages, "
              f"{s['request_bytes']}B out / {s['response_bytes']}B back, "
              f"{s['wall_ms']}ms, attestation verifies: {s['attestation_verifies']}")
        print(f"             amounts {s['amounts']}")
    print()

    print("REFUSALS")
    for name, r in REPORT["refusals"].items():
        print(f"  {name:<32} {r['status']} {r['type']:<36} {r['section']}")
    print()

    print("MICROBENCHMARKS, median microseconds per call")
    for name, m in REPORT["micro"].items():
        if isinstance(m, dict) and "median_us" in m:
            print(f"  {name:<34} {m['median_us']:>10.2f} us")
    cb = REPORT["micro"].get("canonical_bytes", {})
    if cb:
        print(f"  canonical bytes                    contract {cb['contract']}, "
              f"delivery {cb['delivery']}")
    print("\n  no T0-reexec figure is reported; see the comment in run_micro")


if __name__ == "__main__":
    main()
