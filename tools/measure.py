"""Drive the reference pair through every terminal state and report what it costs.

Four contracts, because FINAL, SETTLED and ABANDONED are mutually exclusive
branches of Figure 2 and one contract cannot reach all three, and because the
Figure 6 path (a Challenge overturns a PASS) is the one that exercises the
restitution basis. Each is minted fresh with real Ed25519 keys, validated
against the published schemas, settled over HTTP against tools/facilitator.py,
and its attestation verified by the party that receives it.

Time is the Facilitator's clock (draft line 480), and here that clock is a
counter the harness advances, so the challenge window and the deadline are
exercised deterministically rather than waited for.

Then the refusals, because a settlement service is defined as much by what it
refuses as by what it accepts, each one driving the rule it is named for, and
then microbenchmarks for the operations that scale with traffic.

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
WINDOW = 3600
DISPUTE = 86400

REPORT: dict = {"scenarios": {}, "refusals": {}, "acceptances": {}, "micro": {},
                "capability_document": {}, "environment": {}}


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


_SCHEMAS = None


def _schema_check(obj: dict, schema_file: str) -> str:
    """Validate a minted object against the published schema. Loaded once, and
    never inside a timed region."""
    global _SCHEMAS
    if _SCHEMAS is None:
        _SCHEMAS = fac_mod.Schemas()
    try:
        _SCHEMAS.check(obj, schema_file)
    except fac_mod.Refuse as exc:
        return f"INVALID: {exc.detail}"
    return "valid"


class Clock:
    """The Facilitator's clock, advanced by the harness."""
    def __init__(self) -> None:
        self.t = time.time()

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds

    def at(self, seconds_ahead: float) -> str:
        return fac_mod.iso(self.t + seconds_ahead)


class Harness:
    def __init__(self, port: int) -> None:
        self.clock = Clock()
        base = f"http://127.0.0.1:{port}"
        self.fac, self.resolver = fac_mod.build(FACILITATOR, now=self.clock, base_url=base)
        self.httpd = fac_mod.serve(self.fac, port)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.client = agents.Client(base)
        self.buyer = agents.make_party(BUYER, self.resolver, self.client)
        self.seller = agents.make_party(SELLER, self.resolver, self.client)
        self.verifier = agents.make_party(VERIFIER, self.resolver, self.client)

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def fresh(self, vid: str, verifier: str | None = VERIFIER, **kw) -> dict:
        kw.setdefault("deadline", self.clock.at(7 * 86400))
        vtc = agents.draft_contract(vid, BUYER, SELLER, FACILITATOR, verifier, **kw)
        return agents.cosign(vtc, self.buyer, self.seller)


def conservation(c) -> dict:
    """Every cent that went in is somewhere it can be named, at a terminal state.

    This is a ledger identity over the Facilitator's own pools, which is what
    an in-memory implementation can check. It is asserted, not merely
    computed: a scenario whose money does not balance fails the run.
    """
    p = c.pools
    put_in = p.bond_initial + pc.cents(c.vtc["price"]["amount"]) + \
        pc.cents(c.vtc["liability"]["verification_fund"])
    accounted = (p.paid_to_buyer + p.paid_to_seller + p.paid_to_challenger +
                 p.remainder + p.bond_returned + p.fund_returned +
                 p.escrow + p.bond + p.fund)
    out = {"in": pc.money(put_in), "accounted": pc.money(accounted),
           "balanced": put_in == accounted}
    assert out["balanced"], f"money does not balance for {c.id}: {out}"
    return out


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
    c = detail.pop("contract")
    att = c.attestation
    ok, why = agents.check_attestation(att, h.resolver, FACILITATOR)
    out["attestation_verifies"] = ok
    out["attestation_reason"] = why
    out["amounts"] = att["amounts"]
    out["ledger"] = c.pools.ledger
    out["money"] = conservation(c)
    out["schema"] = {k: _schema_check(v, f) for k, (v, f) in detail.pop("objects", {}).items()}
    out.update({k: v for k, v in detail.items() if k != "state"})
    REPORT["scenarios"][name] = out
    return out


# --------------------------------------------------------------------------
# The terminal states
# --------------------------------------------------------------------------

def run_final(h: Harness) -> dict:
    """PASS, window closes with no Challenge, FINAL. Four exchanges."""
    vtc = h.fresh("vtc_final_01")
    st, _ = h.client.propose(vtc)
    assert st == 201, st
    dlv = agents.make_delivery(vtc, h.seller, b"the delivered bytes", b"results")
    st, _ = h.client.deliver(dlv)
    assert st == 202, st
    vd = agents.make_verdict(vtc, dlv, h.verifier, "PASS")
    st, body = h.client.verdict(vd)
    assert st == 201 and body["state"] == "RELEASING", (st, body.get("state"))
    h.clock.advance(WINDOW + 1)          # the window closes on the Facilitator's clock
    st, att = h.client.attestation(vtc["id"])   # the GET is what notices it
    assert st == 200, att
    c = h.fac.contracts[vtc["id"]]
    return {"state": c.state, "contract": c,
            "objects": {"contract": (vtc, "vtc.schema.json"),
                        "delivery": (dlv, "delivery.schema.json"),
                        "verdict": (vd, "verdict.schema.json"),
                        "attestation": (att, "attestation.schema.json")}}


def run_settled(h: Harness) -> dict:
    """The verifier records FAIL: DISPUTED, remedy, SETTLED. Four exchanges."""
    vtc = h.fresh("vtc_settled_01")
    h.client.propose(vtc)
    dlv = agents.make_delivery(vtc, h.seller, b"plausible but wrong", b"bad results")
    h.client.deliver(dlv)
    st, body = h.client.verdict(agents.make_verdict(vtc, dlv, h.verifier, "FAIL"))
    assert st == 201 and body["state"] == "SETTLED", (st, body.get("state"))
    st, att = h.client.attestation(vtc["id"])
    c = h.fac.contracts[vtc["id"]]
    return {"state": c.state, "contract": c,
            "buyer_recovered": pc.money(c.pools.paid_to_buyer),
            "seller_received": pc.money(c.pools.paid_to_seller)}


def run_abandoned(h: Harness) -> dict:
    """Signed, funded, never delivered: the deadline passes. Three exchanges."""
    vtc = h.fresh("vtc_abandoned_01", deadline=h.clock.at(3600))
    st, _ = h.client.propose(vtc)
    assert st == 201, st
    h.clock.advance(3601)
    st, body = h.client.contract(vtc["id"])      # the GET is what notices the expiry
    assert st == 200 and body["state"] == "ABANDONED", (st, body.get("state"))
    st, att = h.client.attestation(vtc["id"])
    c = h.fac.contracts[vtc["id"]]
    return {"state": c.state, "contract": c,
            "buyer_recovered": pc.money(c.pools.paid_to_buyer),
            "bond_returned_to_seller": pc.money(c.pools.bond_returned)}


def run_overturned(h: Harness) -> dict:
    """Figure 6: PASS, the price releases, the Buyer challenges inside the
    window, an independent Verdict upholds the Challenge, the waterfall runs
    with the price already gone. Five exchanges. This is the path where the
    restitution basis does any work."""
    vtc = h.fresh("vtc_overturned_01")
    h.client.propose(vtc)
    dlv = agents.make_delivery(vtc, h.seller, b"looked fine at first", b"results")
    h.client.deliver(dlv)
    st, body = h.client.verdict(agents.make_verdict(vtc, dlv, h.verifier, "PASS"))
    assert st == 201 and body["state"] == "RELEASING", (st, body.get("state"))
    h.clock.advance(600)
    ch = agents.make_challenge(vtc, dlv, h.buyer, ["row_count_min"])
    st, body = h.client.challenge(ch)
    assert st == 202 and body["state"] == "DISPUTED", (st, body)
    st, body = h.client.verdict(agents.make_verdict(vtc, dlv, h.verifier, "FAIL"))
    assert st == 201 and body["state"] == "SETTLED", (st, body)
    st, att = h.client.attestation(vtc["id"])
    c = h.fac.contracts[vtc["id"]]
    return {"state": c.state, "contract": c,
            "released_before_failure": pc.money(c.pools.released),
            "buyer_recovered_from_bond": pc.money(c.pools.restituted),
            "challenger_bounty": pc.money(c.pools.paid_to_challenger),
            "objects": {"challenge": (ch, "challenge.schema.json")}}


def run_settled_price(h: Harness) -> dict:
    """The pre-release FAIL again, with restitution_basis "price". Under the
    net-of-loss reading (facilitator.py CHOICES C2) the Buyer's loss is zero
    after rank 1 either way, so the basis changes nothing here; it only
    matters once value has been released, which is run_overturned."""
    vtc = h.fresh("vtc_settled_price", restitution_basis="price")
    h.client.propose(vtc)
    dlv = agents.make_delivery(vtc, h.seller, b"plausible but wrong", b"bad")
    h.client.deliver(dlv)
    h.client.verdict(agents.make_verdict(vtc, dlv, h.verifier, "FAIL"))
    h.client.attestation(vtc["id"])
    c = h.fac.contracts[vtc["id"]]
    return {"state": c.state, "contract": c,
            "buyer_recovered": pc.money(c.pools.paid_to_buyer),
            "from_bond": pc.money(c.pools.restituted)}


# --------------------------------------------------------------------------
# Refusals. What a settlement service will not do, each driving the rule it
# is named for. Two acceptances are reported separately because they are
# acceptances, not refusals, and counting them as refusals was a lie.
# --------------------------------------------------------------------------

def run_refusals(h: Harness) -> None:
    def record(name: str, status: int, body: dict) -> None:
        REPORT["refusals"][name] = {
            "status": status,
            "type": body.get("type", "").rsplit("/", 1)[-1],
            "section": body.get("section"),
            "detail": body.get("detail", "")[:200],
        }

    def accept(name: str, status: int, state: str, section: str, detail: str) -> None:
        REPORT["acceptances"][name] = {"status": status, "state": state,
                                       "section": section, "detail": detail}

    def delivered(vid: str, **kw) -> tuple[dict, dict]:
        vtc = h.fresh(vid, **kw)
        h.client.propose(vtc)
        dlv = agents.make_delivery(vtc, h.seller, b"w", b"r")
        h.client.deliver(dlv)
        return vtc, dlv

    # Section 7.2, before funds lock: 18.00 against q_min 0.90 needs 20.00.
    record("bond_below_constraint", *h.client.propose(h.fresh("r_bond", q_min=0.90)))

    # Section 13.2: schema conformance at propose (a zero window).
    bad = agents.draft_contract("r_schema", BUYER, SELLER, FACILITATOR, VERIFIER,
                                deadline=h.clock.at(86400))
    bad["challenge"]["window_seconds"] = 0
    record("schema_invalid_zero_window", *h.client.propose(agents.cosign(bad, h.buyer, h.seller)))

    # Section 13.2 / Table 9: buyer and seller the same party after normalization.
    same = agents.draft_contract("r_same", BUYER, BUYER + "/", FACILITATOR, VERIFIER,
                                 deadline=h.clock.at(86400))
    record("buyer_equals_seller", *h.client.propose(agents.cosign(same, h.buyer, h.buyer)))

    # Section 16.7: a contract naming another Facilitator is a replayable instrument.
    other = agents.draft_contract("r_venue", BUYER, SELLER, "did:web:elsewhere.example",
                                  VERIFIER, deadline=h.clock.at(86400))
    record("contract_names_other_facilitator", *h.client.propose(agents.cosign(other, h.buyer, h.seller)))

    # Section 7.3 / 8: a release mode this Facilitator does not advertise.
    record("release_mode_not_advertised",
           *h.client.propose(h.fresh("r_mode", release="on-window")))

    # Section 9.1 at propose: the Seller named as its own verifier.
    record("named_verifier_is_seller",
           *h.client.propose(h.fresh("r_selfnamed", verifier=SELLER)))

    # Section 10.1: subcontracts are not implemented and are refused, not ignored.
    child = agents.draft_contract("r_child", BUYER, SELLER, FACILITATOR, VERIFIER,
                                  deadline=h.clock.at(86400))
    child["liability"]["parent"] = {"vtc_id": "vtc_nowhere", "vtc_hash": pc.h(b"x")}
    record("subcontract_refused", *h.client.propose(agents.cosign(child, h.buyer, h.seller)))

    # Section 5: a third party's signature on a co-signed contract.
    third = agents.make_party("did:web:bystander.example", h.resolver, h.client)
    extra = h.fresh("r_thirdsig")
    extra["signatures"].append(pc.sign({k: v for k, v in extra.items() if k != "signatures"},
                                       third.key, agents.MEDIA_CONTRACT))
    record("third_party_signature", *h.client.propose(extra))

    # Section 13.1 / Table 9: alg none, with a correct typ so only the allowlist fires.
    tampered = h.fresh("r_alg")
    prot = pc.b64u(pc.jcs({"alg": "none", "kid": h.buyer.key.kid,
                           "typ": agents.MEDIA_CONTRACT}))
    tampered["signatures"][0]["protected"] = prot
    record("algorithm_none", *h.client.propose(tampered))

    # Section 12.2: the same id with different bytes is 409.
    vtc3 = h.fresh("r_idem")
    h.client.propose(vtc3)
    altered = json.loads(json.dumps(vtc3))
    altered["liability"]["seller_bond"] = "19.00"
    altered = agents.cosign({k: v for k, v in altered.items() if k != "signatures"},
                            h.buyer, h.seller)
    record("altered_contract_same_id", *h.client.propose(altered))

    # Section 12: a Delivery from a look-alike of the Seller's identifier.
    evil = agents.make_party(SELLER + ".evil", h.resolver, h.client)
    vtc7 = h.fresh("r_prefix")
    h.client.propose(vtc7)
    record("delivery_by_prefix_lookalike",
           *h.client.deliver(agents.make_delivery(vtc7, evil, b"w", b"r")))

    # Section 6: a Delivery must carry evidence conformant to the profile.
    vtc5 = h.fresh("r_noevidence")
    h.client.propose(vtc5)
    d5 = agents.make_delivery(vtc5, h.seller, b"w", b"r")
    del d5["evidence"]
    record("delivery_without_evidence",
           *h.client.deliver(h.seller.sign_into(d5, agents.MEDIA_DELIVERY)))

    # Section 6: input_hash is REQUIRED where the tier re-executes.
    vtc8 = h.fresh("r_noinput")
    h.client.propose(vtc8)
    d8 = agents.make_delivery(vtc8, h.seller, b"w", b"r")
    del d8["input_hash"]
    record("delivery_without_input_hash",
           *h.client.deliver(h.seller.sign_into(d8, agents.MEDIA_DELIVERY)))

    # Section 12.4: no Verdict without a recorded Delivery.
    vtc2 = h.fresh("r_nodelivery")
    h.client.propose(vtc2)
    _, some_dlv = delivered("r_donor")
    record("verdict_without_delivery",
           *h.client.verdict(agents.make_verdict(vtc2, some_dlv, h.verifier, "PASS")))

    # Section 9.1, DERIVED: no verifier named, and the Seller signs the Verdict.
    vtc_s, d_s = delivered("r_selfverify", verifier=None)
    record("verdict_signed_by_seller",
           *h.client.verdict(agents.make_verdict(vtc_s, d_s, h.seller, "PASS")))

    # Section 3: no verifier named, and the Facilitator signs the Verdict.
    fac_party = agents.Party(FACILITATOR, h.fac.key, h.client)
    record("verdict_signed_by_facilitator",
           *h.client.verdict(agents.make_verdict(vtc_s, d_s, fac_party, "PASS")))

    # Draft line 1852: the contract names a verifier, so only that party judges.
    stranger = agents.make_party("did:web:watchdog.example", h.resolver, h.client)
    vtc4, d4 = delivered("r_stranger")
    record("verdict_by_unnamed_party",
           *h.client.verdict(agents.make_verdict(vtc4, d4, stranger, "PASS")))

    # Section 12.4: a Verdict over a different instrument.
    wrong_inst = agents.make_verdict(vtc4, d4, h.verifier, "PASS")
    wrong_inst["instrument_hash"] = pc.h(b"some other instrument")
    wrong_inst["signature"] = pc.sign({k: v for k, v in wrong_inst.items() if k != "signature"},
                                      h.verifier.key, agents.MEDIA_VERDICT)
    record("verdict_over_other_instrument", *h.client.verdict(wrong_inst))

    # RFC 8725 3.11 and vector V-05: typ carries the full media type.
    wrong_typ = agents.make_verdict(vtc4, d4, h.verifier, "PASS")
    wrong_typ["signature"] = pc.sign({k: v for k, v in wrong_typ.items() if k != "signature"},
                                     h.verifier.key, agents.MEDIA_DELIVERY)
    record("verdict_signed_with_delivery_typ", *h.client.verdict(wrong_typ))

    # Section 7.5: a Challenge before any window is open.
    record("challenge_before_window",
           *h.client.challenge(agents.make_challenge(vtc4, d4, h.buyer, ["rows"])))

    # Now a PASS, so the window opens; then the two window-related refusals
    # and the acceptance that matters most.
    h.client.verdict(agents.make_verdict(vtc4, d4, h.verifier, "PASS"))
    bad_proof = agents.make_challenge(vtc4, d4, h.buyer, ["rows"])
    bad_proof["proof"]["instrument_hash"] = pc.h(b"not the committed instrument")
    bad_proof["signature"] = pc.sign({k: v for k, v in bad_proof.items() if k != "signature"},
                                     h.buyer.key, agents.MEDIA_CHALLENGE)
    record("challenge_proof_nonconformant", *h.client.challenge(bad_proof))

    st, body = h.client.challenge(agents.make_challenge(vtc4, d4, stranger, ["rows"]))
    c4 = h.fac.contracts["r_stranger"]
    accept("challenge_alone_does_not_settle", st, body.get("state", "?"), "7.5",
           f"bond still locked: {pc.money(c4.pools.bond)} of "
           f"{pc.money(c4.pools.bond_initial)}; attestation issued: {c4.attestation is not None}")

    # Section 7.5: the Challenger's own assertion is not a Verdict.
    record("verdict_by_the_challenger",
           *h.client.verdict(agents.make_verdict(vtc4, d4, stranger, "FAIL")))

    # A second PASS on a fresh contract, then a Challenge after the window.
    vtc9, d9 = delivered("r_late")
    h.client.verdict(agents.make_verdict(vtc9, d9, h.verifier, "PASS"))
    h.clock.advance(WINDOW + 1)
    record("challenge_after_window",
           *h.client.challenge(agents.make_challenge(vtc9, d9, h.buyer, ["rows"])))

    # Section 12: a Verdict on a contract that is already FINAL.
    record("verdict_after_final",
           *h.client.verdict(agents.make_verdict(vtc9, d9, h.verifier, "FAIL")))

    # Section 12.2: the same body twice is the same resource, 200 not 409.
    st, body = h.client.propose(vtc3)
    accept("resubmit_identical_contract", st, body.get("state", "?"), "12.2",
           "the current resource, not a snapshot")


# --------------------------------------------------------------------------
# Capability document, Section 8
# --------------------------------------------------------------------------

def run_capability(h: Harness) -> None:
    st, doc = h.client.capability()
    ok, why = pc.verify_object(doc, h.resolver, fac_mod.MEDIA_FACILITATOR, [FACILITATOR])
    REPORT["capability_document"] = {
        "status": st,
        "schema": _schema_check(doc, "facilitator.schema.json"),
        "signature_verifies": ok,
        "release_modes": doc.get("release_modes"),
        "settlement_bindings": doc.get("settlement_bindings"),
    }


# --------------------------------------------------------------------------
# Microbenchmarks
# --------------------------------------------------------------------------

def bench(fn, n: int = 2000) -> dict:
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

    # Labels say what is timed. "sign" and "verify" both include canonicalizing
    # the contract to rebuild the detached payload, because that is what a
    # Facilitator does per signature; the raw Ed25519 primitive is a fraction
    # of each and is reported on its own so the reader can subtract.
    REPORT["micro"]["canonicalize_contract"] = bench(lambda: pc.jcs(vtc))
    REPORT["micro"]["canonicalize_and_digest_contract"] = bench(
        lambda: pc.digest_over(pc.hashable(vtc)))
    REPORT["micro"]["sign_contract_incl_canonicalization"] = bench(
        lambda: pc.sign(vtc, key, agents.MEDIA_CONTRACT), n=500)
    entry = pc.sign(vtc, key, agents.MEDIA_CONTRACT)
    REPORT["micro"]["verify_contract_signature_end_to_end"] = bench(
        lambda: pc.verify_entry(vtc, entry, h.resolver), n=500)
    msg = b"x" * 1500
    sig = key.sign_bytes(msg)
    REPORT["micro"]["ed25519_sign_primitive_1500B"] = bench(lambda: key.sign_bytes(msg), n=500)
    REPORT["micro"]["ed25519_verify_primitive_1500B"] = bench(
        lambda: key.verify_bytes(sig, msg), n=500)
    REPORT["micro"]["normalize_identifier"] = bench(lambda: pc.norm(SELLER))
    REPORT["micro"]["assurance_constraint_exact_decimal"] = bench(
        lambda: pc.assurance_holds("180.00", "18.00", "0.9091", "0"))

    # RFC 9162 root over N leaves, pactcore.mth. The Facilitator does not build
    # trees (subcontracts are not implemented); this is the primitive a
    # Section 10 implementation would call per parent attestation.
    for n in (2, 8, 64):
        leaves = [pc.jcs({"child": i}) for i in range(n)]
        REPORT["micro"][f"rfc9162_root_{n}_leaves"] = bench(
            lambda leaves=leaves: pc.mth(leaves), n=200 if n > 8 else 1000)

    REPORT["micro"]["canonical_bytes"] = {
        "contract": len(pc.jcs(pc.hashable(vtc))),
        "delivery": len(pc.jcs(pc.hashable(dlv))),
    }
    # There is deliberately NO T0-reexec figure. An earlier version timed
    # examples/acceptance-harness/test_acceptance.py by running it as a plain
    # script, which executes no tests at all; the number was pytest's import
    # time. An honest figure needs the harness invoked through pytest, which
    # currently fails because pytest_addoption sits in a test module rather
    # than a conftest.py, and moving it changes criteria_hash: a -02 item.


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
        "note": "single host, loopback HTTP, in-memory store, no payment rail; the "
                "Facilitator's clock is advanced by the harness",
    }

    h = Harness(args.port)
    try:
        _schema_check({}, "vtc.schema.json")   # load schemas outside any timed region
        run_capability(h)
        scenario(h, "FINAL", lambda: run_final(h))
        scenario(h, "SETTLED", lambda: run_settled(h))
        scenario(h, "ABANDONED", lambda: run_abandoned(h))
        scenario(h, "OVERTURNED_PASS", lambda: run_overturned(h))
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

    cd = REPORT["capability_document"]
    print(f"CAPABILITY DOCUMENT  status {cd['status']}, schema {cd['schema']}, "
          f"signature verifies: {cd['signature_verifies']}\n")

    print("TERMINAL STATES")
    for name, s in REPORT["scenarios"].items():
        print(f"  {name:<20} {s['messages']} messages, {s['request_bytes']}B out / "
              f"{s['response_bytes']}B back, {s['wall_ms']}ms, attestation verifies: "
              f"{s['attestation_verifies']}, money balanced: {s['money']['balanced']}")
        print(f"                       amounts {s['amounts']}")
        bad = [k for k, v in s.get("schema", {}).items() if v != "valid"]
        if bad:
            print(f"                       SCHEMA FAILURES: {bad}")
    print()

    print(f"REFUSALS ({len(REPORT['refusals'])})")
    for name, r in REPORT["refusals"].items():
        print(f"  {name:<34} {r['status']} {r['type']:<34} {r['section']}")
    print(f"\nACCEPTANCES ({len(REPORT['acceptances'])})")
    for name, r in REPORT["acceptances"].items():
        print(f"  {name:<34} {r['status']} state {r['state']:<12} {r['section']}  {r['detail']}")
    print()

    print("MICROBENCHMARKS, median microseconds per call")
    for name, m in REPORT["micro"].items():
        if isinstance(m, dict) and "median_us" in m:
            print(f"  {name:<40} {m['median_us']:>10.2f} us")
    cb = REPORT["micro"].get("canonical_bytes", {})
    if cb:
        print(f"  canonical bytes                          contract {cb['contract']}, "
              f"delivery {cb['delivery']}")
    print("\n  no T0-reexec figure is reported; see the comment in run_micro")


if __name__ == "__main__":
    main()
