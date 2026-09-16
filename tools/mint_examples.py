"""Mint the committed examples under examples/, reproducibly.

The -01 examples carried placeholder signatures because the posted draft
printed their digests and nothing could be changed. -02 recomputes every
digest, so the examples are signed for real, with Ed25519 keys derived from
public seeds, and Ed25519 signatures are deterministic: anyone running this
script gets byte-identical files and therefore the digests Section 15 of the
draft prints. The seeds are not secrets and the keys must never be used for
anything but these examples.

    python3 tools/mint_examples.py          # rewrite examples/ and print digests
    python3 tools/mint_examples.py --check  # recompute and compare, write nothing
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import agents
import pactcore as pc
import profile as terms

ROOT = pathlib.Path(__file__).resolve().parent.parent
EX = ROOT / "examples"
CONTENT = EX / "task-content"

BUYER = "did:web:buyer.example:agents:procure-1"
SELLER = "did:web:dataforge.example:agents:etl-3"
FACILITATOR = "did:web:settle.example"
VERIFIER = "did:web:audit.example"
CHALLENGER = "did:web:watch.example"

# The Facilitator's clock for the worked example, Section 15 and Appendix A.
T_ACCEPTED = "2026-11-01T10:00:00Z"
T_DELIVERED = "2026-11-10T08:30:12Z"
T_VERDICT = "2026-11-10T09:14:30Z"
T_CLOSES = "2026-11-10T10:14:30Z"
T_CHALLENGE = "2026-11-10T09:40:00Z"
T_VERDICT2 = "2026-11-10T09:58:05Z"


def key_for(did: str) -> pc.Key:
    seed = hashlib.sha256(b"pact-spec example key, public seed: " + did.encode()).digest()
    return pc.Key.from_seed(f"{did}#k1", seed)


def dump(obj: dict) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def build() -> dict[str, dict]:
    keys = {name: key_for(did) for name, did in
            (("buyer", BUYER), ("seller", SELLER), ("facilitator", FACILITATOR),
             ("verifier", VERIFIER), ("challenger", CHALLENGER))}
    profile = terms.BondedRestitution()

    harness_hash = pc.manifest_digest(EX / "acceptance-harness")
    content_hash = {p.name: pc.h(p.read_bytes()) for p in CONTENT.iterdir() if p.suffix != ".md"}

    taskspec = {
        "description": "Deduplicate a 2,100,000-row customer CSV; normalize country "
                       "fields to ISO-3166 alpha-2; merge conflicting records by "
                       "most-recent timestamp.",
        "inputs": {
            "schema_uri": "https://buyer.example/specs/customers.schema.json",
            "schema_hash": content_hash["customers.schema.json"],
            "sample_uri": "https://buyer.example/specs/sample-10k.csv",
            "sample_hash": content_hash["sample-10k.csv"],
        },
        "deliverable": {
            "format": "csv",
            "schema_uri": "https://buyer.example/specs/output.schema.json",
            "schema_hash": content_hash["output.schema.json"],
        },
        "acceptance": {
            "harness_uri": "https://buyer.example/specs/acceptance-tests.tar",
            "harness_hash": harness_hash,
            "thresholds": {"dup_rate_max": 0.001, "schema_valid_rate": 1.0},
        },
        "constraints": {"tools_prohibited": ["external-APIs"], "confidential": False},
    }
    spec_hash = pc.digest_over(taskspec)

    vtc = {
        "pact": "0.2",
        "type": "VerifiableTaskContract",
        "id": "vtc_9f2c11",
        "parties": {"buyer": BUYER, "seller": SELLER, "facilitator": FACILITATOR,
                    "verifier": VERIFIER},
        "task": {"spec_hash": spec_hash,
                 "spec_uri": "https://buyer.example/specs/taskspec.json",
                 "deadline": "2026-11-14T00:00:00Z"},
        "price": {"amount": "180.00", "currency": "USDC",
                  "settlement": "https://settle.example/bindings/ledger-1",
                  "network": "eip155:8453"},
        "verification": {"tier": "T0-reexec", "profile": "acceptance",
                         "criteria_hash": harness_hash, "max_verdict_seconds": 86400},
        "flow": "verdict-first",
        "terms": {
            "profile": profile.id,
            "profile_hash": profile.profile_hash,
            "parameters": {
                "seller_bond": "18.00", "verification_fund": "0.50", "cap": "180.00",
                "restitution_basis": "released", "remainder_to": "sink",
                "principal_on": "verdict",
                "assurance": {"mode": "certain", "q_min": 1.0},
            },
        },
        "challenge": {"window_seconds": 3600, "max_dispute_seconds": 86400},
    }
    vtc["signatures"] = agents.sort_signatures([
        pc.sign(vtc, keys["buyer"], agents.MEDIA_CONTRACT),
        pc.sign(vtc, keys["seller"], agents.MEDIA_CONTRACT)])
    vtc_hash = pc.digest_over(vtc)

    work = (CONTENT / "sample-10k.csv").read_bytes()  # stands in for the deliverable
    results = b'{"schema_valid_rate": 1.0, "dup_rate": 0.0}\n'
    delivery = {
        "pact": "0.2", "type": "Delivery", "vtc_id": vtc["id"], "vtc_hash": vtc_hash,
        "work_hash": pc.h(work),
        "work_uri": "https://cdn.dataforge.example/o/" + pc.h(work)[7:11],
        "input_hash": content_hash["sample-10k.csv"],
        "evidence": {"profile": "acceptance", "instrument_hash": harness_hash,
                     "results_hash": pc.h(results),
                     "results_uri": "https://cdn.dataforge.example/o/" + pc.h(results)[7:11]},
    }
    delivery["signature"] = pc.sign(delivery, keys["seller"], agents.MEDIA_DELIVERY)
    delivery_hash = pc.digest_over(delivery)

    verdict = {
        "pact": "0.2", "type": "Verdict", "vtc_id": vtc["id"],
        "delivery_hash": delivery_hash, "outcome": "PASS", "profile": "acceptance",
        "instrument_hash": harness_hash, "results_hash": pc.h(results),
        "evaluated_at": "2026-11-10T09:14:22Z",
    }
    verdict["signature"] = pc.sign(verdict, keys["verifier"], agents.MEDIA_VERDICT)
    verdict_hash = pc.digest_over(verdict)

    challenge = {
        "pact": "0.2", "type": "Challenge", "vtc_id": vtc["id"],
        "delivery_hash": delivery_hash,
        "proof": {"profile": "acceptance", "instrument_hash": harness_hash,
                  "results_hash": pc.h(b"independent re-execution: 41 duplicate rows"),
                  "results_uri": "https://watch.example/o/a91e",
                  "failing_checks": ["schema_valid_rate", "row_count_min"]},
        "costs": {"amount": "1.20", "currency": "USDC"},
    }
    challenge["signature"] = pc.sign(challenge, keys["challenger"], agents.MEDIA_CHALLENGE)
    challenge_hash = pc.digest_over(challenge)

    verdict2 = {
        "pact": "0.2", "type": "Verdict", "vtc_id": vtc["id"],
        "delivery_hash": delivery_hash, "challenge_hash": challenge_hash,
        "outcome": "FAIL", "profile": "acceptance", "instrument_hash": harness_hash,
        "results_hash": pc.h(b"independent re-execution: 41 duplicate rows"),
        "evaluated_at": "2026-11-10T09:57:40Z",
    }
    verdict2["signature"] = pc.sign(verdict2, keys["verifier"], agents.MEDIA_VERDICT)
    verdict2_hash = pc.digest_over(verdict2)

    trace = [
        {"event": "accepted", "at": T_ACCEPTED, "object": vtc_hash},
        {"event": "funded", "at": T_ACCEPTED},
        {"event": "delivered", "at": T_DELIVERED, "object": delivery_hash},
        {"event": "verdict", "at": T_VERDICT, "object": verdict_hash,
         "signer": keys["verifier"].kid, "outcome": "PASS"},
        {"event": "window-opened", "at": T_VERDICT, "closes_at": T_CLOSES},
        {"event": "challenge", "at": T_CHALLENGE, "object": challenge_hash,
         "signer": keys["challenger"].kid, "costs": challenge["costs"]},
        {"event": "verdict", "at": T_VERDICT2, "object": verdict2_hash,
         "signer": keys["verifier"].kid, "outcome": "FAIL",
         "answers": challenge_hash, "supersedes": verdict_hash},
        {"event": "children-final", "at": T_VERDICT2},
        {"event": "terminal", "at": T_VERDICT2, "state": "SETTLED", "challenge_upheld": True},
    ]

    status = {
        "pact": "0.2", "type": "ContractStatus", "vtc_id": vtc["id"], "vtc_hash": vtc_hash,
        "state": "WINDOW_OPEN", "trace": trace[:5], "issued_at": T_VERDICT,
    }
    status["signature"] = pc.sign(status, keys["facilitator"], agents.MEDIA_STATUS)

    transfers = profile.schedule(vtc, trace)
    ok, why = profile.check(vtc, transfers, terminal=True)
    assert ok, why
    outcome = {
        "pact": "0.2", "type": "OutcomeRecord", "vtc_id": vtc["id"], "vtc_hash": vtc_hash,
        "parties": vtc["parties"],
        "outcome": {"state": "SETTLED", "challenge_upheld": True},
        "work_hash": delivery["work_hash"],
        "trace": trace,
        "terms_result": {"profile": profile.id, "profile_hash": profile.profile_hash,
                         "currency": "USDC", "transfers": transfers},
    }
    outcome["signatures"] = [pc.sign(outcome, keys["facilitator"], agents.MEDIA_OUTCOME)]

    capability = {
        "pact": "0.2", "type": "FacilitatorCapabilities", "facilitator": FACILITATOR,
        "settlement_bindings": [{"id": "https://settle.example/bindings/ledger-1",
                                 "networks": ["eip155:8453"], "assets": ["USDC"]}],
        "flows": ["verdict-first", "delivery-first"],
        "verification_profiles": ["acceptance", "bisection"],
        "terms_profiles": [{"id": profile.id, "profile_hash": profile.profile_hash}],
        "max_contract_value": {"amount": "50000.00", "currency": "USDC"},
        "endpoints": {
            "contract": "https://settle.example/pact/v2/contracts",
            "delivery": "https://settle.example/pact/v2/deliveries",
            "verdict": "https://settle.example/pact/v2/verdicts",
            "challenge": "https://settle.example/pact/v2/challenges",
            "outcome": "https://settle.example/pact/v2/outcomes",
        },
    }
    capability["signature"] = pc.sign(capability, keys["facilitator"], agents.MEDIA_FACILITATOR)

    public_keys = {name: {"kid": k.kid, "kty": "OKP", "crv": "Ed25519",
                          "x": pc.b64u(pc.public_bytes(k))} for name, k in keys.items()}

    files = {
        "taskspec.json": taskspec, "vtc.json": vtc, "delivery.json": delivery,
        "verdict.json": verdict, "challenge.json": challenge, "verdict-on-challenge.json": verdict2,
        "status.json": status, "outcome.json": outcome,
        "well-known/pact-facilitator.json": capability,
        "keys/public-keys.json": public_keys,
    }
    digests = {"spec_hash": spec_hash, "criteria_hash": harness_hash,
               "profile_hash": profile.profile_hash, "vtc_hash": vtc_hash,
               "delivery_hash": delivery_hash, "verdict_hash": verdict_hash,
               "challenge_hash": challenge_hash, "verdict2_hash": verdict2_hash}
    return {"files": files, "digests": digests}


KEYS_README = """# Example keys

`public-keys.json` holds the public keys that verify the signatures on the
committed examples, as JWKs (RFC 7517). The private keys are derived in
`tools/mint_examples.py` from public seeds, so they are not secrets and the
signatures are reproducible byte for byte; nothing signed with them means
anything outside this repository.
"""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="compare with the files on disk")
    args = ap.parse_args()
    built = build()
    changed = []
    for rel, obj in built["files"].items():
        path = EX / rel
        text = dump(obj)
        if args.check:
            if not path.exists() or path.read_text() != text:
                changed.append(rel)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
    if not args.check:
        (EX / "keys" / "README.md").write_text(KEYS_README)
    for name, value in built["digests"].items():
        print(f"{name:<16}{value}")
    if args.check:
        print("differs from disk: " + (", ".join(changed) if changed else "nothing"))
        sys.exit(1 if changed else 0)


if __name__ == "__main__":
    main()
