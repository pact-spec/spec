"""Buyer, Seller, Verifier and Challenger: the client half of the reference pair.

Each party holds one key and speaks HTTP to a Facilitator. Nothing here trusts
the Facilitator's word for anything it can check itself: a party verifies the
attestation it is handed, and recomputes the contract digest rather than
accepting the one it is told.

The contracts these agents mint are fresh, with fresh keys and real signatures.
They are deliberately NOT the committed examples under examples/, whose digests
the published Internet-Draft prints in Section 14 and cannot be corrected.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

import pactcore as pc

MEDIA_CONTRACT = "application/pact-contract+json"
MEDIA_DELIVERY = "application/pact-delivery+json"
MEDIA_VERDICT = "application/pact-verdict+json"
MEDIA_CHALLENGE = "application/pact-challenge+json"


@dataclass
class Wire:
    """A record of one request and response, for the measurement harness."""
    method: str
    path: str
    status: int
    request_bytes: int
    response_bytes: int
    seconds: float


class Client:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")
        self.wire: list[Wire] = []

    def _call(self, method: str, path: str, body: dict | None,
              content_type: str | None) -> tuple[int, dict]:
        raw = json.dumps(body, separators=(",", ":")).encode() if body else None
        req = urllib.request.Request(self.base + path, data=raw, method=method)
        if content_type:
            req.add_header("Content-Type", content_type)
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(req) as resp:
                out = resp.read()
                status = resp.status
        except urllib.error.HTTPError as exc:
            out = exc.read()
            status = exc.code
        elapsed = time.perf_counter() - started
        self.wire.append(Wire(method, path, status, len(raw or b""), len(out), elapsed))
        return status, json.loads(out or b"{}")

    def post(self, path: str, body: dict, ct: str) -> tuple[int, dict]:
        return self._call("POST", path, body, ct)

    def get(self, path: str) -> tuple[int, dict]:
        return self._call("GET", path, None, None)

    # -- named operations, Table 1 ----------------------------------------
    def propose(self, vtc): return self.post("/pact/v1/contracts", vtc, MEDIA_CONTRACT)
    def deliver(self, d): return self.post("/pact/v1/deliveries", d, MEDIA_DELIVERY)
    def verdict(self, v): return self.post("/pact/v1/verdicts", v, MEDIA_VERDICT)
    def challenge(self, c): return self.post("/pact/v1/challenges", c, MEDIA_CHALLENGE)
    def contract(self, vid): return self.get(f"/pact/v1/contracts/{vid}")
    def attestation(self, vid): return self.get(f"/pact/v1/attestations/{vid}")
    def capability(self): return self.get("/.well-known/pact-facilitator")


@dataclass
class Party:
    did: str
    key: pc.Key
    client: Client

    def sign_into(self, obj: dict, typ: str, array: bool = False) -> dict:
        return pc.attach(obj, pc.sign(obj, self.key, typ), array)


def make_party(did: str, resolver: pc.KeyResolver, client: Client,
               alg: str = "EdDSA") -> Party:
    key = resolver.register(pc.Key.generate(f"{did}#key-1", alg))
    return Party(did=did, key=key, client=client)


# --------------------------------------------------------------------------
# Contract construction
# --------------------------------------------------------------------------

def draft_contract(vid: str, buyer: str, seller: str, facilitator: str,
                   verifier: str | None, *, price: str = "180.00", bond: str = "18.00",
                   fund: str = "0.50", q_min: float = 0.9091,
                   deadline: str = "2027-01-01T00:00:00Z",
                   release: str = "on-verification",
                   restitution_basis: str = "released",
                   spec_hash: str | None = None,
                   criteria_hash: str | None = None) -> dict:
    """An unsigned contract in the shape schemas/vtc.schema.json requires."""
    parties = {"buyer": buyer, "seller": seller, "facilitator": facilitator}
    if verifier is not None:
        parties["verifier"] = verifier   # absent: Section 9.1 is derived per signer
    return {
        "pact": "0.1",
        "type": "VerifiableTaskContract",
        "id": vid,
        "parties": parties,
        "task": {
            "spec_hash": spec_hash or pc.h(b"taskspec placeholder"),
            "spec_uri": "https://buyer.example/specs/taskspec.json",
            "deadline": deadline,
        },
        "price": {
            "amount": price, "currency": "USDC",
            "settlement": "pact-escrow", "network": "eip155:8453",
        },
        "verification": {
            "tier": "T0-reexec", "profile": "acceptance",
            "criteria_hash": criteria_hash or pc.h(b"criteria placeholder"),
        },
        "assurance": {"mode": "certain", "q_min": q_min},
        "release": release,
        "liability": {
            "seller_bond": bond, "verification_fund": fund,
            "cap": price, "restitution_basis": restitution_basis,
        },
        "challenge": {"window_seconds": 3600, "max_dispute_seconds": 86400},
    }


def cosign(vtc: dict, buyer: Party, seller: Party) -> dict:
    """Both parties sign the same bytes: the contract without its signatures.

    That is what makes the digest meaningful. vtc_hash is then taken over the
    contract WITH the signature set, so the commitment proves who agreed.
    """
    entries = [pc.sign(vtc, buyer.key, MEDIA_CONTRACT),
               pc.sign(vtc, seller.key, MEDIA_CONTRACT)]
    vtc["signatures"] = entries
    return vtc


def make_delivery(vtc: dict, seller: Party, work: bytes,
                  results: bytes) -> dict:
    d = {
        "pact": "0.1",
        "type": "Delivery",
        "vtc_id": vtc["id"],
        "vtc_hash": pc.digest_over(pc.hashable(vtc)),
        "work_hash": pc.h(work),
        "work_uri": "https://cdn.seller.example/o/" + pc.h(work)[7:15],
        "input_hash": pc.h(b"inputs"),
        "delivered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "evidence": {
            "profile": "acceptance",
            "instrument_hash": vtc["verification"]["criteria_hash"],
            "results_hash": pc.h(results),
            "results_uri": "https://cdn.seller.example/r/" + pc.h(results)[7:15],
        },
    }
    return seller.sign_into(d, MEDIA_DELIVERY)


def make_verdict(vtc: dict, delivery: dict, verifier: Party,
                 outcome: str) -> dict:
    v = {
        "pact": "0.1",
        "type": "Verdict",
        "vtc_id": vtc["id"],
        "delivery_hash": pc.digest_over(pc.hashable(delivery)),
        "outcome": outcome,
        "profile": "acceptance",
        "instrument_hash": vtc["verification"]["criteria_hash"],
        "results_hash": delivery["evidence"]["results_hash"],
        "evaluated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    return verifier.sign_into(v, MEDIA_VERDICT)


def make_challenge(vtc: dict, delivery: dict, challenger: Party,
                   failing: list[str]) -> dict:
    c = {
        "pact": "0.1",
        "type": "Challenge",
        "vtc_id": vtc["id"],
        "delivery_hash": pc.digest_over(pc.hashable(delivery)),
        "proof": {
            "profile": "acceptance",
            "instrument_hash": vtc["verification"]["criteria_hash"],
            "results_hash": pc.h(b"independent re-execution"),
            "results_uri": "https://watch.example/o/a91e",
            "failing_checks": failing,
        },
    }
    return challenger.sign_into(c, MEDIA_CHALLENGE)


def check_attestation(att: dict, resolver: pc.KeyResolver,
                      facilitator: str) -> tuple[bool, str]:
    """A party checks the record it is handed rather than taking it on trust.

    Section 11 makes the Facilitator the required signer precisely so that a
    slashed Seller cannot decline to co-sign its own conviction. The other side
    of that is that the Facilitator's signature is what makes the record
    evidence, so it has to actually verify.
    """
    return pc.verify_object(att, resolver,
                            "application/pact-attestation+json", [facilitator])
