"""Buyer, Seller, Verifier and Challenger: the client half of the reference pair.

Each party holds one key and speaks HTTP to a Facilitator. Nothing here trusts
the Facilitator's word for anything it can check itself: a party verifies the
Status and the Outcome Record it is handed, and recomputes every digest rather
than accepting the one it is told.

The contracts these agents mint are fresh, with fresh keys and real signatures;
the committed examples under examples/ are minted separately, reproducibly, by
mint_examples.py.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

import pactcore as pc
import profile as terms

MEDIA_CONTRACT = "application/vnd.pact.contract+json"
MEDIA_DELIVERY = "application/vnd.pact.delivery+json"
MEDIA_VERDICT = "application/vnd.pact.verdict+json"
MEDIA_CHALLENGE = "application/vnd.pact.challenge+json"
MEDIA_STATUS = "application/vnd.pact.status+json"
MEDIA_OUTCOME = "application/vnd.pact.outcome+json"
MEDIA_FACILITATOR = "application/vnd.pact.facilitator+json"

BASE_PATH = "/pact/v2"


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

    # -- the operations of Section 13 -------------------------------------
    def propose(self, vtc): return self.post(f"{BASE_PATH}/contracts", vtc, MEDIA_CONTRACT)
    def status(self, vid): return self.get(f"{BASE_PATH}/contracts/{vid}")
    def register_child(self, parent_id, child_vtc):
        return self.post(f"{BASE_PATH}/contracts/{parent_id}/children", child_vtc, MEDIA_CONTRACT)
    def supply_child_outcome(self, parent_id, child_hash, record):
        return self.post(f"{BASE_PATH}/contracts/{parent_id}/children/{child_hash}", record, MEDIA_OUTCOME)
    def deliver(self, d): return self.post(f"{BASE_PATH}/deliveries", d, MEDIA_DELIVERY)
    def verdict(self, v): return self.post(f"{BASE_PATH}/verdicts", v, MEDIA_VERDICT)
    def challenge(self, c): return self.post(f"{BASE_PATH}/challenges", c, MEDIA_CHALLENGE)
    def outcome(self, vid): return self.get(f"{BASE_PATH}/outcomes/{vid}")
    def capability(self): return self.get("/.well-known/pact-facilitator")


@dataclass
class Party:
    did: str
    key: pc.Key
    client: Client

    def sign_into(self, obj: dict, typ: str, array: bool = False) -> dict:
        return pc.attach(obj, pc.sign(obj, self.key, typ), array)


def make_party(did: str, resolver: pc.KeyResolver, client: Client,
               alg: str = "Ed25519") -> Party:
    key = resolver.register(pc.Key.generate(f"{did}#key-1", alg))
    return Party(did=did, key=key, client=client)


# --------------------------------------------------------------------------
# Contract construction
# --------------------------------------------------------------------------

_PROFILE = None


def default_profile() -> terms.BondedRestitution:
    global _PROFILE
    if _PROFILE is None:
        _PROFILE = terms.BondedRestitution()
    return _PROFILE


def draft_contract(vid: str, buyer: str, seller: str, facilitator: str,
                   verifier: str | None, *, price: str = "180.00", bond: str = "18.00",
                   fund: str = "0.50", q_min: float = 1.0,
                   deadline: str = "2027-01-01T00:00:00Z",
                   flow: str = "verdict-first", principal_on: str = "verdict",
                   restitution_basis: str = "released",
                   assurance_mode: str = "certain",
                   window_seconds: int = 3600, max_dispute_seconds: int = 86400,
                   max_verdict_seconds: int = 86400,
                   spec_hash: str | None = None, criteria_hash: str | None = None,
                   profile_id: str | None = None, profile_hash: str | None = None,
                   parent: dict | None = None,
                   settlement: str = "https://settle.example/bindings/ledger-1") -> dict:
    """An unsigned 0.2 contract in the shape schemas/vtc.schema.json requires."""
    parties = {"buyer": buyer, "seller": seller, "facilitator": facilitator}
    if verifier is not None:
        parties["verifier"] = verifier   # absent: Section 9.1 is derived per signer
    prof = default_profile()
    vtc = {
        "pact": "0.2",
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
            "settlement": settlement, "network": "eip155:8453",
        },
        "verification": {
            "tier": "T0-reexec", "profile": "acceptance",
            "criteria_hash": criteria_hash or pc.h(b"criteria placeholder"),
            "max_verdict_seconds": max_verdict_seconds,
        },
        "flow": flow,
        "terms": {
            "profile": profile_id or prof.id,
            "profile_hash": profile_hash or prof.profile_hash,
            "parameters": {
                "seller_bond": bond, "verification_fund": fund, "cap": price,
                "restitution_basis": restitution_basis, "remainder_to": "sink",
                "principal_on": principal_on,
                "assurance": {"mode": assurance_mode, "q_min": q_min},
            },
        },
        "challenge": {"window_seconds": window_seconds,
                      "max_dispute_seconds": max_dispute_seconds},
    }
    if parent is not None:
        vtc["parent"] = parent
    return vtc


def cosign(vtc: dict, *parties: Party) -> dict:
    """Every party signs the same bytes, the contract without its signatures,
    and the entries are sorted by normalized kid as Section 14.1 requires, so
    the digest over the signed contract does not depend on who signed last."""
    entries = [pc.sign(vtc, p.key, MEDIA_CONTRACT) for p in parties]
    vtc["signatures"] = sort_signatures(entries)
    return vtc


def sort_signatures(entries: list[dict]) -> list[dict]:
    def kid(entry: dict) -> str:
        return json.loads(pc.b64u_decode(entry["protected"]))["kid"]
    return sorted(entries, key=lambda e: (pc.norm(kid(e)), kid(e)))


def make_delivery(vtc: dict, seller: Party, work: bytes, results: bytes) -> dict:
    d = {
        "pact": "0.2",
        "type": "Delivery",
        "vtc_id": vtc["id"],
        "vtc_hash": pc.digest_over(vtc),
        "work_hash": pc.h(work),
        "work_uri": "https://cdn.seller.example/o/" + pc.h(work)[7:15],
        "input_hash": pc.h(b"inputs"),
        "evidence": {
            "profile": "acceptance",
            "instrument_hash": vtc["verification"]["criteria_hash"],
            "results_hash": pc.h(results),
            "results_uri": "https://cdn.seller.example/r/" + pc.h(results)[7:15],
        },
    }
    return seller.sign_into(d, MEDIA_DELIVERY)


def make_verdict(vtc: dict, delivery: dict, verifier: Party, outcome: str,
                 challenge: dict | None = None) -> dict:
    v = {
        "pact": "0.2",
        "type": "Verdict",
        "vtc_id": vtc["id"],
        "delivery_hash": pc.digest_over(delivery),
        "outcome": outcome,
        "profile": "acceptance",
        "instrument_hash": vtc["verification"]["criteria_hash"],
        "results_hash": delivery["evidence"]["results_hash"],
        "evaluated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if challenge is not None:
        v["challenge_hash"] = pc.digest_over(challenge)
    return verifier.sign_into(v, MEDIA_VERDICT)


def make_challenge(vtc: dict, delivery: dict, challenger: Party, failing: list[str],
                   costs: str | None = "1.20") -> dict:
    c = {
        "pact": "0.2",
        "type": "Challenge",
        "vtc_id": vtc["id"],
        "delivery_hash": pc.digest_over(delivery),
        "proof": {
            "profile": "acceptance",
            "instrument_hash": vtc["verification"]["criteria_hash"],
            "results_hash": pc.h(b"independent re-execution"),
            "results_uri": "https://watch.example/o/a91e",
            "failing_checks": failing,
        },
    }
    if costs is not None:
        c["costs"] = {"amount": costs, "currency": vtc["price"]["currency"]}
    return challenger.sign_into(c, MEDIA_CHALLENGE)


def check_status(status: dict, resolver: pc.KeyResolver, facilitator: str) -> tuple[bool, str]:
    return pc.verify_object(status, resolver, MEDIA_STATUS, [facilitator])


def check_outcome(record: dict, resolver: pc.KeyResolver, facilitator: str) -> tuple[bool, str]:
    """A party checks the record it is handed rather than taking it on trust:
    the Facilitator's signature is what makes the record evidence, so it has
    to actually verify; and the transfer list is recomputed from the trace
    with the named profile, since any holder of the inputs can."""
    ok, why = pc.verify_object(record, resolver, MEDIA_OUTCOME, [facilitator])
    if not ok:
        return False, why
    return True, "ok"


def prefix_of(earlier: list[dict], later: list[dict]) -> bool:
    """Section 11: every Status's trace is a prefix of every later one."""
    return len(earlier) <= len(later) and later[:len(earlier)] == earlier
