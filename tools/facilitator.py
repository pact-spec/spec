"""A reference Facilitator for draft-laxsharma-pact-02: the eight operations of
Section 13, the state machine of Section 4 over a signed event trace, and an
Outcome Record per contract.

This is the first implementation that speaks the -02 protocol, written by the
author of the draft, which is the weakest evidence that a specification is
implementable. Two independent Facilitators producing the same trace from the
same posted records, and the same transfer list from the same trace and
profile, is the experiment of Section 1.4; this is the first half of it.

What it enforces, with the section each rule comes from, is listed in RULES.
Where the draft leaves a choice to the implementer, every such choice is
listed in CHOICES and repeated in tools/README.md, because a choice presented
as a rule is how a second implementer ends up disagreeing with the first.

Nothing here decides anything about value. Every event is handed to the terms
profile the contract names (tools/profile.py), which returns the entries it
emits, and the Facilitator records them and signs the result. It holds no
account and moves nothing; the -01 pools are gone with the -01 text.

Run it:

    python3 tools/facilitator.py --port 8402

Then drive it with agents.py, or measure it with measure.py.
"""

from __future__ import annotations

import argparse
import functools
import json
import math
import pathlib
import re
import socket
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pactcore as pc
import profile as terms

ROOT = pathlib.Path(__file__).resolve().parent.parent

RULES = """
Section 2     pact 0.3 only; an undefined member is refused everywhere except inside terms.parameters
Section 4.2   events are recorded in one order on the Facilitator's clock; an entry issued in a
              Status is never reordered, removed or altered; every clock-driven entry that is due
              is recorded before a Status is issued or a posted record is judged
Section 5     a contract carries exactly one verifying signature covering parties.buyer and one
              covering parties.seller, sorted by normalized kid, and no other
Section 5.3   terms.profile and profile_hash match an advertised profile; parameters validate
              against that profile's schema; the profile's admission rule runs at accepted
Section 6     a Delivery is accepted in FUNDED only, signed by the Seller, with evidence conformant
              to the verification profile and naming the instrument the contract committed to
              (evidence.instrument_hash equal to verification.criteria_hash); a nonconformant one is
              refused and recorded nowhere
Section 7.1   flows this Facilitator does not advertise are refused; the window is never extended
Section 7.2   a Verdict is accepted in DELIVERED (verdict-first) or WINDOW_OPEN (delivery-first)
              only while none stands, and in DISPUTED only answering a pending Challenge; its
              signer is the named verifier, or independent by Section 9.1, never the Facilitator;
              verdict-lapsed after max_verdict_seconds
Section 7.3   a Challenger's own Verdict on its Challenge is refused unless it is the named verifier
Section 7.3   a Challenge is accepted before closes_at only, with a conformant proof, never from
              the Seller, always from the Buyer if otherwise valid
Section 7.4   a pending Challenge lapses after max_dispute_seconds and the earlier Verdict stands
Section 8     the capability document is signed and lists only profiles whose vectors reproduce
Section 9.1   verifier independence is derived from normalized identifiers, never read from a field;
              an identifier or kid that does not parse is refused before any comparison,
              and a party identifier before the schema check
Section 10   a child is registered by a POST of its contract to the parent's resource, checked
              against the parent's own bytes and the timing rule L(child) < L(parent); a child's
              outcome is taken from this venue when the child lives here, else supplied by POST
              and checked against the registered child contract and its own trace;
              child-unresolved at L(child), and a record that arrives after it is still taken
              until the parent's terminal entry; the terminal entry waits for children-final
Section 11    every accepted request is answered with a signed Status carrying the entry it caused
Section 12    exactly one Outcome Record per terminal contract, signed by the Facilitator alone;
              it copies parties, task.spec_hash, verification and flow from the contract;
              outcome.verdict is the standing Verdict's digest, else verdict-lapsed, else none;
              work_hash is the recorded Delivery's, present exactly when one was recorded;
              terms_result is the profile's output and satisfies no-overdraft and closure, and an
              operation whose list would break either records nothing and answers internal-error
Section 13    a contract's 201 carries a Location naming {contract}/{id}, the id percent-encoded
              as one path segment, and a GET of that reference answers the contract's Status;
              Section 3 and the schema exclude the ids "." and "..", which a client resolving
              the reference would remove as dot segments (RFC 3986 Section 5.2.4)
Section 13.2  a POST whose body has a known digest returns 200 and the current Status; the same id
              with a different digest returns 409
Section 13.3  every failure is an RFC 9457 problem document naming the rule, with section for a
              rule in the document (the section stating the rule that refusal reports, chosen
              where it is raised) and profile plus profile_section for a rule in a profile;
              a failure no rule names (a path with no resource, a method not implemented or
              not allowed, a body whose length cannot be determined) is about:blank, no section
Section 14.1  JWS with a detached payload over the transmitted protected header, an algorithm
              allowlist, kid inside the protected header, typ equal to the media type, sorted
              signature sets, low-S ECDSA
Section 14.2  an amount in a posted contract or Challenge (price.amount, costs.amount) has no more
              decimal places than the settlement binding carries; a contract whose latest
              finality instant (Section 10.3) falls after the year 9999 is refused at propose
Section 17.13 the public key resolved for every accepted signature is recorded with the record
"""

CHOICES = """
Where the -02 text leaves a choice to the implementer this implementation chose, and says so:
C1  funded is recorded in the same call as accepted: there is no rail, so nothing can be
    observed and the Status of a 201 already reads FUNDED.
C2  Retrieval (GET) is open on the loopback interface. Section 17.12 restricts it by default
    and leaves the mechanism to the deployment; a deployment puts HTTP-layer authentication in
    front of this process. retrieval-restricted is never emitted here.
C3  Contract trees: a registered child this Facilitator holds is noticed when it reaches a
    terminal state; any other child's Outcome Record must be supplied by POST. No cross-venue
    GET is made.
C4  The one settlement binding advertised here has no rail and is taken to carry two decimal
    places: a price, or a Challenge's costs, with more is refused as amount-invalid. Amounts
    inside terms.parameters are not held to it; the profile's schedule is exact, so its
    entries have up to as many places as the amounts that produce them. A child registered
    here whose price.settlement names a binding not advertised here is not held to any
    number of places: that binding is its own Facilitator's (Section 10.2).
C5  Not implemented: the no-window flow, challenge deposits, network key resolution, any rail,
    the committed-sample draw. A contract that needs any of them is refused, not stranded.
C6  Section 4.2 has every clock-driven entry that is due recorded before a Status is issued or
    a posted record acted on, and does not say for which contracts; read literally, it is every
    contract held here. This implementation records them for the contract a request names and,
    before it reads a child, for each child of it held here, recursively; any other contract
    records its own at the next request that reaches it. The child entries one operation
    records follow the order in which the children were registered.
"""

PROBLEM_BASE = "tag:laxsharma79@gmail.com,2026:pact:problem:"

# Every type this implementation emits, with the HTTP status and every section
# of the draft a problem of the type names in its section member, in section
# order: for internal-error, which reports no rule, the section defining it,
# and for any other type each section a refusal of it cites. A refusal carries
# the one stating the rule it reports (Section 13.3): a type with one section
# takes it from here, and a type with more names it where it is raised (audit
# A7). Section 19.3 of the draft is rendered from and checked against this
# table by table6-check.py.
PROBLEMS = {
    "algorithm-not-permitted": (400, ("14.1",)),
    "amount-invalid": (422, ("14.2",)),
    "challenge-window-closed": (409, ("7.3",)),
    "child-outcome-invalid": (422, ("10.2",)),
    "deadline-invalid": (422, ("2", "14.2")),
    "evidence-nonconformant": (422, ("6",)),
    "facilitator-mismatch": (422, ("13.1",)),
    "finality-ordering-violation": (422, ("10.3",)),
    "flow-unsupported": (422, ("7.1",)),
    "identifier-not-evaluable": (422, ("9.1",)),
    "internal-error": (500, ("13",)),
    "no-recorded-delivery": (409, ("7.2",)),
    "object-conflict": (409, ("6", "7.3", "10.2", "13.2")),
    "parent-unresolvable": (422, ("10.2",)),
    "parties-not-distinct": (422, ("14.2",)),
    "payload-too-large": (413, ("13",)),
    "proof-nonconformant": (422, ("7.3",)),
    "retrieval-restricted": (403, ("17.12",)),
    "schema-invalid": (422, ("14.2",)),
    "settlement-unsupported": (422, ("13.1",)),
    "signature-invalid": (400, ("14.1", "14.1.1")),
    "signature-missing": (400, ("14.2",)),
    "signatures-unordered": (422, ("14.1",)),
    "terms-parameters-invalid": (422, ("5.3",)),
    "terms-unsupported": (422, ("5.3",)),
    "unexpected-signer": (422, ("6", "7.3", "14.2")),
    "unknown-contract": (404, ("13",)),
    "verdict-nonconformant": (422, ("7.2",)),
    "verifier-not-independent": (422, ("7.2", "7.3", "9.1")),
    "wrong-state": (409, ("6", "7.2", "10.2", "13")),
}

TERMINAL = ("FINAL", "SETTLED", "ABANDONED")

MEDIA_CONTRACT = "application/vnd.pact.contract+json"
MEDIA_DELIVERY = "application/vnd.pact.delivery+json"
MEDIA_VERDICT = "application/vnd.pact.verdict+json"
MEDIA_CHALLENGE = "application/vnd.pact.challenge+json"
MEDIA_STATUS = "application/vnd.pact.status+json"
MEDIA_OUTCOME = "application/vnd.pact.outcome+json"
MEDIA_FACILITATOR = "application/vnd.pact.facilitator+json"

MAX_BODY = 1 << 20  # one MiB; a contract is under three KB
LINGER_SECONDS = 2.0         # how long a closing connection reads what the client still sends
LINGER_BYTES = 4 * MAX_BODY   # and how much of it, before the socket is closed regardless

CONTRACTS = "/pact/v2/contracts"


def contract_path(vid: str) -> str:
    """{contract}/{id} of Section 13 as the 13.1 example prints it, an
    absolute-path reference. The schema admits nearly any string as an id,
    so the id is percent-encoded as one path segment (RFC 3986 Section 3.3):
    a space or a slash in it would otherwise make the Location no URI, or a
    different one. Encoding cannot help an id of "." or "..": both are
    unreserved and would go out as dot segments, which a client resolving the
    Location against the target URI (RFC 9110 Section 10.2.2) removes (RFC
    3986 Section 5.2.4), and %2E is no way out, since RFC 3986 Section 2.3
    makes it equivalent to ".". Section 3 and vtc.schema.json therefore
    exclude both, and a contract never reaches here with either."""
    return CONTRACTS + "/" + urllib.parse.quote(vid, safe="")


class Refuse(Exception):
    """A refusal under a rule of this document. `section` is the section
    stating the rule the refusal reports, and goes out as the problem's
    section member (Section 13.3). It must be one PROBLEMS lists for the type,
    and a type listed with more than one section must be given it here: a
    section fixed per type cited 14.2 for a Seller-signed Challenge whose
    rule is in 7.3 (audit A7). A wrong or missing section is this
    Facilitator's own defect, so it surfaces as internal-error."""

    def __init__(self, kind: str, detail: str, section: str | None = None, **extra: Any) -> None:
        sections = PROBLEMS.get(kind, (400, ("13.3",)))[1]
        if section is None and len(sections) != 1:
            raise ValueError(f"{kind} reports rules in sections {', '.join(sections)}; "
                             f"the refusal must name the one it reports")
        if section is not None and section not in sections:
            raise ValueError(f"section {section} is not listed for {kind}")
        self.kind = kind
        self.detail = detail
        self.section = section or sections[0]
        self.extra = extra
        super().__init__(detail)


class NoRule(Exception):
    """A failure that breaks no rule of the document or of a terms profile: a path
    with no resource, a method the resource does not take, a request whose body
    length cannot be determined. Section 13.3 still asks for problem details, so it
    is answered with the type about:blank (RFC 9457 Section 4.2.1) and no section."""

    def __init__(self, status: int, detail: str,
                 headers: tuple[tuple[str, str], ...] = ()) -> None:
        self.status = status
        self.detail = detail
        self.headers = headers
        super().__init__(detail)


# --------------------------------------------------------------------------
# Schemas. The published ones, loaded once. The Facilitator refuses to start
# without jsonschema because Section 14.2 makes schema conformance a MUST and
# a Facilitator that skips it is not one.
# --------------------------------------------------------------------------

class Schemas:
    def __init__(self) -> None:
        try:
            from jsonschema import Draft202012Validator
            from referencing import Registry, Resource
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "the reference Facilitator needs `jsonschema` and `referencing` "
                "to validate posted objects; pip install them") from exc
        docs = {p.name: json.loads(p.read_text())
                for p in (ROOT / "schemas").glob("*.schema.json")}
        registry = Registry().with_resources(
            [(name, Resource.from_contents(s)) for name, s in docs.items()])
        registry = registry.with_resources(
            [(s["$id"], Resource.from_contents(s)) for s in docs.values()])
        self._v = {name: Draft202012Validator(s, registry=registry)
                   for name, s in docs.items()}

    def check(self, obj: Any, name: str) -> None:
        errors = sorted(self._v[name].iter_errors(obj), key=lambda e: list(e.path))
        if errors:
            e = errors[0]
            where = "/".join(str(x) for x in e.path) or "(root)"
            raise Refuse("schema-invalid",
                         f"does not validate against {name} at {where}: {e.message}",
                         schema=name, path=where)


# --------------------------------------------------------------------------

def parse_rfc3339(s: str, label: str = "task.deadline") -> float:
    """RFC 3339 to a POSIX timestamp, UTC. Accepts Z, an offset, fractions.
    The form of a timestamp is Section 2's rule; the refusal quotes the value
    as received, not as rewritten for the parser."""
    try:
        t = s[:-1] + "+00:00" if s.endswith("Z") or s.endswith("z") else s
        dt = datetime.fromisoformat(t)
    except (ValueError, TypeError) as exc:
        raise Refuse("deadline-invalid", f"{label} {s!r} is not RFC 3339", "2") from exc
    if dt.tzinfo is None:
        raise Refuse("deadline-invalid", f"{label} {s!r} carries no zone", "2")
    return dt.astimezone(timezone.utc).timestamp()


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# 10000-01-01T00:00:00Z. A timestamp of Section 2 has a four-digit year, so no
# instant at or after this one can be written in a trace.
END_OF_TIMESTAMPS = 253402300800


def instant_text(ts: float) -> str:
    """An instant for the text of a refusal: never raises, so a refusal about
    an instant too late to write is still a refusal and not internal-error."""
    if ts < END_OF_TIMESTAMPS:
        return iso(ts)
    return "after 9999-12-31T23:59:59Z"


def latest_finality(vtc: dict) -> float:
    """L of Section 10.3, a POSIX timestamp; math.inf when the sum is too large
    for a float, which only ever compares as later than everything."""
    deadline = parse_rfc3339(vtc["task"]["deadline"])
    flow = vtc["flow"]
    if flow == "no-window":
        return deadline
    total = vtc["challenge"]["window_seconds"] + vtc["challenge"]["max_dispute_seconds"]
    if flow == "verdict-first":
        total += vtc["verification"]["max_verdict_seconds"]
    try:
        return deadline + total
    except OverflowError:
        return math.inf


def _sig_refusal(why: str) -> Refuse:
    """A failed pactcore.verify_object as the refusal it reports. An
    unresolvable kid is Section 14.1.1's rule; every other failure of a
    signature entry is 14.1's; a missing or second signature from a party is
    the contract rule of 14.2, the only caller that names required parties
    with more than one entry possible."""
    if why.startswith("algorithm"):
        return Refuse("algorithm-not-permitted", why)
    if "no signature" in why or "carries no signatures" in why:
        return Refuse("signature-missing", why)
    if "more than one signature" in why:
        return Refuse("unexpected-signer", why, "14.2")
    if why.startswith("cannot resolve kid"):
        return Refuse("signature-invalid", why, "14.1.1")
    return Refuse("signature-invalid", why, "14.1")


def _kid_of(entry: dict) -> str:
    return json.loads(pc.b64u_decode(entry["protected"]))["kid"]


@dataclass
class Child:
    vtc: dict
    digest: str
    facilitator: str
    latest: float
    record: dict | None = None
    unresolved: bool = False


@dataclass
class Contract:
    vtc: dict
    state: str = "ACCEPTED"
    trace: list[dict] = field(default_factory=list)
    transfers: list[dict] = field(default_factory=list)
    delivery: dict | None = None
    delivered_at: float | None = None
    window_closes_at: float | None = None
    verdicts: list[dict] = field(default_factory=list)      # trace entries, in order
    challenges: dict[str, dict] = field(default_factory=dict)  # digest -> object
    challenge_at: dict[str, float] = field(default_factory=dict)
    pending: list[str] = field(default_factory=list)        # challenge digests
    children: dict[str, Child] = field(default_factory=dict)  # child digest -> Child
    outcome: dict | None = None
    created_at: float = 0.0
    deadline: float = 0.0
    keys: dict[str, str] = field(default_factory=dict)      # Section 17.13 record

    @property
    def id(self) -> str:
        return self.vtc["id"]

    @property
    def buyer(self) -> str:
        return self.vtc["parties"]["buyer"]

    @property
    def seller(self) -> str:
        return self.vtc["parties"]["seller"]

    @property
    def flow(self) -> str:
        return self.vtc["flow"]

    @property
    def standing(self) -> dict | None:
        return self.verdicts[-1] if self.verdicts else None

    def digest(self) -> str:
        return pc.digest_over(self.vtc)


def _atomic(fn):
    """Every public operation records all of its entries or none of them. A
    refusal leaves the clock-driven entries it recorded first (they were due
    whatever the request was); an internal failure, such as a terms result that
    breaks an invariant of Section 12.1, rolls back everything the operation
    recorded, so no entry is kept that no Status carried (audit A4)."""
    @functools.wraps(fn)
    def run(self, *args, **kwargs):
        with self.lock:
            try:
                return fn(self, *args, **kwargs)
            except Refuse as exc:
                if exc.kind == "internal-error":
                    self._rollback()
                raise
            except (terms.ProfileRefusal, pc.NotEvaluable):
                raise
            except Exception as exc:
                self._rollback()
                raise Refuse("internal-error", f"the Facilitator failed internally "
                             f"({type(exc).__name__}); nothing this request caused was recorded") from exc
    return run


class Facilitator:
    """Runs the state machine and signs the records. Thread safe under the
    threading HTTP server."""

    def __init__(self, identity: str, key: pc.Key, resolver: pc.KeyResolver,
                 now: Any = time.time, base_url: str = "http://127.0.0.1:8402") -> None:
        pc.norm(identity)   # Section 9.1: a Facilitator identifier that does not parse is a configuration error
        self.identity = identity
        self.key = key
        self.resolver = resolver
        self.now = now
        self.base_url = base_url.rstrip("/")
        self.schemas = Schemas()
        self.contracts: dict[str, Contract] = {}
        self.seen: dict[tuple[str, str], str] = {}  # (kind, digest) -> vtc_id
        self.lock = threading.RLock()
        self.message_count = 0
        self._op: float | None = None   # one clock reading per operation (Section 4.2)
        self._undo: dict = {}           # contract id -> its state before this operation
        self._created: list[str] = []
        self._seen_added: list = []
        # What this Facilitator advertises, Section 8. Contracts outside it are
        # refused at propose rather than accepted and stranded.
        self.settlement_bindings = [
            {"id": "https://settle.example/bindings/ledger-1",
             "networks": ["eip155:8453"], "assets": ["USDC"]}]
        self.binding_places = {"https://settle.example/bindings/ledger-1": 2}   # CHOICES C4
        self.flows = ["verdict-first", "delivery-first"]
        self.verification_profiles = ["acceptance"]
        self.max_contract_value = {"amount": "50000.00", "currency": "USDC"}
        prof = terms.BondedRestitution()
        ok, why = prof.reproduces()
        if not ok:  # Section 8: never list a profile whose vectors do not reproduce
            raise RuntimeError(f"terms profile {terms.ID} does not reproduce its vectors: {why}")
        self.profiles: dict[tuple[str, str], terms.BondedRestitution] = {
            (terms.ID, prof.profile_hash): prof}

    # -- Section 13.2 ------------------------------------------------------
    def _remember(self, kind: str, obj: dict, vid: str) -> None:
        key = (kind, pc.digest_over(obj))
        if key not in self.seen:
            self._seen_added.append(key)
        self.seen[key] = vid

    # -- one operation records everything or nothing (Section 12.1, audit A4) --
    def _snap(self, c: "Contract") -> None:
        if c.id in self._undo or c.id in self._created:
            return
        self._undo[c.id] = (
            c.state, len(c.trace), len(c.transfers), c.delivery, c.delivered_at, c.window_closes_at,
            list(c.verdicts), dict(c.challenges), dict(c.challenge_at), list(c.pending),
            {k: (ch.record, ch.unresolved) for k, ch in c.children.items()}, c.outcome, dict(c.keys))

    def _rollback(self) -> None:
        for vid, snap in self._undo.items():
            c = self.contracts[vid]
            (c.state, n_trace, n_transfers, c.delivery, c.delivered_at, c.window_closes_at,
             c.verdicts, c.challenges, c.challenge_at, c.pending, kids, c.outcome, c.keys) = snap
            del c.trace[n_trace:]
            del c.transfers[n_transfers:]
            for k in list(c.children):
                if k not in kids:
                    del c.children[k]
                else:
                    c.children[k].record, c.children[k].unresolved = kids[k]
        for vid in self._created:
            self.contracts.pop(vid, None)
        for key in self._seen_added:
            self.seen.pop(key, None)

    def _replay(self, kind: str, obj: dict) -> tuple[int, dict] | None:
        """200 with the CURRENT Status, not a snapshot taken at creation."""
        vid = self.seen.get((kind, pc.digest_over(obj)))
        if vid is None:
            return None
        c = self._contract(vid)
        self._tick(c)
        return 200, self._status(c)

    # -- the trace, Section 4.2 -------------------------------------------
    def _profile(self, c: Contract) -> terms.BondedRestitution:
        return self.profiles[(c.vtc["terms"]["profile"], c.vtc["terms"]["profile_hash"])]

    def _begin(self) -> float:
        # whole seconds: what the trace prints is what the comparisons use (Section 4.2)
        self._op = float(math.floor(self.now()))
        self._undo, self._created, self._seen_added = {}, [], []
        return self._op

    def _op_now(self) -> float:
        return self._op if self._op is not None else float(math.floor(self.now()))

    def _record(self, c: Contract, event: str, **members: Any) -> dict:
        entry = {"event": event, "at": iso(self._op_now())}
        entry.update({k: v for k, v in members.items() if v is not None})
        c.trace.append(entry)
        # Section 5.3: the profile's schedule is invoked with the event and
        # nothing else; what it emits is recorded, never decided here.
        c.transfers.extend(self._profile(c).step(c.vtc, c.trace))
        return entry

    def _status(self, c: Contract) -> dict:
        st = {
            "pact": "0.3", "type": "ContractStatus",
            "vtc_id": c.id, "vtc_hash": c.digest(), "state": c.state,
            "trace": list(c.trace), "issued_at": iso(self._op_now()),
        }
        st["signature"] = pc.sign(st, self.key, MEDIA_STATUS)
        self._self_check(st, "status.schema.json")
        return st

    def _self_check(self, obj: dict, schema: str) -> None:
        # A record this Facilitator built that fails its own schema is its own
        # defect, not the requester's: internal-error, and nothing recorded.
        try:
            self.schemas.check(obj, schema)
        except Refuse as exc:
            raise Refuse("internal-error", f"a record this Facilitator built fails {schema}: {exc.detail}")

    def _record_keys(self, c: Contract, obj: dict) -> None:
        # Section 17.13: the key material resolved at acceptance is recorded, so
        # a later rotation or revocation does not orphan an accepted signature.
        for kid in pc.signer_kids(obj):
            key = self.resolver.resolve(kid)
            if key is not None and kid not in c.keys:
                c.keys[kid] = pc.b64u(pc.public_bytes(key))

    # -- clock-driven edges, Table 2 ---------------------------------------
    def _tick(self, c: Contract) -> None:
        """Advance the contract along every clock-driven edge that is due, in
        the order of Table 2, until nothing more is due."""
        for _ in range(16):
            before = len(c.trace)
            now = self._op_now()
            if c.state in ("ACCEPTED", "FUNDED") and now >= c.deadline:
                self._record(c, "deadline-passed")
                c.state = "AWAITING_CHILDREN"
            elif (c.state == "DELIVERED" and c.flow == "verdict-first"
                  and c.delivered_at is not None
                  and now >= c.delivered_at + c.vtc["verification"]["max_verdict_seconds"]):
                self._record(c, "verdict-lapsed")
                self._open_window(c)
            elif c.state == "DISPUTED":
                limit = c.vtc["challenge"]["max_dispute_seconds"]
                for digest in list(c.pending):
                    if now >= c.challenge_at[digest] + limit:
                        self._record(c, "dispute-lapsed", object=digest)
                        c.pending.remove(digest)
                if not c.pending:
                    c.state = "WINDOW_OPEN"
            elif (c.state == "WINDOW_OPEN" and c.window_closes_at is not None
                  and now >= c.window_closes_at and not c.pending):
                self._record(c, "window-closed")
                c.state = "AWAITING_CHILDREN"
            self._children_tick(c)
            if c.state == "AWAITING_CHILDREN":
                self._children_final_if_ready(c)
            if len(c.trace) == before:
                return

    def _children_tick(self, c: Contract) -> None:
        if c.state in TERMINAL:
            return
        now = self._op_now()
        for child in c.children.values():
            if child.record is not None:
                continue
            local = self.contracts.get(child.vtc["id"])
            if local is not None and local is not c and local.digest() == child.digest and local.outcome is None:
                # Section 4.2: a child this venue holds records its own due clock-driven
                # entries first, so one that its clock ended before L(child) is child-final
                # here, not child-unresolved, whichever contract was read first
                self._snap(local)
                self._tick(local)
            if local is not None and local.outcome is not None and local.digest() == child.digest:
                # CHOICES C3: obtained from this venue, after child-unresolved too, as a
                # posted record is (Sections 10.2 and 12.2)
                child.record = local.outcome
                child.unresolved = False
                self._record(c, "child-final", object=pc.digest_over(local.outcome),
                             child=child.digest)
            elif now >= child.latest and not child.unresolved:
                child.unresolved = True
                self._record(c, "child-unresolved", child=child.digest)

    def _children_final_if_ready(self, c: Contract) -> None:
        if any(ch.record is None and not ch.unresolved for ch in c.children.values()):
            return
        self._record(c, "children-final")
        self._terminal(c)

    def _open_window(self, c: Contract) -> None:
        closes = self._op_now() + c.vtc["challenge"]["window_seconds"]
        c.window_closes_at = closes
        self._record(c, "window-opened", closes_at=iso(closes))
        c.state = "WINDOW_OPEN"

    # -- Section 12: the terminal entry and the Outcome Record --------------
    def _terminal(self, c: Contract) -> None:
        st = c.standing
        if any(e["event"] == "deadline-passed" for e in c.trace):
            state, upheld = "ABANDONED", False
        elif st is not None and st["outcome"] == "FAIL":
            state, upheld = "SETTLED", "answers" in st
        else:
            state, upheld = "FINAL", False
        self._record(c, "terminal", state=state, challenge_upheld=upheld)
        prof = self._profile(c)
        ok, why = prof.check(c.vtc, c.transfers, terminal=True)
        if not ok:
            # The profile broke its own arithmetic. Never sign that; the
            # operation is rolled back whole (_atomic), so the trace keeps
            # nothing this call recorded and no later call finds a stray
            # children-final (audit A4).
            raise Refuse("internal-error", f"terms result fails an invariant: {why}")
        c.state = state
        record = {
            "pact": "0.3", "type": "OutcomeRecord",
            "vtc_id": c.id, "vtc_hash": c.digest(),
            "parties": c.vtc["parties"],
            **pc.outcome_scope(c.vtc),          # task.spec_hash, verification, flow (Section 12)
            "outcome": {"state": state, "challenge_upheld": upheld,
                        "verdict": pc.outcome_verdict(c.trace)},
        }
        delivered = [e for e in c.trace if e["event"] == "delivered"]
        if delivered:
            # Section 12: copied from the Delivery the delivered entry names.
            assert c.delivery is not None and pc.digest_over(c.delivery) == delivered[0]["object"]
            record["work_hash"] = c.delivery["work_hash"]
        record["trace"] = list(c.trace)
        record["terms_result"] = {
            "profile": terms.ID, "profile_hash": prof.profile_hash,
            "currency": c.vtc["price"]["currency"], "transfers": list(c.transfers),
        }
        if c.children:
            leaves = sorted(bytes.fromhex(pc.digest_over(ch.record)[7:]) for ch in c.children.values()
                            if ch.record is not None)
            record["children_merkle_root"] = "sha256:" + pc.mth(leaves).hex()
        record["signatures"] = [pc.sign(record, self.key, MEDIA_OUTCOME)]
        self._self_check(record, "outcome.schema.json")
        problems = pc.outcome_errors(record, c.vtc, c.delivery)
        if problems:
            raise Refuse("internal-error", "the Outcome Record breaks Section 12: " + "; ".join(problems))
        c.outcome = record

    def _evaluable(self, obj: dict, parties: bool = False) -> None:
        """Section 9.1: refuse, before any comparison, an object naming an
        identifier, or signed under a kid, that does not parse."""
        names = []
        if parties:
            # Runs before the schema check, so it reads only what is there:
            # a member that is not a string is left for the schema to refuse.
            ps = obj.get("parties")
            if isinstance(ps, dict):
                names += [(f"parties.{role}", v) for role, v in ps.items() if isinstance(v, str)]
            parent = obj.get("parent")
            if isinstance(parent, dict) and isinstance(parent.get("facilitator"), str):
                names.append(("parent.facilitator", parent["facilitator"]))
        try:
            kids = pc.signer_kids(obj)
        except (TypeError, AttributeError):
            kids = []     # a malformed signature member is the schema's to refuse
        names += [("kid", k) for k in kids if isinstance(k, str)]
        for where, ident in names:
            try:
                pc.norm(ident)
            except pc.NotEvaluable as exc:
                raise Refuse("identifier-not-evaluable",
                             f"{where} is not evaluable under Section 9.1: {exc}",
                             identifier=ident)

    # -- Propose, Section 13.1 --------------------------------------------
    def _check_contract(self, vtc: dict) -> None:
        """Everything Section 14 asks of a contract on its own, used both at
        propose and at child registration."""
        if not vtc.get("signatures"):
            raise Refuse("signature-missing", "the contract carries no signatures")
        # Section 9.1 before the schema: a party identifier that the published
        # schema would also reject is refused as identifier-not-evaluable.
        self._evaluable(vtc, parties=True)
        self.schemas.check(vtc, "vtc.schema.json")
        parties = vtc["parties"]
        buyer, seller = parties["buyer"], parties["seller"]
        if pc.same_party(buyer, seller):
            raise Refuse("parties-not-distinct",
                         "buyer and seller are equivalent identifiers after the "
                         "normalization of Section 9.1", buyer=buyer, seller=seller)
        self._amount_fits(vtc["price"]["amount"], vtc["price"]["settlement"], "price.amount")
        # Section 14.1 and 14.2: exactly one signature covering each of buyer and
        # seller, verifying, nobody else, in sorted order.
        for kid in pc.signer_kids(vtc):
            if not (pc.kid_covers(kid, buyer) or pc.kid_covers(kid, seller)):
                raise Refuse("unexpected-signer",
                             "the contract carries a signature from a party that is "
                             "neither its Buyer nor its Seller", "14.2", signer=kid)
        ok, why = pc.verify_object(vtc, self.resolver, MEDIA_CONTRACT, [buyer, seller])
        if not ok:
            raise _sig_refusal(why)
        ok, why = pc.signatures_ordered(vtc)
        if not ok:
            raise Refuse("signatures-unordered", why)

    def _amount_fits(self, amount: str, settlement: str, where: str) -> None:
        """Section 14.2: an amount with more decimal places than the settlement
        binding carries is refused (CHOICES C4: two places here). A binding this
        Facilitator does not advertise is not one it can measure against: at
        propose such a contract is refused as settlement-unsupported, and a
        child registered here from another venue is its own Facilitator's to
        check (Section 10.2)."""
        places = self.binding_places.get(settlement)
        if places is None:
            return
        if pc.places_of(amount) > places:
            raise Refuse("amount-invalid", f"{where} {amount!r} has more decimal places than the "
                         f"settlement binding carries ({places}; CHOICES C4)", member=where)

    @_atomic
    def propose(self, vtc: dict) -> tuple[int, dict]:
        with self.lock:
            self._begin()
            hit = self._replay("contract", vtc)
            if hit is not None:
                return hit
            self._check_contract(vtc)
            vid = vtc["id"]
            if vid in self.contracts:
                raise Refuse("object-conflict", f"contract {vid} exists with a different digest", "13.2")
            parties = vtc["parties"]
            buyer, seller = parties["buyer"], parties["seller"]
            if not pc.same_party(parties["facilitator"], self.identity):
                raise Refuse("facilitator-mismatch",
                             "the contract names a different Facilitator; accepting it "
                             "would make this signed instrument replayable across venues",
                             named=parties["facilitator"], this=self.identity)
            named = parties.get("verifier")
            if named:
                for who, label in ((buyer, "buyer"), (seller, "seller"),
                                   (self.identity, "facilitator")):
                    if pc.same_party(named, who):
                        raise Refuse("verifier-not-independent",
                                     f"parties.verifier is the {label} after normalization",
                                     "9.1", verifier=named)
            price_m = vtc["price"]
            binding = next((b for b in self.settlement_bindings
                            if b["id"] == price_m["settlement"]), None)
            if (binding is None or price_m["network"] not in binding["networks"]
                    or price_m["currency"] not in binding["assets"]):
                raise Refuse("settlement-unsupported",
                             "settlement, network or asset is not one this Facilitator "
                             "advertises in its capability document",
                             settlement=price_m["settlement"], network=price_m["network"],
                             currency=price_m["currency"])
            if price_m["currency"] != self.max_contract_value["currency"]:
                raise Refuse("settlement-unsupported",
                             "price is not stated in the currency of this Facilitator's max_contract_value",
                             currency=price_m["currency"])
            if pc.exact(price_m["amount"]) > pc.exact(self.max_contract_value["amount"]):
                raise Refuse("settlement-unsupported",
                             f"price exceeds this Facilitator's max_contract_value "
                             f"{self.max_contract_value['amount']}")
            if vtc["flow"] not in self.flows:
                raise Refuse("flow-unsupported", f"flow {vtc['flow']!r} is not implemented; "
                             f"accepting it would strand the contract", supported=self.flows)
            if vtc["verification"]["profile"] not in self.verification_profiles:
                raise Refuse("settlement-unsupported",
                             f"verification profile {vtc['verification']['profile']!r} "
                             f"is not one this Facilitator supports",
                             supported=self.verification_profiles)
            t = vtc["terms"]
            prof = self.profiles.get((t["profile"], t["profile_hash"]))
            if prof is None:
                raise Refuse("terms-unsupported",
                             "terms.profile and terms.profile_hash do not match a profile "
                             "this Facilitator lists in its capability document",
                             profile=t["profile"], profile_hash=t["profile_hash"])
            err = prof.parameters_error(t["parameters"])
            if err:
                raise Refuse("terms-parameters-invalid", err, profile=t["profile"])
            deadline = parse_rfc3339(vtc["task"]["deadline"])
            if deadline <= self._op_now():
                raise Refuse("deadline-invalid",
                             "task.deadline is already past on this Facilitator's clock", "14.2")
            # Section 14.2: an L (Section 10.3) that a timestamp cannot write is
            # refused here, before anything is recorded. L bounds closes_at only
            # when verdict-lapsed is recorded the instant it falls due; one
            # recorded later (Section 4.2 allows the first opportunity) opens
            # the window later, so this refusal narrows the overflow without
            # excluding it.
            latest = latest_finality(vtc)
            if latest >= END_OF_TIMESTAMPS:
                raise Refuse("deadline-invalid",
                             "the contract's latest finality instant (Section 10.3) falls after the "
                             "year 9999, so a closes_at its trace could carry has no timestamp form",
                             "14.2", latest_finality=instant_text(latest))
            prof.admit(vtc)   # raises terms.ProfileRefusal, reported per Section 13.3

            c = Contract(vtc=vtc, created_at=self._op_now(), deadline=deadline)
            self.contracts[c.id] = c
            self._created.append(c.id)
            self._record_keys(c, vtc)
            self._remember("contract", vtc, c.id)
            self._record(c, "accepted", object=c.digest())
            c.state = "ACCEPTED"
            # CHOICES C1: no rail, nothing to observe, funded in the same call.
            self._record(c, "funded")
            c.state = "FUNDED"
            return 201, self._status(c)

    # -- Retrieve, Section 11 and 12 --------------------------------------
    @_atomic
    def get_status(self, vid: str) -> tuple[int, dict]:
        with self.lock:
            self._begin()
            c = self._contract(vid)
            self._tick(c)
            return 200, self._status(c)

    @_atomic
    def get_outcome(self, vid: str) -> tuple[int, dict]:
        with self.lock:
            self._begin()
            c = self._contract(vid)
            self._tick(c)
            if c.outcome is None:
                raise Refuse("wrong-state", f"contract {vid} is {c.state} and not terminal, "
                             f"so no Outcome Record exists yet", "13")
            return 200, c.outcome

    def _contract(self, vid: str) -> Contract:
        c = self.contracts.get(vid)
        if c is None:
            raise Refuse("unknown-contract", f"no contract {vid}")
        self._snap(c)
        return c

    # -- Submit Delivery, Section 6 ---------------------------------------
    @_atomic
    def submit_delivery(self, dlv: dict) -> tuple[int, dict]:
        with self.lock:
            self._begin()
            hit = self._replay("delivery", dlv)
            if hit is not None:
                return hit
            if "signature" not in dlv:
                raise Refuse("signature-missing", "the Delivery carries no signature")
            for member in ("vtc_id", "vtc_hash"):
                if not isinstance(dlv.get(member), str):
                    raise Refuse("schema-invalid", f"the Delivery lacks {member}")
            c = self._contract(dlv["vtc_id"])
            self._tick(c)
            if dlv["vtc_hash"] != c.digest():
                raise Refuse("object-conflict", "vtc_hash does not commit to this contract",
                             "6", expected=c.digest(), received=dlv["vtc_hash"])
            if c.state != "FUNDED":
                raise Refuse("wrong-state", f"contract {c.id} is {c.state}; a Delivery "
                             f"is only accepted in FUNDED", "6")
            self._evaluable(dlv)
            for kid in pc.signer_kids(dlv):
                if not pc.kid_covers(kid, c.seller):
                    raise Refuse("unexpected-signer", "a Delivery is signed by the Seller only",
                                 "6", signer=kid)
            ok, why = pc.verify_object(dlv, self.resolver, MEDIA_DELIVERY, [c.seller])
            if not ok:
                raise _sig_refusal(why)
            # Section 6: shape, not substance. A nonconformant Delivery is
            # refused and recorded in no trace; the contract stays FUNDED.
            reason = self._delivery_nonconformance(c, dlv)
            if reason is None:
                try:
                    self.schemas.check(dlv, "delivery.schema.json")
                except Refuse as exc:
                    if str(exc.extra.get("path", "")).startswith("evidence"):
                        reason = exc.detail
                    else:
                        raise
            if reason is not None:
                raise Refuse("evidence-nonconformant", reason, state=c.state)

            c.delivery = dlv
            c.delivered_at = self._op_now()
            self._record_keys(c, dlv)
            self._remember("delivery", dlv, c.id)
            self._record(c, "delivered", object=pc.digest_over(dlv))
            c.state = "DELIVERED"
            if c.flow == "delivery-first":
                self._open_window(c)
            elif c.flow == "no-window":
                c.state = "AWAITING_CHILDREN"
                self._tick(c)
            return 202, self._status(c)

    def _delivery_nonconformance(self, c: Contract, dlv: dict) -> str | None:
        ev = dlv.get("evidence")
        ver = c.vtc["verification"]
        if not isinstance(ev, dict):
            return "the Delivery carries no evidence member"
        if ev.get("profile") != ver["profile"]:
            return (f"evidence profile {ev.get('profile')!r} does not match the "
                    f"contract's declared profile {ver['profile']!r}")
        if ev.get("instrument_hash") != ver["criteria_hash"]:
            return "the evidence does not commit to the instrument the contract committed to"
        if "results_hash" not in ev:
            return "the acceptance profile requires results_hash in the evidence"
        if ver["tier"] == "T0-reexec" and "input_hash" not in dlv:
            return "input_hash is required for a tier whose proof of nonconformance re-executes (Section 6)"
        return None

    def _delivery_digest(self, c: Contract) -> str:
        if c.delivery is None:
            raise Refuse("no-recorded-delivery",
                         f"contract {c.id} has no recorded Delivery to judge")
        return pc.digest_over(c.delivery)

    # -- Record Verdict, Section 7.2 --------------------------------------
    @_atomic
    def record_verdict(self, verdict: dict) -> tuple[int, dict]:
        with self.lock:
            self._begin()
            hit = self._replay("verdict", verdict)
            if hit is not None:
                return hit
            if "signature" not in verdict:
                raise Refuse("signature-missing", "the Verdict carries no signature")
            self.schemas.check(verdict, "verdict.schema.json")
            c = self._contract(verdict["vtc_id"])
            self._tick(c)
            recorded = self._delivery_digest(c)
            if verdict["delivery_hash"] != recorded:
                raise Refuse("verdict-nonconformant",
                             "delivery_hash does not commit to the recorded Delivery, "
                             "including its signature", expected=recorded,
                             received=verdict["delivery_hash"])
            answers = verdict.get("challenge_hash")
            admissible = ((c.state == "DELIVERED" and c.flow == "verdict-first" and c.standing is None)
                          or (c.state == "WINDOW_OPEN" and c.flow == "delivery-first" and c.standing is None)
                          or c.state == "DISPUTED")
            if not admissible:
                raise Refuse("wrong-state",
                             f"contract {c.id} is {c.state} under {c.flow}"
                             f"{' with a Verdict standing' if c.standing is not None else ''}; "
                             f"Table 2 lists no verdict entry for it", "7.2")
            ver = c.vtc["verification"]
            if verdict["instrument_hash"] != ver["criteria_hash"]:
                raise Refuse("verdict-nonconformant",
                             "instrument_hash is not the instrument the contract committed to",
                             expected=ver["criteria_hash"], received=verdict["instrument_hash"])
            if verdict["profile"] != ver["profile"]:
                raise Refuse("verdict-nonconformant",
                             f"profile {verdict['profile']!r} is not the contract's "
                             f"{ver['profile']!r}")
            if c.state == "DISPUTED":
                if answers is None:
                    raise Refuse("verdict-nonconformant",
                                 "the contract is DISPUTED; a Verdict must name the pending "
                                 "Challenge it answers in challenge_hash", pending=c.pending)
                if answers not in c.pending:
                    raise Refuse("verdict-nonconformant",
                                 "challenge_hash names no pending Challenge", received=answers)
            elif answers is not None:
                raise Refuse("verdict-nonconformant",
                             "challenge_hash is present and no Challenge is pending")

            kids = pc.signer_kids(verdict)
            if not kids:
                raise Refuse("signature-missing", "the Verdict carries no signature")
            self._evaluable(verdict)
            self._check_verdict_signer(c, kids, answers)
            named = c.vtc["parties"].get("verifier")
            ok, why = pc.verify_object(verdict, self.resolver, MEDIA_VERDICT,
                                       [named] if named else [])
            if not ok:
                raise _sig_refusal(why)

            # Every check passed; only now does the trace move.
            self._record_keys(c, verdict)
            self._remember("verdict", verdict, c.id)
            outcome = verdict["outcome"]
            superseded = c.standing["object"] if c.standing is not None else None
            entry = self._record(c, "verdict", object=pc.digest_over(verdict), signer=kids[0],
                                 outcome=outcome, answers=answers, supersedes=superseded)
            c.verdicts.append(entry)
            if answers is not None:
                c.pending.remove(answers)
            if outcome == "FAIL":
                c.state = "AWAITING_CHILDREN"
                self._tick(c)
            elif c.state == "DELIVERED":
                self._open_window(c)
                self._tick(c)
            elif c.state == "DISPUTED" and not c.pending:
                c.state = "WINDOW_OPEN"
                self._tick(c)
            return 201, self._status(c)

    def _check_verdict_signer(self, c: Contract, kids: list[str], answers: str | None) -> None:
        # Section 7.2: the named verifier, or Section 9.1 derived against the
        # signer; never the Facilitator; never the Challenger it answers.
        named = c.vtc["parties"].get("verifier")
        if named and not any(pc.kid_covers(k, named) for k in kids):
            raise Refuse("verifier-not-independent",
                         "the contract names a verifier and the Verdict is not signed "
                         "by that party", "7.2", signer=kids[0], required_verifier=named)
        for kid in kids:
            for who, label in ((c.seller, "Seller"), (c.buyer, "Buyer"),
                               (self.identity, "Facilitator")):
                if pc.kid_covers(kid, who):
                    raise Refuse("verifier-not-independent",
                                 f"the Verdict is signed by the contract's {label}",
                                 "9.1", signer=kid)
            if answers is not None and not named:
                for ck in pc.signer_kids(c.challenges[answers]):
                    if pc.same_party(ck, kid):
                        raise Refuse("verifier-not-independent",
                                     "a Challenger's own assertion is not a Verdict on its "
                                     "Challenge (Section 7.3)", "7.3", signer=kid)

    # -- Open Challenge, Section 7.3 --------------------------------------
    @_atomic
    def open_challenge(self, ch: dict) -> tuple[int, dict]:
        with self.lock:
            self._begin()
            hit = self._replay("challenge", ch)
            if hit is not None:
                return hit
            if "signature" not in ch:
                raise Refuse("signature-missing", "the Challenge carries no signature")
            self.schemas.check(ch, "challenge.schema.json")
            c = self._contract(ch["vtc_id"])
            self._tick(c)
            if c.state not in ("WINDOW_OPEN", "DISPUTED"):
                raise Refuse("challenge-window-closed",
                             f"no challenge window is open: contract {c.id} is {c.state}",
                             state=c.state)
            recorded = self._delivery_digest(c)
            if ch["delivery_hash"] != recorded:
                raise Refuse("object-conflict",
                             "delivery_hash does not commit to the recorded Delivery",
                             "7.3", expected=recorded, received=ch["delivery_hash"])
            if c.window_closes_at is None or self._op_now() >= c.window_closes_at:
                raise Refuse("challenge-window-closed",
                             "the challenge window has closed", closes_at=iso(c.window_closes_at or 0))
            proof = ch["proof"]
            ver = c.vtc["verification"]
            if proof.get("profile") != ver["profile"]:
                raise Refuse("proof-nonconformant",
                             f"proof profile {proof.get('profile')!r} is not the "
                             f"contract's {ver['profile']!r}")
            if proof.get("instrument_hash") != ver["criteria_hash"]:
                raise Refuse("proof-nonconformant",
                             "the proof does not commit to the instrument the contract "
                             "committed to")
            if "results_hash" not in proof:
                raise Refuse("proof-nonconformant",
                             "the acceptance profile requires results_hash in the proof")
            if "costs" in ch:   # Section 14.2, audit A5: every document-level amount, not price alone
                self._amount_fits(ch["costs"]["amount"], c.vtc["price"]["settlement"], "costs.amount")
            self._evaluable(ch)
            ok, why = pc.verify_object(ch, self.resolver, MEDIA_CHALLENGE, [])
            if not ok:
                raise _sig_refusal(why)
            kids = pc.signer_kids(ch)
            if any(pc.kid_covers(k, c.seller) for k in kids):
                raise Refuse("unexpected-signer", "a performer's statement against its own "
                             "Delivery is not a proof of nonconformance (Section 7.3)", "7.3", signer=kids[0])
            # A Challenge is a proof of nonconformance submitted for evaluation, not a
            # finding. The Buyer is admissible; nothing here checks who else is.
            digest = pc.digest_over(ch)
            c.challenges[digest] = ch
            c.challenge_at[digest] = self._op_now()
            c.pending.append(digest)
            self._record_keys(c, ch)
            self._remember("challenge", ch, c.id)
            self._record(c, "challenge", object=digest, signer=kids[0], costs=ch.get("costs"))
            c.state = "DISPUTED"
            return 202, self._status(c)

    # -- Contract trees, Section 10 ---------------------------------------
    @_atomic
    def register_child(self, parent_id: str, child: dict) -> tuple[int, dict]:
        with self.lock:
            self._begin()
            p = self._contract(parent_id)
            self._tick(p)
            hit = self.seen.get(("child", pc.digest_over(child)))
            if hit == parent_id:
                return 200, self._status(p)
            if p.state in TERMINAL:
                raise Refuse("wrong-state", f"parent {parent_id} is {p.state}", "10.2")
            self._check_contract(child)
            par = child.get("parent")
            if par is None:
                raise Refuse("parent-unresolvable", "the registered contract carries no parent")
            if par["vtc_hash"] != p.digest() or par["vtc_id"] != p.id:
                raise Refuse("parent-unresolvable",
                             "parent.vtc_hash is not this parent's digest",
                             expected=p.digest(), received=par["vtc_hash"])
            if not pc.same_party(par["facilitator"], self.identity):
                raise Refuse("parent-unresolvable",
                             "parent.facilitator is not this Facilitator",
                             named=par["facilitator"])
            if not pc.same_party(child["parties"]["buyer"], p.seller):
                raise Refuse("parent-unresolvable",
                             "the child's Buyer is not the parent's Seller after normalization",
                             child_buyer=child["parties"]["buyer"], parent_seller=p.seller)
            lc, lp = latest_finality(child), latest_finality(p.vtc)
            if not lc < lp:
                raise Refuse("finality-ordering-violation",
                             "the child's latest finality instant is not earlier than the "
                             "parent's (Section 10.3)", child_latest=instant_text(lc),
                             parent_latest=instant_text(lp))
            digest = pc.digest_over(child)
            if digest in p.children:
                return 200, self._status(p)
            p.children[digest] = Child(vtc=child, digest=digest,
                                       facilitator=child["parties"]["facilitator"], latest=lc)
            if ("child", digest) not in self.seen:
                self._seen_added.append(("child", digest))
            self.seen[("child", digest)] = parent_id
            self._record(p, "child-registered", object=digest,
                         facilitator=child["parties"]["facilitator"])
            self._tick(p)
            return 201, self._status(p)

    @_atomic
    def supply_child_outcome(self, parent_id: str, child_hash: str, record: dict) -> tuple[int, dict]:
        with self.lock:
            self._begin()
            p = self._contract(parent_id)
            self._tick(p)
            child = next((ch for ch in p.children.values() if ch.digest == child_hash), None)
            if child is None:
                raise Refuse("unknown-contract", f"no registered child with digest {child_hash} under {parent_id}")
            if child.record is not None:   # a replay of an accepted record is the existing resource (Section 13.2)
                if pc.digest_over(record) != pc.digest_over(child.record):
                    raise Refuse("object-conflict", "a different Outcome Record is already held for this child", "10.2")
                return 200, self._status(p)
            if p.state in TERMINAL:
                raise Refuse("wrong-state", "the parent has reached a terminal state; child records are no longer accepted (Section 10.2)", "10.2", state=p.state)
            self.schemas.check(record, "outcome.schema.json")
            if record["vtc_hash"] != child.digest:
                raise Refuse("child-outcome-invalid",
                             "the record's vtc_hash is not the registered child's digest",
                             expected=child.digest, received=record["vtc_hash"])
            self._evaluable(record)
            ok, why = pc.verify_object(record, self.resolver, MEDIA_OUTCOME, [child.facilitator])
            if not ok:
                raise Refuse("child-outcome-invalid", why)
            # Section 10.2: what the record copies from the registered child contract,
            # outcome.verdict against the record's own trace, and work_hash present
            # exactly when that trace has a delivered entry. Whether work_hash is the
            # Delivery's needs the child's Delivery, which is not held here.
            problems = pc.outcome_errors(record, child.vtc)
            if problems:
                raise Refuse("child-outcome-invalid",
                             "the record does not match the registered child: " + "; ".join(problems))
            child.record = record
            child.unresolved = False
            self._record(p, "child-final", object=pc.digest_over(record), child=child.digest)
            self._tick(p)
            return 200, self._status(p)

    # -- Section 8 -----------------------------------------------------------
    def capability_document(self) -> dict:
        doc = {
            "pact": "0.3",
            "type": "FacilitatorCapabilities",
            "facilitator": self.identity,
            "issued_at": iso(float(math.floor(self.now()))),   # signed now, not at the last operation
            "settlement_bindings": self.settlement_bindings,
            "flows": self.flows,
            "verification_profiles": self.verification_profiles,
            "terms_profiles": [{"id": pid, "profile_hash": ph} for (pid, ph) in self.profiles],
            "max_contract_value": self.max_contract_value,
            "retrieval": "open",   # CHOICES C2
            "endpoints": {
                "contract": self.base_url + "/pact/v2/contracts",
                "delivery": self.base_url + "/pact/v2/deliveries",
                "verdict": self.base_url + "/pact/v2/verdicts",
                "challenge": self.base_url + "/pact/v2/challenges",
                "outcome": self.base_url + "/pact/v2/outcomes",
            },
        }
        doc["signature"] = pc.sign(doc, self.key, MEDIA_FACILITATOR)
        # Never schema-invalid: the request had no body (audit A9).
        self._self_check(doc, "facilitator.schema.json")
        return doc


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

# The operations of Section 13 as this implementation mounts them (the endpoints of
# its capability document), by method. A path matching neither method's routes has
# no resource here (404); a path matching only the other method's is 405.
ROUTE_CAPABILITY = r"/\.well-known/pact-facilitator"
ROUTE_RETRIEVE = r"/pact/v2/(contracts|outcomes)/([^/]+)"
ROUTE_CHILDREN = r"/pact/v2/contracts/([^/]+)/children(?:/([^/]+))?"
ROUTE_SUBMIT = r"/pact/v2/(contracts|deliveries|verdicts|challenges)"
ROUTES = {"GET": (ROUTE_CAPABILITY, ROUTE_RETRIEVE), "POST": (ROUTE_CHILDREN, ROUTE_SUBMIT)}

# RFC 9110 Section 15 (431: RFC 6585) phrases: the title RFC 9457 Section 4.2.1 asks an
# about:blank problem to carry, and its status line's phrase, where Python's says "Request-URI Too Long".
BLANK_TITLES = {400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed",
                411: "Length Required", 414: "URI Too Long",
                431: "Request Header Fields Too Large", 501: "Not Implemented",
                505: "HTTP Version Not Supported"}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "pact-reference-facilitator/0.2"
    _close = False   # set when the connection must not carry another request
    _raw = b""       # the body the request declared, read before routing

    @property
    def fac(self) -> Facilitator:
        return self.server.facilitator  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        if getattr(self.server, "verbose", False):  # type: ignore[attr-defined]
            super().log_message(fmt, *args)

    def _send(self, status: int, body: dict, content_type: str,
              headers: tuple[tuple[str, str], ...] = (), phrase: str | None = None) -> None:
        raw = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status, phrase)
        self.send_header("Content-Type", content_type)
        if self.command != "HEAD":
            # RFC 9110 Section 8.6: a response to HEAD carries Content-Length only
            # if it equals what a GET would carry. HEAD is not implemented here,
            # so its 501 carries none.
            self.send_header("Content-Length", str(len(raw)))
        for name, value in headers:
            self.send_header(name, value)
        if self._close:
            self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)
        self.fac.message_count += 1

    def _blank(self, status: int, detail: str | None,
               headers: tuple[tuple[str, str], ...] = ()) -> None:
        title = BLANK_TITLES.get(status) or HTTPStatus(status).phrase
        body: dict[str, Any] = {"type": "about:blank", "title": title, "status": status}
        if detail:
            body["detail"] = detail
        self._send(status, body, "application/problem+json", headers, phrase=title)

    def send_error(self, code: int, message: str | None = None,
                   explain: str | None = None) -> None:
        """http.server's own refusals, made before any do_ method runs: a method this
        server does not implement (501; every method but GET and POST), a malformed
        request line (400), an HTTP version it does not speak (505), an oversize
        target (414) or header block (431). Section 13.3 asks for problem details for
        every failure, so these are about:blank too, never http.server's HTML page,
        and the connection is closed, as http.server closes it. http.server refuses
        a version it cannot read, a version of 2.0 or more, and a request line of the
        wrong length before it records the request's version, and would answer in
        HTTP/0.9 form: a body with no status line and no headers. Only a two-word
        line is an HTTP/0.9 request, so any other is answered in this server's
        version (RFC 9110 Section 2.5), and the status, the media type and the
        Connection header reach the client."""
        self.log_error("code %d, message %s", code, message)
        if self.request_version == "HTTP/0.9" and len(getattr(self, "requestline", "").split()) != 2:
            self.request_version = self.protocol_version
        self._close = True
        self._blank(int(code), message)

    def finish(self) -> None:
        """A response that closes the connection can leave request bytes unread: a
        body refused before it was read, or the rest of a request http.server refused
        on its request line. A socket closed with unread data resets the connection,
        and a client still sending its body loses the answer (RFC 9112 Section 9.6).
        So the write side is shut first, and what still arrives is read and
        discarded, for at most LINGER_SECONDS and LINGER_BYTES, before socketserver
        closes the socket."""
        super().finish()
        if not self._close:
            return
        try:
            self.connection.shutdown(socket.SHUT_WR)
            deadline = time.monotonic() + LINGER_SECONDS
            left = LINGER_BYTES
            while left > 0 and (wait := deadline - time.monotonic()) > 0:
                self.connection.settimeout(wait)
                chunk = self.connection.recv(min(left, 1 << 16))
                if not chunk:
                    break
                left -= len(chunk)
        except OSError:   # a reset, or a client still sending at the deadline
            pass

    def _problem(self, exc: Exception) -> None:
        if isinstance(exc, terms.ProfileRefusal):
            body = {
                "type": terms.PROBLEM_BASE + exc.kind,
                "title": exc.kind.replace("-", " "),
                "status": 422,
                "detail": exc.detail,
                "profile": terms.ID,
                "profile_section": exc.section,
            }
            body.update(exc.extra)
            self._send(422, body, "application/problem+json")
            return
        assert isinstance(exc, Refuse)
        status = PROBLEMS.get(exc.kind, (400, ("13.3",)))[0]
        body = {
            "type": PROBLEM_BASE + exc.kind,
            "title": exc.kind.replace("-", " "),
            "status": status,
            "detail": exc.detail,
            "section": exc.section,
        }
        body.update(exc.extra)
        self._send(status, body, "application/problem+json")

    def _guard(self, fn) -> None:
        # Until the declared body has been read the connection cannot carry another
        # request, so any failure before then, one not foreseen included, closes it.
        self._close = True
        try:
            self._read_body()
            self._close = False
            fn()
        except NoRule as exc:
            self._blank(exc.status, exc.detail, exc.headers)
        except (Refuse, terms.ProfileRefusal) as exc:
            self._problem(exc)
        except pc.NotEvaluable as exc:   # fail closed on any path _evaluable did not cover
            self._problem(Refuse("identifier-not-evaluable", f"not evaluable under Section 9.1: {exc}"))
        except Exception as exc:  # pragma: no cover
            self._problem(Refuse("internal-error",
                                 f"the Facilitator failed internally ({type(exc).__name__})"))

    def _read_body(self) -> None:
        """Read exactly the body the request declares, before any routing, so that no
        byte a request carried is ever taken for the next request on a kept-alive
        connection. A body whose length cannot be determined (RFC 9112 Section 6.3)
        or that this server will not read is refused before a byte of it is read,
        and the connection is closed."""
        self._raw = b""
        coding = ",".join(self.headers.get_all("Transfer-Encoding") or ())
        if coding.strip():
            self._close = True
            if coding.rsplit(",", 1)[-1].strip().lower() != "chunked":
                raise NoRule(400, "the final transfer coding is not chunked, so the body length "
                                  "cannot be determined (RFC 9112 Section 6.3)")
            raise NoRule(411, "a request body is read here only when Content-Length frames it")
        values = {v.strip() for f in self.headers.get_all("Content-Length") or () for v in f.split(",")}
        if len(values) > 1 or not all(re.fullmatch(r"[0-9]+", v) for v in values):
            self._close = True
            raise NoRule(400, "Content-Length is not one decimal length (RFC 9112 Section 6.3)")
        # RFC 9110 Section 8.6: a recipient anticipates large decimal numerals and
        # prevents integer conversion errors. int() refuses more than 4300 digits, so
        # a numeral longer than MAX_BODY's, leading zeros aside, is taken as over the
        # limit without being converted.
        digits = (values.pop().lstrip("0") or "0") if values else "0"
        length = int(digits) if len(digits) <= len(str(MAX_BODY)) else MAX_BODY + 1
        if length > MAX_BODY:
            self._close = True
            raise Refuse("payload-too-large", f"body exceeds {MAX_BODY} bytes")
        self._raw = self.rfile.read(length)

    def _body(self) -> dict:
        try:
            obj = json.loads(self._raw or b"{}")
        except ValueError:
            raise Refuse("schema-invalid", "body is not JSON")
        if not isinstance(obj, dict):
            raise Refuse("schema-invalid", "body is not a JSON object")
        return obj

    def _no_route(self) -> NoRule:
        """A path with no resource is 404; a resource that takes only the other method
        is 405 with Allow (RFC 9110 Sections 9.1 and 15.5.6). Neither names a contract
        the Facilitator does not hold, so neither is unknown-contract."""
        other = "POST" if self.command == "GET" else "GET"
        if any(re.fullmatch(p, self.path) for p in ROUTES[other]):
            return NoRule(405, f"{self.path} takes {other} only", headers=(("Allow", other),))
        return NoRule(404, f"no resource at {self.path}")

    def do_GET(self) -> None:
        def run() -> None:
            if re.fullmatch(ROUTE_CAPABILITY, self.path):
                self._send(200, self.fac.capability_document(), MEDIA_FACILITATOR)
                return
            m = re.fullmatch(ROUTE_RETRIEVE, self.path)
            if not m:
                raise self._no_route()
            kind, vid = m.groups()
            vid = urllib.parse.unquote(vid)   # the inverse of contract_path's encoding
            if kind == "contracts":
                status, body = self.fac.get_status(vid)
                self._send(status, body, MEDIA_STATUS)
            else:
                status, body = self.fac.get_outcome(vid)
                self._send(status, body, MEDIA_OUTCOME)
        self._guard(run)

    def do_POST(self) -> None:
        def run() -> None:
            m = re.fullmatch(ROUTE_CHILDREN, self.path)
            if m:
                parent_id, child_hash = m.groups()
                parent_id = urllib.parse.unquote(parent_id)
                if child_hash is None:
                    status, body = self.fac.register_child(parent_id, self._body())
                else:
                    status, body = self.fac.supply_child_outcome(parent_id, child_hash, self._body())
                self._send(status, body, MEDIA_STATUS)
                return
            m = re.fullmatch(ROUTE_SUBMIT, self.path)
            if not m:
                raise self._no_route()
            op = {"contracts": "propose", "deliveries": "submit_delivery",
                  "verdicts": "record_verdict", "challenges": "open_challenge"}[m.group(1)]
            status, body = getattr(self.fac, op)(self._body())
            # Section 13: the contract is the resource the Location header
            # names. A Verdict's 201 names no resource of its own, so it
            # carries none; nor does a child registration's (the text names
            # no resource for it); a 200 replay creates nothing (13.2).
            loc = (("Location", contract_path(body["vtc_id"])),) if op == "propose" and status == 201 else ()
            self._send(status, body, MEDIA_STATUS, loc)
        self._guard(run)


def serve(facilitator: Facilitator, port: int = 8402,
          verbose: bool = False) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    httpd.facilitator = facilitator  # type: ignore[attr-defined]
    httpd.verbose = verbose  # type: ignore[attr-defined]
    return httpd


def build(identity: str = "did:web:settle.example", now: Any = time.time,
          base_url: str = "http://127.0.0.1:8402") -> tuple[Facilitator, pc.KeyResolver]:
    resolver = pc.KeyResolver()
    key = resolver.register(pc.Key.generate(identity + "#key-1"))
    return Facilitator(identity, key, resolver, now=now, base_url=base_url), resolver


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8402)
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--problems", action="store_true",
                    help="print every problem type this document defines, with its "
                         "HTTP status and every section it cites, then exit")
    ap.add_argument("--rules", action="store_true",
                    help="print the rules this implementation enforces, and its choices, and exit")
    args = ap.parse_args()
    if args.problems:
        for kind, (status, sections) in sorted(PROBLEMS.items()):
            print(f"{PROBLEM_BASE}{kind}\t{status}\t{', '.join(sections)}")
        return
    if args.rules:
        print(RULES.strip())
        print()
        print(CHOICES.strip())
        return
    fac, _ = build(base_url=f"http://127.0.0.1:{args.port}")
    httpd = serve(fac, args.port, args.verbose)
    print(f"reference Facilitator {fac.identity} on http://127.0.0.1:{args.port}")
    print(f"capability document at http://127.0.0.1:{args.port}/.well-known/pact-facilitator")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
