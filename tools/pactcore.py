"""Shared PACT primitives: canonicalization, digests, JWS, and the assurance constraint.

This module is the part of the reference implementation that both the
Facilitator (facilitator.py) and the party agents (agents.py) need. It is
deliberately separate from tools/validate.py, which stays a self-contained
conformance checker over the committed examples and must keep passing on a
machine with nothing but jsonschema installed.

Two things here are worth reading before trusting a number produced with it.

The canonicalizer is the same restricted RFC 8785 implementation validate.py
uses. It is correct for the value types PACT objects carry and is not a
conforming general JCS implementation; what it does get right, and what the
Section 13.3 vectors pin, is the UTF-16 code unit key order of RFC 8785
section 3.2.3, which json.dumps(sort_keys=True) does not implement.

The signatures are real. Section 13.1 fixes the JWS Signing Input as
ASCII(BASE64URL(UTF8(protected)) || "." || BASE64URL(JCS(object))) over the
object with its signing member removed, and Section 6 computes vtc_hash over
the contract *including* its signatures member. Those two facts are why a
contract digest proves who agreed rather than merely what was written, and
why the signing input and the digest are computed over different bytes. Both
are implemented here and exercised by the measurement harness.

The committed examples under examples/ keep their placeholder signature
values on purpose. The published Internet-Draft prints their digests in
Section 14 and cannot be corrected, so re-signing them would silently
desynchronise the repository from the document. Everything in this module
mints fresh keys and fresh contracts at run time instead.
"""

from __future__ import annotations

import base64
import hashlib
import json
import unicodedata
from decimal import Decimal
from dataclasses import dataclass, field
from typing import Any, Callable

# Ed25519 and P-256 come from `cryptography`. It is an optional dependency:
# validate.py's sixty-six checks do not need it, and this module is only
# imported by the Facilitator and the agents.
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
    )
    from cryptography.exceptions import InvalidSignature

    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False

    class InvalidSignature(Exception):
        pass


# --------------------------------------------------------------------------
# RFC 8785 canonicalization and digests
# --------------------------------------------------------------------------

def _utf16_key_order(obj: Any) -> Any:
    """Reorder object keys by UTF-16 code unit, per RFC 8785 section 3.2.3.

    Comparing UTF-16 big-endian encodings bytewise is equivalent to comparing
    sequences of UTF-16 code units. json.dumps preserves insertion order, so
    building the dict in the right order is enough; sort_keys must NOT also
    be set, since that re-sorts by code point and the two orders diverge
    above the Basic Multilingual Plane.
    """
    if isinstance(obj, dict):
        return {k: _utf16_key_order(obj[k])
                for k in sorted(obj, key=lambda s: s.encode("utf-16-be"))}
    if isinstance(obj, list):
        return [_utf16_key_order(v) for v in obj]
    return obj


def jcs(obj: Any) -> bytes:
    """Restricted RFC 8785 canonical serialization. See the module docstring."""
    return json.dumps(_utf16_key_order(obj), separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def h(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def digest_over(obj: Any) -> str:
    """Digest over the whole object as it stands, signatures included.

    This is the Section 6 construction. Use it for vtc_hash, and never for a
    signing input.
    """
    return h(jcs(obj))


# PACT objects carry their signatures two ways, and both are in the schemas.
# The contract and the Work Attestation take an array, because more than one
# party signs them. Delivery, Verdict and Challenge take a single object,
# because exactly one party does.
SIGNING_MEMBERS = ("signatures", "signature")

# The Facilitator adds `state` to a response body. Section 12 says it is not
# part of the signed object and MUST NOT be included when the object is
# canonicalized or hashed, so it is stripped everywhere alongside signatures.
UNSIGNED_MEMBERS = SIGNING_MEMBERS + ("state",)


def signable(obj: dict) -> dict:
    return {k: v for k, v in obj.items() if k not in UNSIGNED_MEMBERS}


def hashable(obj: dict) -> dict:
    """The object as it is committed to: signatures kept, transport state dropped."""
    return {k: v for k, v in obj.items() if k != "state"}


def signature_entries(obj: dict) -> list[dict]:
    """Every signature entry on an object, whichever member carries them."""
    if "signatures" in obj:
        return list(obj["signatures"])
    if "signature" in obj:
        return [obj["signature"]]
    return []


def attach(obj: dict, entry: dict, array: bool) -> dict:
    obj["signatures" if array else "signature"] = [entry] if array else entry
    return obj


# --------------------------------------------------------------------------
# Identifier normalization, Section 9.1
# --------------------------------------------------------------------------

def norm(identifier: str) -> str:
    """Normalize a party identifier per Section 9.1, exactly as written.

    "strip leading and trailing whitespace; lower-case the scheme and, for
    did:web and https identifiers, the host; remove any fragment (a "#" and
    everything after it) and any trailing "/" or ".". Percent-encoding MUST NOT
    be decoded, since an open-ended decoder is its own attack surface."

    Note what this does NOT do. It does not case-fold the whole identifier: the
    path of a did:web is case sensitive, and folding it would merge two
    distinct parties. An earlier version of this function folded everything and
    never stripped the fragment, which is both too permissive and too strict in
    different places.
    """
    s = unicodedata.normalize("NFC", identifier).strip()
    s = s.split("#", 1)[0]

    if ":" in s:
        scheme, rest = s.split(":", 1)
        scheme = scheme.lower()
        if scheme == "did":
            parts = rest.split(":")
            if parts:
                parts[0] = parts[0].lower()               # the DID method
                if parts[0] == "web" and len(parts) > 1:
                    parts[1] = parts[1].lower()           # the host
            rest = ":".join(parts)
        elif scheme in ("http", "https") and rest.startswith("//"):
            host, sep, tail = rest[2:].partition("/")
            rest = "//" + host.lower() + sep + tail
        s = scheme + ":" + rest

    while s.endswith(("/", ".")):
        s = s[:-1]
    return s


def same_party(a: str, b: str) -> bool:
    return norm(a) == norm(b)


# --------------------------------------------------------------------------
# The assurance constraint, Section 7.2
# --------------------------------------------------------------------------

def required_bond(price: float, q: float, released: float = 0.0) -> float:
    """B >= P(1-q)/q + E.

    E, the amount already paid out before a Verdict is recorded, is the only
    term this specification contributes; the rest is the classical deterrence
    bound (Polinsky and Shavell; Belenkiy et al. Theorem 1; Mamageishvili and
    Felten for rollup validators). Optimistic release both pays a defecting
    Seller and puts that payment beyond recovery, so the required Bond rises
    with it one for one.
    """
    if q <= 0:
        raise ValueError("q must be greater than zero")
    return price * (1.0 - q) / q + released


def assurance_holds(price: str | float, bond: str | float, q_min: str | float,
                    released: str | float = "0") -> bool:
    """B >= P(1-q)/q + E, evaluated exactly.

    Multiplied through by q (which is positive) this is B*q >= P*(1-q) + E*q,
    which needs no division and no rounding. An earlier version rounded both
    sides to the nearest cent first, and a bond one hundredth of a cent short
    of the bound passed.
    """
    P, B, q, E = (Decimal(str(x)) for x in (price, bond, q_min, released))
    if q <= 0:
        raise ValueError("q must be greater than zero")
    return B * q >= P * (1 - q) + E * q


# --------------------------------------------------------------------------
# JWS General JSON Serialization with a detached payload, Section 13.1
# --------------------------------------------------------------------------

ALLOWED_ALGS = ("EdDSA", "ES256", "ES384")


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def signing_input(protected_b64: str, obj: dict) -> bytes:
    """ASCII(BASE64URL(UTF8(protected)) || "." || BASE64URL(JCS(object))).

    Exactly RFC 7515 section 5.1, over the object with its signing member
    removed. The payload is never transmitted; a verifier rebuilds it from
    the object it holds. The protected header is used AS TRANSMITTED: an
    earlier version re-serialized the parsed header, which meant a
    conformant JWS whose header bytes differed from this module's own
    serialization (whitespace, key order) was rejected, and the commitment
    depended on a re-serialization the signer never saw.
    """
    return (protected_b64 + "." + b64u(jcs(signable(obj)))).encode("ascii")


@dataclass
class Key:
    """A party key. `kid` is the URI a verifier resolves, per Section 13.1.1."""
    kid: str
    alg: str
    private: Any = None
    public: Any = None

    @classmethod
    def generate(cls, kid: str, alg: str = "EdDSA") -> "Key":
        if not HAVE_CRYPTO:
            raise RuntimeError(
                "the `cryptography` package is required to mint keys; "
                "install it with `pip install cryptography`")
        if alg == "EdDSA":
            sk = Ed25519PrivateKey.generate()
        elif alg == "ES256":
            sk = ec.generate_private_key(ec.SECP256R1())
        elif alg == "ES384":
            sk = ec.generate_private_key(ec.SECP384R1())
        else:
            raise ValueError(f"unsupported alg {alg}")
        return cls(kid=kid, alg=alg, private=sk, public=sk.public_key())

    def sign_bytes(self, data: bytes) -> bytes:
        if self.alg == "EdDSA":
            return self.private.sign(data)
        curve_hash = hashes.SHA256() if self.alg == "ES256" else hashes.SHA384()
        der = self.private.sign(data, ec.ECDSA(curve_hash))
        r, s = decode_dss_signature(der)
        size = 32 if self.alg == "ES256" else 48
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")

    def verify_bytes(self, sig: bytes, data: bytes) -> None:
        if self.alg == "EdDSA":
            self.public.verify(sig, data)
            return
        size = 32 if self.alg == "ES256" else 48
        if len(sig) != size * 2:
            raise InvalidSignature("bad JWS ECDSA signature length")
        r = int.from_bytes(sig[:size], "big")
        s = int.from_bytes(sig[size:], "big")
        curve_hash = hashes.SHA256() if self.alg == "ES256" else hashes.SHA384()
        self.public.verify(encode_dss_signature(r, s), data, ec.ECDSA(curve_hash))


class KeyResolver:
    """Maps a `kid` to a public key.

    Section 13.1.1 resolves a kid as a DID URL (DID Core, did:web) or as an
    https URI naming a JWK Set (RFC 7517). Both are network lookups with
    caching and revocation semantics that a reference implementation should
    not fake. This resolver is an in-process registry with the same interface,
    so the Facilitator's verification path is real and only the transport of
    the public key is stubbed. What that costs a measurement is one network
    round trip per unseen kid, which is stated wherever numbers are reported.
    """

    def __init__(self) -> None:
        self._keys: dict[str, Key] = {}

    def register(self, key: Key) -> Key:
        self._keys[key.kid] = key
        return key

    def resolve(self, kid: str) -> Key | None:
        return self._keys.get(kid)


def public_bytes(key: "Key") -> bytes:
    """Raw public key bytes, for the Section 16.11 record of what was resolved."""
    from cryptography.hazmat.primitives import serialization
    if key.alg == "EdDSA":
        return key.public.public_bytes(serialization.Encoding.Raw,
                                       serialization.PublicFormat.Raw)
    return key.public.public_bytes(serialization.Encoding.X962,
                                   serialization.PublicFormat.UncompressedPoint)


def sign(obj: dict, key: Key, typ: str) -> dict:
    """Return one entry for the object's `signatures` array.

    `typ` is the full media type, per RFC 8725 section 3.11: a bare "JWT" or
    an omitted typ lets an attacker present a token minted for one purpose as
    one minted for another.
    """
    protected_b64 = b64u(jcs({"alg": key.alg, "kid": key.kid, "typ": typ}))
    sig = key.sign_bytes(signing_input(protected_b64, obj))
    return {"protected": protected_b64, "signature": b64u(sig)}


def verify_entry(obj: dict, entry: dict, resolver: KeyResolver,
                 expect_typ: str | None = None) -> tuple[bool, str]:
    """Verify one signature entry. Returns (ok, reason)."""
    try:
        protected = json.loads(b64u_decode(entry["protected"]))
    except Exception:
        return False, "protected header is not valid base64url JSON"

    for member in ("alg", "kid", "typ"):
        if member not in protected:
            return False, f"protected header is missing {member}"
    if "kid" in entry:
        # Section 13.1: a kid outside the signed header is attacker-controlled.
        return False, "kid carried as a sibling of the protected header"
    # RFC 8725 section 3.11 and conformance vector V-05: typ carries the full
    # media type so a signature minted over one object cannot be presented as
    # one minted over another. This was previously accepted as an argument and
    # never compared, which made V-05 pass in validate.py and fail over the wire.
    if expect_typ is not None and protected.get("typ") != expect_typ:
        return False, (f"typ {protected.get('typ')!r} does not match the expected "
                       f"{expect_typ!r}")

    alg = protected["alg"]
    if alg not in ALLOWED_ALGS:
        # Rejecting `none` and everything off the allowlist is the whole point:
        # absent one, the attacker selects the algorithm. The reason string
        # starts with "algorithm" so a caller can map it to Table 9's
        # algorithm-not-permitted rather than a generic signature failure.
        return False, f"algorithm {alg!r} is not permitted"

    key = resolver.resolve(protected["kid"])
    if key is None:
        return False, f"cannot resolve kid {protected['kid']!r}"
    if key.alg != alg:
        return False, f"alg {alg!r} does not match the resolved key"

    try:
        key.verify_bytes(b64u_decode(entry["signature"]),
                         signing_input(entry["protected"], obj))
    except Exception:
        return False, "signature does not verify"
    return True, "ok"


def signer_kids(obj: dict) -> list[str]:
    out = []
    for entry in signature_entries(obj):
        try:
            out.append(json.loads(b64u_decode(entry["protected"]))["kid"])
        except Exception:
            continue
    return out


def kid_covers(kid: str, party: str) -> bool:
    """True when `kid` is a key identifier belonging to `party`.

    Section 9.1 normalization strips the fragment, so a kid of
    did:web:seller.example#key-1 normalizes to the party identifier itself and
    this is an equality test. It used to be a prefix test, which is a hole:
    did:web:acme.example.evil starts with did:web:acme.example and would have
    signed as its neighbour. Line 1965 of the draft requires equality of the
    normalized identifier, not containment.
    """
    return norm(kid) == norm(party)


def verify_object(obj: dict, resolver: KeyResolver, typ: str,
                  required_parties: list[str]) -> tuple[bool, str]:
    """Verify every signature and check that each required party signed once."""
    entries = signature_entries(obj)
    if not entries:
        return False, "object carries no signatures"

    for entry in entries:
        ok, why = verify_entry(obj, entry, resolver, expect_typ=typ)
        if not ok:
            return False, why

    kids = signer_kids(obj)
    for party in required_parties:
        covering = [k for k in kids if kid_covers(k, party)]
        if not covering:
            return False, f"no signature from {party}"
        if len(covering) > 1:
            return False, f"more than one signature from {party}"
    return True, "ok"


# --------------------------------------------------------------------------
# Merkle tree, RFC 9162 section 2.1.1
# --------------------------------------------------------------------------

def mth(items: list[bytes]) -> bytes:
    """Merkle Tree Hash over `items`, exactly as RFC 9162 defines it.

    Leaves are hashed with a 0x00 prefix and internal nodes with 0x01, and an
    n-item tree splits at k, the largest power of two strictly less than n.
    That split is not the same as promoting an odd node, which is what the
    -00 said and what an earlier revision of this repository implemented.
    """
    if not items:
        return hashlib.sha256(b"").digest()
    if len(items) == 1:
        return hashlib.sha256(b"\x00" + items[0]).digest()
    k = 1
    while k * 2 < len(items):
        k *= 2
    return hashlib.sha256(b"\x01" + mth(items[:k]) + mth(items[k:])).digest()


# --------------------------------------------------------------------------
# Money. Contracts carry decimal strings; arithmetic happens in cents.
# --------------------------------------------------------------------------

def cents(amount: str | float) -> int:
    """Whole cents. Amounts with more than two decimal places are refused at
    propose by the Facilitator (it settles in cents); this never rounds."""
    d = Decimal(str(amount))
    scaled = d * 100
    if scaled != scaled.to_integral_value():
        raise ValueError(f"amount {amount!r} is not a whole number of cents")
    return int(scaled)


def money(c: int) -> str:
    return f"{c / 100:.2f}"


@dataclass
class Pools:
    """The three pools of Section 7.1, in cents.

    Keeping the Verification Fund separate from the Bond is not tidiness. Under
    the -00 a Challenger was reimbursed from the slashed Bond, so reimbursement
    was capped by the Bond, and for any re-execution profile the cost of
    producing a fraud proof approximates the cost of the work itself. That MUST
    was unsatisfiable in the ordinary case.
    """
    escrow: int = 0
    bond: int = 0
    fund: int = 0
    bond_initial: int = 0
    bond_returned: int = 0
    fund_returned: int = 0
    cap: int = 0       # liability.cap: the most the Facilitator may move from the Seller
    released: int = 0  # E in the constraint of Section 7.2
    paid_to_buyer: int = 0
    restituted: int = 0
    paid_to_seller: int = 0
    paid_to_challenger: int = 0
    remainder: int = 0
    ledger: list[str] = field(default_factory=list)

    def note(self, line: str) -> None:
        self.ledger.append(line)
