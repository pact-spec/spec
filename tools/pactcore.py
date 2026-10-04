"""Shared PACT primitives: canonicalization, digests, JWS, and the assurance constraint.

This module is the part of the reference implementation that the Facilitator
(facilitator.py), the party agents (agents.py), the terms profile (profile.py)
and the validator (validate.py) all import, so the validator checks the
committed examples with the same canonicalizer, digests and normalization the
Facilitator runs. What it pins, it pins with vectors, not with a second copy.
Nothing here needs more than the standard library, except signing and
verification, which need cryptography; validate.py still runs without it and
prints [skip] for those checks.

Two things here are worth reading before trusting a number produced with it.

The canonicalizer is a restricted RFC 8785 implementation. It is correct for
the value types PACT objects carry and is not a conforming general JCS
implementation; what it does get right, and what the Section 14.3 vectors
pin, is the UTF-16 code unit key order of RFC 8785 section 3.2.3, which
json.dumps(sort_keys=True) does not implement.

The signatures are real. Section 14.1 fixes the JWS Signing Input as
ASCII(BASE64URL(UTF8(protected)) || "." || BASE64URL(JCS(object))) over the
object with its signing member removed, and Section 2 computes vtc_hash over
the contract *including* its signatures member. Those two facts are why a
contract digest proves who agreed rather than merely what was written, and
why the signing input and the digest are computed over different bytes. Both
are implemented here and exercised by the measurement harness.

The committed examples under examples/ carry real Ed25519 signatures minted by
mint_examples.py from public seeds, so anyone can reproduce their bytes and the
digests the -02 prints; the -01 examples kept placeholder signature values, and
the -01 text printed digests over them. The measurement harness still mints fresh
keys and contracts at run time.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import string
import unicodedata
from decimal import Decimal
from fractions import Fraction
from dataclasses import dataclass, field
from typing import Any, Callable

# Ed25519 and P-256 come from `cryptography`. It is an optional dependency:
# validate.py's checks do not need it, and this module is only
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


def _es6_number(f: float) -> str:
    """Serialize a float the way ECMAScript Number::toString does, which is
    what RFC 8785 section 3.2.2.3 requires. Python's own repr gives the same
    shortest round-trip digits but places them differently: 1.0 becomes
    "1.0", 1e20 becomes "1e+20" and 1e-7 becomes "1e-07", and each of those
    is a different byte string, so a different digest, from what a conformant
    canonicalizer produces. An earlier revision of this file used repr and
    every digest it printed over an object with a float was wrong."""
    if f != f or f in (float("inf"), float("-inf")):
        raise ValueError("RFC 8785 does not serialize NaN or Infinity")
    if f == 0:
        return "0"
    d = Decimal(repr(f))
    sign = "-" if d < 0 else ""
    t = abs(d).as_tuple()
    digits = "".join(map(str, t.digits))
    n = t.exponent + len(digits)          # value = 0.digits x 10^n
    digits = digits.rstrip("0")
    k = len(digits)
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + s


def _emit(obj: Any) -> str:
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, float):
        return _es6_number(obj)
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_emit(v) for v in obj) + "]"
    if isinstance(obj, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _emit(obj[k])
                              for k in sorted(obj, key=lambda s: s.encode("utf-16-be"))) + "}"
    raise TypeError(f"not JSON: {type(obj).__name__}")


def jcs(obj: Any) -> bytes:
    """RFC 8785 canonical serialization: keys in UTF-16 code unit order,
    numbers as ECMAScript prints them, strings escaped as JSON requires and
    nothing else, no whitespace. See the module docstring."""
    return _emit(obj).encode("utf-8")


def h(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def digest_over(obj: Any) -> str:
    """Digest over the whole object as it stands, signatures included.

    This is the Section 2 construction. Use it for vtc_hash, and never for a
    signing input.
    """
    return h(jcs(obj))


# PACT objects carry their signatures two ways, and both are in the schemas.
# The contract and the Outcome Record take an array, because more than one
# party may sign them. Delivery, Verdict, Challenge, Status and the capability
# document take a single object, because exactly one party does.
SIGNING_MEMBERS = ("signatures", "signature")


def signable(obj: dict) -> dict:
    """The signing input's object: everything but the signing member."""
    return {k: v for k, v in obj.items() if k not in SIGNING_MEMBERS}


def hashable(obj: dict) -> dict:
    """The object as it is committed to: everything, signatures included.

    -02 Section 2 defines one digest construction over the whole object. The
    -01 response bodies carried an unsigned `state` member that had to be
    stripped here; the -02 Status object replaced it and nothing is stripped.
    """
    return dict(obj)


def manifest_digest(dirpath) -> str:
    """The bundle commitment of Section 5.1: SHA-256(JCS(M)) where M maps each
    file's path, relative to the bundle root with "/" separators, to the
    SHA-256 of its bytes, over every file in the bundle."""
    import pathlib
    root = pathlib.Path(dirpath)
    manifest = {p.relative_to(root).as_posix(): h(p.read_bytes())
                for p in sorted(root.rglob("*"))
                if p.is_file() and not any(part.startswith(".") for part in p.relative_to(root).parts)}
    return h(jcs(manifest))


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

# RFC 3986 Section 2.3. Built from the string module, not written out: a
# literal run of hex digits reads as a digest prefix to digest-scan.py.
UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")
HEXDIG = frozenset(string.hexdigits)
SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*\Z")
# DID Core 1.0 Section 3.1: "did:" method-name ":" method-specific-id, with
# method-char = %x61-7A / DIGIT and idchar = ALPHA / DIGIT / "." / "-" / "_" /
# pct-encoded; every "%" was already checked to begin a well-formed escape.
DID = re.compile(r"did:[a-z0-9]+:(?:[A-Za-z0-9._%-]*:)*[A-Za-z0-9._%-]+\Z")
PORT_DID_WEB = re.compile(r"%3A", re.I)
# RFC 3986 Appendix A, for the https form: path-abempty [ "?" query ] after the
# authority (the fragment is gone by then) and a reg-name host. An IP-literal
# host is refused by step 6, so no rule for one is needed here.
_UNRES = r"A-Za-z0-9\-._~"
_SUBDELIMS = r"!$&'()*+,;="
_PCHAR = rf"(?:[{_UNRES}{_SUBDELIMS}:@]|%[0-9A-Fa-f]{{2}})"
HTTPS_TAIL = re.compile(rf"(?:/{_PCHAR}*)*(?:\?(?:{_PCHAR}|[/?])*)?\Z")
REG_NAME = re.compile(rf"[{_UNRES}{_SUBDELIMS}]*\Z")


class NotEvaluable(ValueError):
    """Section 9.1: an identifier that does not parse is never compared."""


def _upper_escapes(x: str) -> str:
    return re.sub(r"%[0-9A-Fa-f]{2}", lambda e: e.group(0).upper(), x)


def _port_ok(port: str) -> bool:
    """Digits with no leading zero, or empty (step 10 removes an empty port)."""
    return port == "" or (port.isdigit() and port[0] != "0")


def _numeric_host(host: str) -> bool:
    """Step 6: the last label of the host that is not empty begins with a
    digit. The rule is the draft's own choice and wider than an IPv4
    reading: it refuses every host written as an IPv4 address in the
    decimal, octal or hexadecimal forms some URL parsers accept
    ("192.0.2.1", "0300.0.2.1", "0xc0.0.2.1", one address spelled three
    ways), and some host names besides ("example.1x")."""
    labels = [x for x in host.split(".") if x]
    return bool(labels) and labels[-1][0].isdigit()


def norm(identifier: str) -> str:
    """Normalize a party identifier or a kid by the ten steps of Section 9.1,
    in the order the text gives them, and return the normalized form.

    Raises NotEvaluable, and never returns, for an identifier that does not
    parse: a character outside %x21-7E, an escape of an unreserved character
    or a stray "%", a scheme other than did and https, a did that fails the
    DID Core syntax (did:WEB, did:web:), an https identifier that is not an
    RFC 3986 URI with an authority, userinfo, a host with an escape, an
    IP-literal host or one whose last non-empty label begins with a digit, a
    port that is not digits or begins with "0", a "." or ".." segment, "//"
    in an https path or "::" in a did:web identifier, an empty query, a host
    that is empty. Nothing is decoded and no path is rewritten. Two
    identifiers are equivalent when norm() returns the same string for both;
    nothing here says who controls either.
    """
    s = identifier
    # 1. Printable ASCII only, %x21 to %x7E, the fragment included. Nothing is
    #    stripped, so no whitespace can survive into a comparison (audit A1),
    #    and a U-label host never parses (row 10).
    if not isinstance(s, str) or not s or any(not ("!" <= ch <= "~") for ch in s):
        raise NotEvaluable("a character outside %x21-7E")
    # 2. The fragment: the first "#" and everything after it.
    s = s.split("#", 1)[0]
    # 3. Escapes, read once from left to right. A "%" must begin "%" HEXDIG
    #    HEXDIG; an escape of an unreserved character is refused (row 6);
    #    nothing is decoded, so "%2541" is "%25" then "41" (row 12).
    i = s.find("%")
    while i != -1:
        hx = s[i + 1:i + 3]
        if len(hx) != 2 or not set(hx) <= HEXDIG:
            raise NotEvaluable("a '%' that does not begin an escape")
        if chr(int(hx, 16)) in UNRESERVED:
            raise NotEvaluable(f"%{hx} encodes an unreserved character")
        i = s.find("%", i + 3)
    # 4. Every "/" at the end of the identifier. A "." is left alone here: at
    #    the end of a host step 9 removes it, and at the end of a path segment
    #    it is part of a different identifier.
    s = s.rstrip("/")
    # 5. The scheme, lower-cased; did and https are the two forms of 14.1.1.
    scheme, colon, rest = s.partition(":")
    if not colon or not SCHEME.match(scheme):
        raise NotEvaluable("no scheme")
    scheme = scheme.lower()
    if scheme == "did":
        # 6. Parse: DID Core syntax; did:WEB is not a case variant, it does not parse.
        if not DID.match("did:" + rest):
            raise NotEvaluable("not a DID (DID Core Section 3.1)")
        method, _, msid = rest.partition(":")
        if method != "web":
            # 7, 9 and 10 concern a host, which only did:web has here; 8 applies.
            return "did:" + _upper_escapes(rest)
        if any(part in (".", "..") for part in msid.split(":")):
            raise NotEvaluable("a '.' or '..' segment in a did:web identifier")
        if "::" in msid:
            raise NotEvaluable("an empty segment ('::') in a did:web identifier")
        seg, sep, tail = msid.partition(":")
        m = PORT_DID_WEB.search(seg)
        host, port_sep, port = (seg[:m.start()], seg[m.start():m.end()], seg[m.end():]) if m else (seg, "", "")
        if "%" in host or (port_sep and not _port_ok(port)):
            raise NotEvaluable("a did:web host with an escape, or a port that is not digits "
                               "or begins with '0'")
        if _numeric_host(host):
            raise NotEvaluable("a did:web host whose last non-empty label begins with a digit")
        # 7. Host lower-cased; the segments after the host keep their case.
        host = host.lower()
        # 8. Escape case: upper-case hex digits (RFC 3986 6.2.2.1). Before step 10.
        port_sep = port_sep.upper()
        tail = _upper_escapes(tail)
        # 9. Every "." at the end of the host; an empty host is not evaluable.
        host = host.rstrip(".")
        if not host:
            raise NotEvaluable("an empty did:web host")
        # 10. Default port: "%3A443" or an empty "%3A", as a fixed string.
        if port_sep + port in ("%3A443", "%3A"):
            port_sep = port = ""
        return "did:web:" + host + port_sep + port + sep + tail
    if scheme == "https":
        # 6. Parse against RFC 3986: "//" authority path-abempty ["?" query],
        #    no userinfo, a reg-name host with no escape and no last non-empty
        #    label that begins with a digit (no IP-literal), a port of digits
        #    with no leading zero, no "." or ".." path segment, no "//" in the
        #    path, and no empty query.
        if not rest.startswith("//"):
            raise NotEvaluable("an https identifier with no authority")
        body = rest[2:]
        cut = min([j for j in (body.find("/"), body.find("?")) if j != -1], default=len(body))
        authority, tail = body[:cut], body[cut:]
        if "@" in authority:
            raise NotEvaluable("userinfo in an https identifier")
        if authority.startswith("["):
            raise NotEvaluable("an IP-literal host")
        host, c, port = authority.partition(":")
        port_part = c + port
        if "%" not in host and not REG_NAME.match(host):
            raise NotEvaluable("a host character that RFC 3986 does not admit")
        if "%" in host:
            raise NotEvaluable("an https host with an escape")
        if _numeric_host(host):
            raise NotEvaluable("an https host whose last non-empty label begins with a digit")
        if port_part and (port_part[0] != ":" or not _port_ok(port_part[1:])):
            raise NotEvaluable("a port that is not digits or begins with '0'")
        if not HTTPS_TAIL.match(tail):
            raise NotEvaluable("a path or query character that RFC 3986 does not admit")
        path, query_mark, query = tail.partition("?")
        if any(part in (".", "..") for part in path.split("/")[1:]):
            raise NotEvaluable("a '.' or '..' path segment")
        if "//" in path:
            raise NotEvaluable("an empty path segment ('//')")
        if query_mark and not query:
            raise NotEvaluable("an empty query")
        # 7. Host lower-cased; path and query keep their case.
        host = host.lower()
        # 8. Escape case, before step 10.
        tail = _upper_escapes(tail)
        # 9. Every "." at the end of the host; an empty host is not evaluable.
        host = host.rstrip(".")
        if not host:
            raise NotEvaluable("an https identifier with an empty host")
        # 10. Default port ":443" or an empty ":", and a path of exactly "/".
        if port_part in (":443", ":"):
            port_part = ""
        if tail == "/" or tail.startswith("/?"):
            tail = tail[1:]
        return "https://" + host + port_part + tail
    raise NotEvaluable(f"scheme {scheme!r} is neither did nor https (Section 14.1.1)")


def same_party(a: str, b: str) -> bool:
    return norm(a) == norm(b)


def signatures_ordered(obj: dict) -> tuple[bool, str]:
    """The `signatures` array sorted by kid (facilitator Section 14.1).

    Two agents that each attach their own entry and then exchange the object
    produce two arrays, two vtc_hash values (Section 2 digests the signature
    set) and two contracts for one agreement. The order is the Section 9.1
    normalized kid, ties broken by the raw kid, both compared as sequences of
    Unicode code points. Returns (ok, reason); an object with fewer than two
    entries is trivially ordered.
    """
    keys = [(norm(k), k) for k in signer_kids(obj)]
    if keys != sorted(keys):
        return False, "signatures are not sorted by normalized kid"
    return True, "ok"


# --------------------------------------------------------------------------
# The assurance constraint, Appendix A.4 of -02 (Section 7.2 of -01)
# --------------------------------------------------------------------------

def exact(x: str | float | int | Decimal) -> Fraction:
    """The exact value of an amount or a JSON number, as the record prints it.

    An amount is a decimal string and is read as written. A JSON number such
    as q_min is read as its RFC 8785 form, which for a float is the shortest
    decimal that round-trips (Python's repr), so 0.9091 is nine thousand and
    ninety-one ten-thousandths and not the binary value nearest to it.
    """
    if isinstance(x, Fraction):
        return x
    return Fraction(Decimal(str(x)))


def assurance_holds(price: str | float, bond: str | float, q_min: str | float,
                    released: str | float = "0") -> bool:
    """B >= P(1-q)/q + E, evaluated exactly (Appendix A.4).

    Multiplied through by q (which is positive) this is B*q >= P*(1-q) + E*q.
    The products are rational numbers with no rounding at all. An earlier
    version rounded both sides to the nearest cent, and a bond one hundredth of
    a cent short of the bound passed; the version after it used Decimal's
    default 28-digit context, which rounded B*q, so P 0.01, B
    0.020000000000000003 and q 0.3333333333333333 passed too, although B*q
    falls 1e-34 short of P*(1-q) and B is about 3e-34 below the bound
    (audit A3).
    """
    P, B, q, E = (exact(x) for x in (price, bond, q_min, released))
    if q <= 0:
        raise ValueError("q must be greater than zero")
    return B * q >= P * (1 - q) + E * q


def required_bond(price, q_min, released="0") -> Fraction:
    """P(1-q)/q + E, exactly; the smallest bond the admission rule accepts."""
    P, q, E = exact(price), exact(q_min), exact(released)
    return P * (1 - q) / q + E


def amount_str(x: Fraction | Decimal | str, places: int | None = None, up: bool = False) -> str:
    """An amount string (Section 2) for an exact value.

    With places None the value must be a terminating decimal and is written
    exactly, with the fewest decimal places that keep it and never fewer than
    two: 0.105 is "0.105", 0.5 is "0.50", 180 is "180.00". With places given
    the value is written at that many places, rounded up when up is true and
    refused otherwise; only the text of a refusal uses that form.
    """
    v = exact(x) if not isinstance(x, Fraction) else x
    if v < 0:
        raise ValueError("an amount has no sign")
    if places is None:
        k = 0
        while (v * 10 ** k).denominator != 1:
            k += 1
            if k > 18:
                raise ValueError(f"{v} has more than eighteen decimal places")
        places = max(k, 2)
    scaled = v * 10 ** places
    if scaled.denominator != 1:
        if not up:
            raise ValueError(f"{v} does not fit {places} decimal places")
        scaled = Fraction(-((-scaled.numerator) // scaled.denominator))
    # Section 2 puts no bound on the integer part. str(int) refuses an integer
    # of more than 4300 digits (Python's limit on int-to-str conversion), and
    # Decimal's own formatting has no such limit, so the digits come from it.
    digits = format(Decimal(int(scaled)), "f").rjust(places + 1, "0")
    return digits[:-places] + "." + digits[-places:]


def places_of(amount: str) -> int:
    """Decimal places as written: "180.00" has two, "0.105" three."""
    return max(0, -Decimal(amount).as_tuple().exponent)


# --------------------------------------------------------------------------
# What an Outcome Record says about its own trace (Section 12 of -03)
# --------------------------------------------------------------------------

def standing_verdict(trace: list[dict]) -> dict | None:
    """Section 4.2: the last verdict entry that no later entry supersedes.

    A Verdict is accepted while one stands only in answer to a Challenge, and
    it then supersedes the one that stood, so this is the last verdict entry.
    """
    verdicts = [e for e in trace if e.get("event") == "verdict"]
    return verdicts[-1] if verdicts else None


def outcome_verdict(trace: list[dict]) -> str:
    """outcome.verdict: the digest of the Verdict standing at the terminal
    entry; else "verdict-lapsed" when the trace records that event; else
    "none" (no Verdict was recorded and none was waited for and missed)."""
    st = standing_verdict(trace)
    if st is not None:
        return st["object"]
    if any(e.get("event") == "verdict-lapsed" for e in trace):
        return "verdict-lapsed"
    return "none"


def outcome_scope(vtc: dict) -> dict:
    """The members an Outcome Record copies from its contract besides parties."""
    return {"task": {"spec_hash": vtc["task"]["spec_hash"]},
            "verification": dict(vtc["verification"]),
            "flow": vtc["flow"]}


def outcome_errors(record: dict, vtc: dict | None = None, delivery: dict | None = None) -> list[str]:
    """Every rule of Section 12 a holder can check: outcome.verdict against the
    record's own trace; work_hash present exactly when a Delivery was recorded;
    with the contract, the copied members; with the Delivery the delivered
    entry names, its work_hash. Returns the problems found, none when sound."""
    errs: list[str] = []
    trace = record.get("trace") or []
    got = (record.get("outcome") or {}).get("verdict")
    want = outcome_verdict(trace)
    if got != want:
        errs.append(f"outcome.verdict is {got!r}; the trace gives {want!r}")
    delivered = [e for e in trace if e.get("event") == "delivered"]
    if delivered and "work_hash" not in record:
        errs.append("work_hash is absent though the trace has a delivered entry")
    if not delivered and "work_hash" in record:
        errs.append("work_hash is present though the trace has no delivered entry")
    if delivery is not None and delivered:
        if digest_over(delivery) != delivered[0].get("object"):
            errs.append("the Delivery given is not the one the delivered entry names")
        elif record.get("work_hash") != delivery.get("work_hash"):
            errs.append("work_hash is not the work_hash of the Delivery the delivered entry names")
    if vtc is not None:
        if record.get("vtc_hash") != digest_over(vtc):
            errs.append("vtc_hash is not the digest of the contract given")
        if record.get("parties") != vtc.get("parties"):
            errs.append("parties is not the contract's, copied")
        for member, value in outcome_scope(vtc).items():
            if record.get(member) != value:
                errs.append(f"{member} is not the contract's, copied")
    return errs


# --------------------------------------------------------------------------
# JWS General JSON Serialization with a detached payload, Section 14.1
# --------------------------------------------------------------------------

ALLOWED_ALGS = ("Ed25519", "ES256", "ES384")


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
    """A party key. `kid` is the URI a verifier resolves, per Section 14.1.1."""
    kid: str
    alg: str
    private: Any = None
    public: Any = None

    @classmethod
    def from_seed(cls, kid: str, seed: bytes) -> "Key":
        """An Ed25519 key from 32 seed bytes. Used only to mint the committed
        examples reproducibly; the seeds are public and so are the keys."""
        if not HAVE_CRYPTO:
            raise RuntimeError("signing needs the `cryptography` package")
        sk = Ed25519PrivateKey.from_private_bytes(seed)
        return cls(kid=kid, alg="Ed25519", private=sk, public=sk.public_key())

    @classmethod
    def from_public_bytes(cls, kid: str, alg: str, raw: bytes) -> "Key":
        """A verify-only key from the raw public bytes public_bytes() emits."""
        if not HAVE_CRYPTO:
            raise RuntimeError("verification needs the `cryptography` package")
        if alg == "Ed25519":
            pub = Ed25519PublicKey.from_public_bytes(raw)
        elif alg == "ES256":
            pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
        elif alg == "ES384":
            pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), raw)
        else:
            raise ValueError(f"unsupported alg {alg}")
        return cls(kid=kid, alg=alg, private=None, public=pub)

    @classmethod
    def generate(cls, kid: str, alg: str = "Ed25519") -> "Key":
        if not HAVE_CRYPTO:
            raise RuntimeError(
                "the `cryptography` package is required to mint keys; "
                "install it with `pip install cryptography`")
        if alg == "Ed25519":
            sk = Ed25519PrivateKey.generate()
        elif alg == "ES256":
            sk = ec.generate_private_key(ec.SECP256R1())
        elif alg == "ES384":
            sk = ec.generate_private_key(ec.SECP384R1())
        else:
            raise ValueError(f"unsupported alg {alg}")
        return cls(kid=kid, alg=alg, private=sk, public=sk.public_key())

    def sign_bytes(self, data: bytes) -> bytes:
        if self.alg == "Ed25519":
            return self.private.sign(data)
        curve_hash = hashes.SHA256() if self.alg == "ES256" else hashes.SHA384()
        der = self.private.sign(data, ec.ECDSA(curve_hash))
        r, s = decode_dss_signature(der)
        n = CURVE_ORDER[self.alg]
        if s > n // 2:                       # emit the low-S form, see verify_bytes
            s = n - s
        size = 32 if self.alg == "ES256" else 48
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")

    def verify_bytes(self, sig: bytes, data: bytes) -> None:
        if self.alg == "Ed25519":
            self.public.verify(sig, data)
            return
        size = 32 if self.alg == "ES256" else 48
        if len(sig) != size * 2:
            raise InvalidSignature("bad JWS ECDSA signature length")
        r = int.from_bytes(sig[:size], "big")
        s = int.from_bytes(sig[size:], "big")
        # RFC 7518 fixes the encoding (raw r||s) but not which of the two valid
        # s values a verifier accepts. Accepting both lets anyone holding a
        # valid signature mint a second one over the same bytes without the
        # key, and a second signature entry changes vtc_hash (Section 2). The
        # low half is enforced here ahead of the text; see Section 14.1.
        n = CURVE_ORDER[self.alg]
        if s == 0 or s > n // 2:
            raise InvalidSignature("ECDSA s is not in the low half of the curve order")
        curve_hash = hashes.SHA256() if self.alg == "ES256" else hashes.SHA384()
        self.public.verify(encode_dss_signature(r, s), data, ec.ECDSA(curve_hash))


# Group orders of P-256 and P-384 (FIPS 186-4 D.1.2.3 and D.1.2.4), for the
# low-S rule in sign_bytes and verify_bytes. tools/validate.py proves both
# constants without a library by computing n * G on each curve and requiring
# the point at infinity.
CURVE_ORDER = {
    "ES256": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    "ES384": int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
                 "581A0DB248B0A77AECEC196ACCC52973", 16),
}


class KeyResolver:
    """Maps a `kid` to a public key.

    Section 14.1.1 resolves a kid as a DID URL (DID Core, did:web) or as an
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
    """Raw public key bytes, for the Section 17.13 record of what was resolved."""
    from cryptography.hazmat.primitives import serialization
    if key.alg == "Ed25519":
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
        # Section 14.1: a kid outside the signed header is attacker-controlled.
        return False, "kid carried as a sibling of the protected header"
    for member in ("jwk", "jku", "x5c", "x5u", "x5t", "x5t#S256", "crit"):
        if member in protected:
            return False, f"protected header carries {member}, which Section 14.1 forbids"
    if "header" in entry:
        return False, "signature entry carries an unprotected header"
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
        # starts with "algorithm" so a caller can map it to the problem table's
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
    did:web:seller.example.evil starts with did:web:seller.example and would have
    signed as its neighbour. Section 14.1 of the draft requires equality of the
    normalized identifier, not containment. Raises NotEvaluable, never
    returns False, for an identifier that does not parse (Section 9.1).
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


