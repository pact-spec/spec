# Legacy -00 examples

`draft-laxsharma-pact-01` removes the sealed-bid second-price award procedure
from the document (see its Section 1.2). The four JSON files here correspond
to Sections 4.1 and 6 of the -00 and are retained so the published -00
remains checkable, not because they are current.

This tree has no schema for them. Commit 8b490ce, the last before the -01
objects, has all three (call-for-bids, bid, capability document), and its
`tools/validate.py` checks these same four files at their old paths. The
`spec_hash` in `cfb.json` matches only under that validator's
canonicalizer, which printed the number one as `1.0` (see vector V-25).
Tag v0.1.0 still has the call-for-bids and bid schemas, not the capability
one.

They are not part of the conformance surface. If the award procedure
returns as a separate draft, they move back.
