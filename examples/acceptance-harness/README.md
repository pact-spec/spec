# Acceptance instrument (worked example)

This directory is the acceptance instrument committed by
`verification.criteria_hash` in `cfb.json` and `vtc.json`.

`criteria_hash` is SHA-256 over the JCS-canonicalized manifest of this
directory: a JSON object mapping each file's path, relative to this
directory, to the SHA-256 of its bytes. `tools/validate.py` recomputes it
on every run and CI fails if it drifts.

Committing a manifest of per-file digests rather than a single archive
digest means the commitment is reproducible without depending on tar or
zip metadata (timestamps, ordering, permissions), which are not stable
across producers.

## Why this replaced a text file

Until August 2026 this instrument was a single 85-byte file whose entire
content was a sentence describing the tests. The commitment therefore
covered a description of the acceptance criteria rather than the criteria
themselves, so a party hosting the real harness could swap its bytes
after signature and manufacture a valid fraud proof. See
https://github.com/pact-spec/spec/issues/1 entry 6.

The general rule this example now demonstrates: a hash commitment covers
exactly the octets hashed. Any URI inside hash-committed content whose
bytes are consumed during bidding, execution, or verification needs its
own sibling hash member.
