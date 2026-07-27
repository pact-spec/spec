# Contributing

Feedback is the point of a -00 draft. Open an issue for design
discussion, a PR for concrete text or schema changes.

## IETF Note Well

This repository develops content intended for submission to the IETF as
Internet-Drafts. By contributing text intended for the draft, you agree
that your contribution may be included in IETF Contributions and you
accept the terms of the IETF Note Well (https://www.ietf.org/note-well/),
including BCP 78 and BCP 79 (IPR disclosure obligations).

## Ground rules

- Substantive protocol changes: open an issue first; PRs after rough
  consensus in the thread.
- Every change to `examples/` or `schemas/` must keep
  `python3 tools/validate.py` passing (CI enforces this).
- Editorial fixes: PRs directly welcome.
