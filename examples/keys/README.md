# Example keys

`public-keys.json` holds the public keys that verify the signatures on the
committed examples, as JWKs (RFC 7517). The private keys are derived in
`tools/mint_examples.py` from public seeds, so they are not secrets and the
signatures are reproducible byte for byte; nothing signed with them means
anything outside this repository.
