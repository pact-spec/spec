# Task content for the worked example

The bytes that the three URIs inside `examples/taskspec.json` point at, so that
the sibling hashes the draft requires (Section 5.1) commit to something a reader
can recompute: `customers.schema.json` for `inputs.schema_uri`, `sample-10k.csv`
for `inputs.sample_uri` (four lines standing in for ten thousand), and
`output.schema.json` for `deliverable.schema_uri`. Each hash is SHA-256 over the
file's bytes. `tools/mint_examples.py` computes them.
