# Harbor near-miss verifier control

This is a development integration for testing a benchmark verifier between its
usual ceiling and floor controls:

```text
oracle -> reward 1
nop -> reward 0
oracle-derived, right-schema/wrong-content near miss -> reward 0
```

The control runs the task's own reference solution, mutates only artifact paths
declared in `task.toml`, and hands the result to the unchanged Harbor verifier.
It refuses to run the verifier unless at least one declared artifact changed by
digest. Unsupported or content-identical mutations are **invalid/not
applicable**, never successes.

## Why it is different from an adversarial agent

An adversarial agent asks whether one policy can discover a hack. This adapter
asks a deterministic property question: does the verifier reject a fixed class
of well-formed but scientifically wrong artifacts? Both are useful; they are
not substitutes.

## Development use

Pin Harbor and the benchmark source before running:

```bash
python near_miss.py selftest
python near_miss.py survey /path/to/tasks

PYTHONPATH="$PWD" uvx --from harbor==0.21.0 harbor run \
  -p /path/to/tasks/example-task \
  -a near_miss_agent:NearMissAgent \
  --ak task_dir=/path/to/tasks/example-task \
  --ak mode=shuffle \
  --ak seed=0 \
  -e docker
```

Supported mutation hypotheses are `shuffle`, `flatten`, `scale`, and
`signflip`. Applicability is decided from the produced artifact, not merely its
extension. For example, scaling a binary integer mask may be a byte-identical
no-op and must be excluded.

## Receipt

`receipt.py` emits a local, append-only, payload-free record over a named probe
set:

```bash
python receipt.py scan /path/to/tasks -o guard-receipt.json
python receipt.py record guard-receipt.json TASK oracle-1 \
  --disposition observed --reward 1 --detail "Harbor 0.21.0 oracle" \
  --harbor-result-sha256 "$RESULT_SHA256"
python receipt.py verify guard-receipt.json
python receipt.py badge guard-receipt.json -o guard-badge.svg
```

The badge reports judged coverage and pending probes. It does not claim that a
benchmark is unexploitable, scientifically valid, or non-bypassable. The
adapter implements no network calls and embeds no raw artifact payloads, but
that is not evidence of host-level network enforcement.

## Current evidence boundary

The checked-in code and tests establish local transformation and receipt
integrity. External benchmark results belong in a separately pinned evidence
packet. A development pilot observed before its manifest was frozen must be
labeled post-start development evidence; it is not a preregistration.

The current founder-review packet is tracked at
`docs/contributions/terminal-bench-science-near-miss/`. It binds the exact
upstream source, Harbor version, proposed patch, five-task run matrix, job and
artifact digests, exclusions, and receipt chain. It is not an upstream adoption
claim.
