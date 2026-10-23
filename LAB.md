# malyz3r Rule Engineering Lab

The first milestone adds strict compilation, structured scans, labeled dataset
evaluation, and harmless positive/negative regression fixtures. Samples are read
as bytes and never executed. This is static file evaluation, not a sandbox.

## Run

```console
python -m pip install .
python -m malware_scanner.lab samples/lab/manifest.json --output report.json
python -m unittest discover -s tests -v
```

After installing the project, `malyz3r-lab` provides the same evaluator command.
Use `--rules path/to/rules` for another ruleset. Both `.yar` and `.yara` files
are discovered recursively. Broken or missing rules abort evaluation.

## Dataset contract

The JSON manifest has `name`, `kind`, and a nonempty `samples` list. Each sample
contains `path` (relative to the manifest), `label` (`benign`, `target`, or `unknown`), and
`expected_rules` (a list of `relative-rule-file:RuleName` identifiers). An optional
`sha256` pins sample content. Benign samples require an empty expected list;
target samples require at least one expected rule. Unknown samples require an
empty expected list and are excluded from metrics. Unknown rules and duplicate
sample content are rejected. Keep manifests and labels under version control.

The bundled dataset is **synthetic**: its eighteen text fixtures verify all nine public rules and their
matching conditions and known false-positive regressions. It cannot establish
real malware recall, generalization, or production readiness. Tightened rules
are candidate heuristics requiring further validation, not validated signatures.

## Reports

Each sample includes its SHA256, matched rule/string identifiers, duration in
milliseconds, and status (`matched`, `no_match`, `error`, or `timeout`). No match
does not mean a file is safe. The per-rule confusion matrix compares matches to
the explicit expected-rule labels. Recall is TP/(TP+FN), precision TP/(TP+FP),
and false-positive rate FP/(FP+TN). F1 is 2TP/(2TP+FP+FN). Undefined ratios are JSON null.
Reports also include a separate benign-only false-positive rate.

Per-rule negatives include **all samples not labeled for that rule**, including
other target samples. Thus this is an off-target false-positive rate; it is not
automatically a benign-only rate. Dataset composition affects precision.

Reports record the engine version, the hash of the manifest bytes actually
parsed, all compiled source/dependency hashes, and resource settings. Sources
are cached as bytes and compilation and hashing use those same bytes. Includes
resolve relative to the including file and must remain inside the rules root;
ambiguous reused include names are rejected. Keep inputs immutable during a run.
There is a 4 MiB per-source limit and a 32 MiB total rule-source snapshot limit.

Unreadable files, hash mismatches, and timeouts are excluded from denominators
and make `complete` false. Never use an incomplete report as a quality gate.
Exit codes: 0 complete run (even with detection mistakes), 1 incomplete run,
2 invalid input/compilation/output failure. With `--strict`, a complete run exits
3 if any false positives or false negatives occur. Without `--strict`, completed
runs with detection mistakes still exit 0. Tests assert regression outcomes.

A directory scan shares one compiled ruleset across bounded worker batches.
The lab uses one immutable compiled snapshot per dataset. Samples are capped at
64 MiB by default (`--max-bytes`), with bounded reads even if a file grows while
being read. YARA scans default to a 10-second timeout (`--timeout`). Nonregular
files are rejected. These limits do not provide a hard deadline for disk I/O,
compilation, or a process sandbox. Use trusted local manifests: absolute paths
and paths outside the manifest directory are permitted intentionally, allowing
private sample storage separate from versioned manifests.

## Next milestones

- Curate independently labeled real samples in an isolated environment and a
  representative benign corpus; keep binaries outside the public repository.
- Separate development and held-out datasets, avoiding duplicate/related samples
  across splits; record provenance, family, and label confidence.
- Baseline comparison and configurable gates are implemented in the workbench;
  see [OPERATIONS.md](OPERATIONS.md).
- Measure benign-only false positives, cross-family confusion, throughput,
  and uncertainty on adequate sample sizes.
