# malyz3r Rule Engineering Lab

The first milestone adds strict compilation, structured scans, labeled dataset
evaluation, and harmless positive/negative regression fixtures. Samples are read
as bytes and never executed. This is static file evaluation, not a sandbox.

## Run

```console
python -m pip install "yara-python>=4.3,<5"
python -m malware_scanner.lab samples/lab/manifest.json --output report.json
python -m unittest discover -s tests -v
```

After installing the project, `malyz3r-lab` provides the same evaluator command.
Use `--rules path/to/rules` for another ruleset. Both `.yar` and `.yara` files
are discovered recursively. Broken or missing rules abort evaluation.

## Dataset contract

The JSON manifest has `name`, `kind`, and a nonempty `samples` list. Each sample
contains `path` (relative to the manifest), `label` (`benign` or `target`), and
`expected_rules` (a list of `relative-rule-file:RuleName` identifiers). An optional
`sha256` pins sample content. Benign samples require an empty expected list;
target samples require at least one expected rule. Unknown rules and duplicate
sample content are rejected. Keep manifests and labels under version control.

The bundled dataset is **synthetic**: its eight text fixtures verify selected
matching conditions and known false-positive regressions. It cannot establish
real malware recall, generalization, or production readiness. Tightened rules
are candidate heuristics requiring further validation, not validated signatures.

## Reports

Each sample includes its SHA256, matched rule/string identifiers, duration in
milliseconds, and status (`matched`, `no_match`, `error`, or `timeout`). No match
does not mean a file is safe. The per-rule confusion matrix compares matches to
the explicit expected-rule labels. Recall is TP/(TP+FN), precision TP/(TP+FP),
and false-positive rate FP/(FP+TN). Undefined ratios are JSON null.

Per-rule negatives include **all samples not labeled for that rule**, including
other target samples. Thus this is an off-target false-positive rate; it is not
automatically a benign-only rate. Dataset composition affects precision.

Reports record the engine version, manifest hash, and discovered rule source
hashes. Keep rules and manifests immutable during a run. External included files
are not fingerprinted; keep benchmark rules self-contained for reproducibility.

Unreadable files, hash mismatches, and timeouts are excluded from denominators
and make `complete` false. Never use an incomplete report as a quality gate.
Exit codes: 0 complete run (even with detection mistakes), 1 incomplete run,
2 invalid input/compilation failure. Tests assert expected regression outcomes.

The scanner recompiles on each call to avoid stale edited rules; the lab compiles
once per dataset. Files are currently read into memory, so use bounded sample
sizes. Includes use YARA's normal resolution; avoid duplicate included rule
definitions. Existing memory-scanning features remain separate from this lab.

## Next milestones

- Curate independently labeled real samples in an isolated environment and a
  representative benign corpus; keep binaries outside the public repository.
- Separate development and held-out datasets, avoiding duplicate/related samples
  across splits; record provenance, family, and label confidence.
- Add baseline-versus-candidate comparisons and configurable regression gates.
- Measure benign-only false positives, cross-family confusion, throughput,
  and uncertainty on adequate sample sizes.
