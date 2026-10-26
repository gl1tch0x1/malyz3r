# Local analyst workflow

The operational entry point is `malyz3r-workbench` (or
`python -m malware_scanner.workbench`). This is a local single-user application,
not a hosted multi-user service. Run it in the analyst environment where the
sample corpus is stored. It does not upload samples or execute their contents.

## 1. Inventory real files

```console
malyz3r-workbench inventory /analysis/incoming --output manifests/incoming.json --provenance "Case 42, analyst collection"
```

Labels default to **unknown**. Unknown samples are scanned for triage but never
treated as benign negatives or used to calculate detection metrics. Hashes,
source paths, sizes, provenance, duplicates, skipped files, and truncation are
recorded. Output must be outside the input directory and must not already exist.
Files are not copied or modified. Symlinks and directory links are skipped.

Only label a collection when its ground truth is justified:

```console
malyz3r-workbench inventory /analysis/clean --output manifests/clean.json --provenance "Verified vendor distribution; describe verification" --label benign --split held_out
malyz3r-workbench inventory /analysis/family-a --output manifests/family-a.json --provenance "Analyst-adjudicated family A; record evidence" --label target --family family-a --expected-rule family-a.yar:Family_A --split held_out
malyz3r-workbench merge manifests/clean.json manifests/family-a.json --output manifests/evaluation.json
```

Use actual paths and rule IDs. Repeating `--expected-rule` supports overlapping
expected detections. `merge` rejects conflicting labels or identical content
assigned to different splits. Near-duplicate and time/family-aware separation
still require analyst judgment. It does not infer malware families from a vendor
score, filename, or YARA match. A label records an assertion, not independent
verification. Preserve source manifests and adjudication evidence.

## 2. Evaluate with persistent evidence

```console
malyz3r-workbench run manifests/evaluation.json --rules rules/baseline --runs-dir runs --wall-seconds 300 --memory-mb 512 --policy policies/research-release.json
```

Each invocation creates a new timestamp/UUID directory containing:

- `status.json`: terminal state, exit code, timestamps, elapsed time, observed RSS.
- `request.json` and optional `policy.json`: effective job settings.
- `inputs/`: exact manifest bytes, a resolved-path manifest, and the source bytes
  actually compiled, including dependencies.
- `samples.jsonl`: flushed per-file scan results, useful after a failed worker.
- `progress.json`: current completed/total counts.
- `worker.log`: compilation/runtime errors and tracebacks for diagnosis.
- `report.json`, `metrics.csv`, `report.html`: completed evaluation and policy results.

Inspect status with `malyz3r-workbench inspect runs/RUN_ID`. The HTML report is a
standalone local file. It escapes input text and lists false detections, missed
targets, and scan errors. Reports contain local paths and sample hashes; treat
them as potentially sensitive case material. Runs are excluded from Git.

The supervisor launches a separate Python worker, monitors resident memory and
wall time, and kills it on a limit violation. On Unix the worker also sets an
address-space limit. Windows uses RSS polling; this can briefly overshoot the
budget and is not an OS-enforced memory reservation. The native engine's timeout
also bounds each scan. Crashes, interruption, and resource-limit failures produce
non-success terminal states rather than clean reports.

This is **failure containment, not a security sandbox**. Workers run with the
analyst's permissions and network access. Use an isolated VM, restricted account,
and appropriate filesystem/network controls for untrusted samples and rules.
Compilation, native libraries, and disk I/O remain part of the threat model.
Inventory runs in the CLI process; use local storage, not untrusted network mounts.

## 3. Compare a rule revision

```console
malyz3r-workbench run manifests/evaluation.json --rules rules/candidate --runs-dir runs
malyz3r-workbench compare runs/BASELINE/report.json runs/CANDIDATE/report.json --output comparison.json
```

Comparison requires complete reports with identical sample content hashes,
labels, expected rule IDs, splits, engine version, and scan settings. It reports
new detections, missed detections, new false positives, removed false positives,
and metric deltas. Rule IDs must remain stable across revisions. A renamed or
new rule needs separately adjudicated labels, not an automatic baseline mapping.
Unknown labels, incomplete inventories, or different corpora cause comparison to fail.

To repeat a run against captured rules, use its `inputs/manifest.resolved.json`
and `inputs/rules` with `run`. The referenced samples must still be accessible;
SHA256 checks detect changes for pinned samples. Snapshots retain rule inputs,
not sample binaries. Include files with `.inc` extensions are dependencies;
`.yar`/`.yara` files are also compiled as independent entry points.

## Quality gates and exit codes

The example policy is a starting point for analyst review, **not an industry
standard or certification**. It requires at least 30 target examples per rule,
4,000 benign files, recall >= 0.90, benign FPR <= 0.001, no unknown labels, and
a held-out non-synthetic dataset. It also requires the two-sided 95% Wilson
recall lower bound to be at least 0.80 and benign-FPR upper bound at most 0.001. Adjust thresholds for the threat and workload;
sample size, representativeness, and confidence intervals still matter. `rules`
can select a subset of stable rule IDs for a family-specific release.

No policy means **quality not evaluated**, even if scanning completed. Undefined
recall and insufficient positive evidence fail policies that require recall.
The benign-only FPR is separate from off-target FPR, which includes other families.
F1 and precision depend on the chosen corpus and do not estimate deployment yield.

Workbench exit codes: 0 completed operation, 1 incomplete/failed/resource-limited
run (or incomplete inventory), 2 invalid command/input, 3 rejected quality policy
or comparison regression, 130 analyst cancellation. Automation must inspect the
exit code and terminal status. A passing policy validates only its stated checks.

## Current validation boundary

The pipeline has been exercised on actual installed Python-package files,
including native extension binaries, and on deterministic fixtures. No labeled
real-malware corpus has been evaluated. Hosted CI, broad platform validation,
independent security review, and representative held-out detection measurements
are still required before a production-readiness claim. Do not promote bundled
heuristic rules merely because the application runs successfully.

## Portable release validation

Install the validated dependency set with `python -m pip install -c constraints.txt ".[dev]"`,
then run `python tests/run_validation.py`. On Docker-capable systems:

```console
docker build -f Dockerfile.validation -t malyz3r-validation:local .
docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --memory 1g --cpus 2 malyz3r-validation:local
```

The native-library benchmark helper `tests/benchmark_system.py OUTPUT_DIRECTORY`
inventories Python extension modules on Linux, records their assumed-benign
provenance, and performs a real-file run. It does not establish malware recall.
See [SECURITY.md](SECURITY.md) for isolation and audit limitations.


## Legacy configuration and automation

Environment overrides are evaluated on each configuration load. Invalid JSON or
parallelism outside 1-32 fails explicitly; `--help` still works with bad settings.
Saving configuration is atomic and excludes the VirusTotal credential. Supply
`MALYZ3R_VT_API_KEY` in the environment for each execution environment that needs it.

`scripts/yara_scan.sh SCAN_DIRECTORY RULES_DIRECTORY LOG_FILE` delegates to the
installed scanner and preserves failures through `pipefail`. It requires all
three paths and does not default to scanning the entire filesystem. Set
`MALYZ3R_PYTHON` to the installed virtual environment's Python if needed. It shares
the scanner's per-file limits but not the workbench's whole-worker supervision.
