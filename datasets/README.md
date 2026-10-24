# GitHub PHP research corpus

This is a reproducible, source-labeled **static YARA calibration dataset**, not
an independently adjudicated malware benchmark or a machine-learning training set.
The downloader retrieves real upstream file bytes; it does not synthesize samples.

## Sources and attribution

- [WordPress/WordPress](https://github.com/WordPress/WordPress), commit
  `f5268cfbd5361508b32e01897b4a01eed1a1e79d`: PHP files are assumed benign because
  they belong to the official application source. This is not a security audit
  of WordPress. Upstream licensing is recorded in its `license.txt` and file notices.
- [tennc/webshell](https://github.com/tennc/webshell), commit
  `6b17eae4a0bc792f996a38ce32772e4db9c7c799`: PHP files are source-asserted webshell
  targets. The collection may include helpers, demonstrations, duplicates, and
  related variants; not every file is a verified incident sample. The repository
  carries an MIT license; individual upstream notices still apply.

[github-php.json](github-php.json) pins commits, archive SHA256 digests, label bases,
and license URLs. Samples remain outside version control in `local-corpus/`.
The project MIT license does not replace third-party licenses. Consult the upstream
notices before redistributing a corpus; raw samples are not bundled with the package.

## Build and evaluate

From an installed source checkout, with network access for fetching:

```console
python -m malware_scanner.dataset datasets/github-php.json --output local-corpus/github-php
python -m malware_scanner.benchmark local-corpus/github-php --output runs/github-php-experiment
```

Both output directories must be new. An optional `--archive-cache DIRECTORY` on
the dataset command reuses `WordPress.zip` and `tennc.zip` only after checking
their pinned digests. Archive retrieval does not execute upstream build scripts.
Only PHP file contents are imported, under SHA256 filenames with `.bin` extensions.
That naming convention prevents accidental normal PHP association; it is not a sandbox.

The importer bounds downloads, individual samples, member count, and aggregate PHP
bytes, rejects archive traversal and symlinks, and rejects conflicting labels for
identical content. `status.json` records completion or failure; partial directories
from failed builds must not be treated as a valid corpus.

The verified import contains **2,448 unique files** after exact deduplication:

- Development: 1,695 assumed-benign files and 286 source-asserted targets.
- Held out: 383 assumed-benign files and 84 source-asserted targets.

`development.json` and `held_out.json` include hashes, relative local paths, labels,
expected rule IDs, split assignments, and per-file immutable GitHub source URLs.
`sources.json` preserves source provenance and duplicate counts. Files with the same
content hash are assigned to one partition, using a deterministic approximately
80/20 hash split. This does **not** prevent near-duplicate or family leakage.

## What calibration does

The benchmark evaluates three predeclared PHP webshell heuristics on the 1,981
development files. It selects the highest development F1 among candidates with
benign FPR at most 1%. This is an exploratory selection rule, not the research
release policy. Selection and rule bytes are saved before held-out evaluation.
No model weights are learned and no LLM is involved.

The selected rule uses the stable ID `webshell.yar:PHP_Webshell_Candidate` and is
kept separate from the nine bundled rules. Each development evaluation and the
held-out evaluation uses the existing supervised workbench and produces normal
JSON/CSV/HTML evidence. The benchmark writes `selection.json`, `selected-rules/`,
and `summary.json`; it refuses to mix exact content across partitions.

Do not revise the rule repeatedly against these held-out results and keep calling
the partition unseen. New tuning requires new independent evaluation evidence.

## Recorded result — 23 October 2026

The restricted Linux run completed all three development evaluations and the
held-out evaluation with no scan errors, no network, and no sample execution.
The selected candidate was `request_execution_or_encoded`:

- Development: 167/286 targets detected; 6/1,695 benign files matched.
- Held out: 51/84 targets detected; 3/383 benign files matched; 33 targets missed.
- Held-out recall: 60.71% (95% Wilson interval 50.02%–70.47%).
- Held-out benign FPR: 0.783% (95% Wilson interval 0.267%–2.277%).

This fails the research release thresholds. No thresholds were relaxed and the
rule is not promoted into the bundled ruleset. Results are in
[results/github-php-2026-10-23.json](results/github-php-2026-10-23.json), the per-file
source/hash/label index is [github-php-index.json](github-php-index.json), and the
candidate is [webshell.yar](../research_rules/php-webshell/webshell.yar).

On this workstation the complete readable corpus and original run records reside
in Docker volume **`malyz3r-php-research`**, under `/research/corpus` and
`/research/experiment`. Windows attempts encountered file-read errors and are
incomplete; they are not used for these metrics. Host protections were not disabled.
Copies of successful reports are in ignored `runs/github-php-linux/`.

To reuse the already-created image and volume for a fresh evaluation:

```console
docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --memory 1g --cpus 2 -v malyz3r-php-research:/research malyz3r-validation:local python -m malware_scanner.workbench run /research/corpus/held_out.json --rules /research/experiment/selected-rules --runs-dir /research/replays
```

For a new workstation, build `Dockerfile.validation`, initialize a writable research
volume for UID 10001, and run the import in that environment. Retain the source
archives for offline reconstruction; they contain the complete upstream notices.
Root license notices are also preserved in `notices/`.

## Interpretation limits

This measures PHP source pattern matching against source-derived labels. It does
not establish Windows executable malware recall, family attribution, dynamic
behavior, or production safety. The benign collection is one application, the
target collection is one repository, labels are not independently verified, and
variants may be correlated. A minimum sample count cannot repair those biases.

There are fewer than 4,000 held-out benign samples, so the existing research release
policy cannot pass this dataset. Thresholds have not been relaxed to manufacture
a release result. LangChain and LangGraph are not required for static YARA
calibration or report visualization; adding them would not improve label quality.
