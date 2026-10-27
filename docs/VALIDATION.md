## Expanded analyst components — 26 October 2026

Added evidence-linked outcome composition and investigation queues, compact density controls, map expansion and label visibility, editor font sizing, cursor position and exact-text draft download. Added SVG navigation icons, layered surfaces and short interaction transitions with a reduced-motion override. No runtime dependency or remote asset was introduced.

Chrome workflow checks cover category drill-down, density toggling, map controls, font sizing and downloaded source fidelity in addition to actual YARA evaluation, syntax rejection/acceptance, comparison, exports and mobile overflow assertions. Captures are in `runs/ui-validation/observatory/` and use synthetic test data, not a live threat feed. UI preferences currently apply only to the rendered view; the editor remains a plain-text YARA editor, not an LSP IDE.

## Analyst studio visual refinement — 26 October 2026

The dashboard, detection map and rule workbench share a revised dark visual system with stronger hierarchy, restrained mint accents, explicit warning colors and responsive controls. The map includes page-level node counts, a persistent observed/annotated relationship legend and clear-selection action. Dense sample/hash labels are suppressed until selected; node details remain available in the inspector. The source editor adds synchronized line numbers and moves validation/evaluation actions above the code.

Validation: the Chrome browser workflow exercises actual YARA fixture evaluations, imports, rejected/valid syntax, draft evaluation, comparison, evidence export and graph interactions. It additionally checks the line-number gutter, clear selection and absence of document-wide horizontal overflow on all three screens at 390 px. Desktop captures use 1440 px. JavaScript syntax and Ruff checks pass. Screenshots are under `runs/ui-validation/studio/`; their metrics come from a synthetic test corpus and are not evidence of real-malware detection quality. This iteration changes presentation and interaction, not detection semantics.

# Analyst dashboard redesign - 26 October 2026

The local UI now includes a quality overview with evidence drill-down and compatibility-filtered history, a pan/zoom detection map with typed nodes and provenance-aware inspectors, a copy-on-edit rule workbench, and focused sample investigation/export. The prior simple graph screen was replaced in navigation by the detection map.

Executed checks for this iteration:

- Full Windows unittest suite: 86 tests passed. The 13 assurance/API tests also passed after the final run-operation metadata change.
- Restricted Linux container: 86 tests discovered, 84 passed and two Windows-only skips. The full validation runner also passed strict lab evaluation, legacy scanner checks, installed-package smoke tests, formatting/lint and dependency consistency.
- Chrome browser workflow passed against actual bounded YARA jobs and the real local API. Added checks cover precision/false-positive drill-down, map node selection and type filtering, imported rule text, oversized submission errors, rejected syntax, valid syntax, candidate evaluation, preservation of original rule source, sample-report export and the existing comparison/navigation workflow.
- History tests verify that changed sample hashes are excluded even when manifest bytes stay identical. Graph tests assert that every edge resolves to stored nodes and that no direct rule-to-family coverage edge is fabricated.
- Non-editable package installation and smoke checks passed; Ruff, JavaScript syntax checks and `git diff --check` passed. Bandit reported no medium/high findings.
- Screenshots from permitted synthetic browser fixtures are stored locally under `runs/ui-validation/redesign/`. They are evidence of UI behavior, not measured real-malware accuracy.

The editor accepts only configured pack files (12 KB source limit), copies bounded dependencies, and uses the existing wall-clock/memory-limited worker for validation and evaluation. Raw sample contents remain unavailable through HTTP. No additional runtime dependency was introduced.

# Detection assurance extension - 26 October 2026

Local validation on branch `codex/detection-assurance` (not a claim about hosted CI):

- Before changes: 73 unittest tests passed on Windows / Python 3.13.
- After the backend integration: 82 tests passed on Windows. Ruff checks and formatting, legacy scanner tests, strict fixture evaluation, non-editable installed-package smoke tests and `pip check` passed through `tests/run_validation.py`.
- Linux / Python 3.13: the same validation runner passed in `malyz3r-assurance-validation`, with 80 tests passed and two Windows-only skips. Container execution used a non-root user, disabled networking, a read-only filesystem, dropped capabilities, no-new-privileges, and bounded memory/PIDs/CPU.
- The nine assurance/API tests were rerun after the final backend metadata change and passed.
- `tests/browser_assurance.py --channel chrome` passed against the real HTTP API and actual YARA evaluations of 52 permitted synthetic samples. It checks an empty workspace, launching a background evaluation, baseline/candidate comparison with 26 introduced false positives, invalid-policy recovery, policy rejection, JSON download, evidence navigation, table pagination, empty filters, coverage-cell navigation, rule metrics, graph relationships, a narrow viewport and expired-session errors. No mocked API or detection result is used.
- The browser test exposed and verified fixes for path-redaction compatibility with the existing strict comparison, stale asynchronous navigation, and stale error notices after successful retry.
- Installed-wheel smoke checks verify both new modules and bundled web assets. JavaScript syntax validation passed with `node --check`.
- Bandit at the CI medium/high threshold reported zero findings. `pip-audit` found no known vulnerabilities in the nine pinned runtime dependencies in `constraints.txt`; optional MCP/Playwright transitive dependencies were not included in that audit scope.

The browser test's optional Playwright installation is test tooling, not an application dependency. Results establish functional regression behavior, not real-malware accuracy, comprehensive security assurance, remote-hosting readiness or large-corpus capacity. See `ASSURANCE.md` for limitations and reproducible commands.

## PR #2 integration repair - 24 October 2026

Merged `main` (7dc174a) into the PR branch without rewriting its history. The
branches independently added many of the same files from the earlier base,
producing 26 conflicts. The resolution preserves the PR's expanded catalog and
assistant hardening, and retains main's CI, 18 original fixtures, diagram assets,
explicit-update-only launcher and strict dependency validation.

The MCP adapter now matches the declared SDK 2.3.0 API. Tests cover automatic and
legacy stdio negotiation. Private corpora remain excluded from Docker context;
the application image has an empty corpus mount point and builds from a clean
checkout. Package discovery excludes test packages.

Validation: Windows Python 3.13 passed the 71-test suite plus the added launcher
regression, lint/format, strict fixtures, installed-package smoke and pip check.
Restricted Linux Python 3.13 ran 72 tests: 70 passed and two Windows-only checks
were skipped; portable validation also passed. These are local results, not a
claim that hosted CI has completed. Rule count is not detector-quality evidence.
The records below refer to earlier revisions.

# Validation record — 22 October 2026

## Multi-provider and MCP update - 23 October 2026

- Windows Python 3.13: 56 tests pass; lint, format, installed package smoke,
  MCP entry point and dependency consistency checks pass.
- Restricted Linux Python 3.13: 54 pass, two Windows-only skips; lint, format,
  fixtures, installed package smoke and dependency checks pass with networking
  disabled, read-only filesystem, dropped capabilities and resource limits.
- Automated stdio subprocess test discovers tools, reads development evidence,
  and rejects traversal; in-memory client verifies network confirmation gating.
- A separate legacy-mode MCP client successfully retrieved evidence from the real
  1,981-file development report. This is a local protocol test, not an IDE UI test.
- All four provider transports use simulated responses in tests. No live provider
  call, paid model quality benchmark, or interactive IDE certification is claimed.
- Python 3.13 CI now installs the MCP extra; Python 3.10 skips optional MCP tests.
  MCP SDK 2.3.0 requires Python 3.11+. Core commands retain Python 3.10 support.

## Optional LLM integration — 23 October 2026

- Windows Python 3.13: all 49 tests pass, including 11 assistant-specific tests.
- Restricted Linux Python 3.13: 47 pass and two Windows-specific tests are skipped.
  Lint, format, fixtures, dependency consistency, and non-editable package smoke
  checks pass on both systems. The installed smoke test now exercises an offline
  assistant preview outside the checkout.
- A preview from the real 1,981-file development run selects 40 evidence cases and
  the explicitly included, hash-verified rule snapshot. It sends no network request.
  The actual held-out report is rejected before a request can be made.
- Provider success/error responses in tests are simulated. No live model request
  was made because `OPENAI_API_KEY` is not configured. Model usefulness, latency,
  cost, and detection improvement remain unmeasured.
- Bandit reports no medium/high findings. This is not an independent security audit.

See [ASSISTANT.md](ASSISTANT.md) for configuration and disclosure controls. Earlier
records below describe prior revisions; their counts are historical.

## Update — 23 October 2026

- Windows Python 3.13: all 38 tests pass, including regressions for missing-file
  diagnostics, unavailable logging, and Windows artifact replacement failures.
  Portable lint, formatting, fixtures, installed-package smoke checks, and
  dependency consistency pass.
- Restricted Linux Python 3.13: 36 tests pass; two Windows-specific tests are
  skipped. The remaining portable validation checks pass.
- Restricted Linux Python 3.10 also passes the same 36 tests, two intentional
  skips, and portable checks. Its base image digest is
  `sha256:6ff506466f8b1e981719b468cc0023b8ef000b983cdec0eafe119d01f379e31d`.
  Rebuild with `Dockerfile.validation` and build argument
  `PYTHON_IMAGE=python:3.10-slim@sha256:6ff506466f8b1e981719b468cc0023b8ef000b983cdec0eafe119d01f379e31d`.
- Six README Mermaid diagrams rendered with Mermaid CLI 11.13.0 and were visually
  inspected. Source and SVG copies are under `docs/diagrams/`.
- The pinned GitHub PHP corpus has 2,448 unique real files: 1,981 development and
  467 held out. Successful Linux evaluations had zero scan errors. Windows corpus
  runs had read errors and are excluded from the benchmark.
- Held-out source-label result: TP 51, FN 33, FP 3, TN 380. Recall 60.71%; benign
  FPR 0.783%. This is insufficient for the release policy. Source-derived labels
  and potential related-variant leakage limit interpretation.
- Updated Bandit check has no medium/high findings; this is not independent review.
- Hosted CI remains unverified: the GitHub connection requires reauthentication.
  Changes remain local. No comparative superiority claim is established.

See [datasets/README.md](datasets/README.md) for data location, provenance,
licensing, reproduction, and results. The original record below describes the
earlier revision and smaller installed-software exercises.

This records local evidence, not a production certification or a hosted CI result.

## Application checks

- Windows, Python 3.13: 31 unit/integration tests passed, plus the legacy scanner
  suite, strict fixture gate, lint, format, dependency consistency, and an installed
  package smoke test launched outside the checkout.
- Linux, Python 3.13 in the pinned Docker validation image: the same 31 tests and
  release checks passed. Runtime used UID 10001, no network, a read-only root,
  dropped capabilities, no-new-privileges, 1 GiB RAM, two CPUs, and 128 processes.
- Supervisor tests exercised a hung child, excessive RSS, failed compilation,
  persisted evidence, and package shadowing from an untrusted working directory.
- Exact runtime versions are recorded in `constraints.txt`; Ruff is pinned in
  the development extra. `Dockerfile.validation` pins the Python base digest.

Local logs are retained under ignored `runs/windows-validation.log` and
`runs/linux-validation.log`. The portable entry point is
`python tests/run_validation.py` after installing `.[dev]` with constraints.

## Real-file exercises

- Windows reference corpus: 121 unique files from installed psutil, urllib3, and
  charset-normalizer distributions, including three native extensions. Scanning
  completed without errors or matches. Rule-snapshot replay produced no changes.
- Linux reference corpus: 78 native Python extension modules from the official
  pinned Python image. Scanning completed without errors or matches, with network
  disabled. Detailed run artifacts remain under ignored `runs/linux-native/`.

These are **assumed-benign software references**, not independently adjudicated
security datasets. Neither exercise measures malware recall. Small corpora with
zero observed matches do not establish a low population false-positive rate.
Reports now include two-sided 95% Wilson bounds, and policies can enforce those
bounds in addition to point estimates. Sampling bias and correlated files remain
limitations even when an interval is narrow.

The release policy rejects development-only, insufficiently sized corpora with no
target examples. The policy's example thresholds are an analyst starting point,
not an external industry standard.

## Security automation

- pip-audit 2.10.1 reported no known advisories for the nine pinned runtime
  dependencies at the time of the check. This does not cover unknown flaws or
  guarantee complete native-library advisory coverage.
- Bandit 1.9.4 found no medium/high-severity issues. Low-severity warnings remain
  around intentional subprocess use, legacy exception handling, and test asserts;
  they have not been represented as an independent security audit.
- CI now includes dependency auditing, a medium/high static-analysis gate, and
  the restricted container run in addition to the Windows/Linux test matrix.

## Not established

- Hosted GitHub Actions success on a pushed revision; changes are still local.
- Windows Python 3.10 execution locally (Linux Python 3.10 was verified in the update above).
- Independently labeled malware-family recall or representative held-out FPR.
- Independent penetration testing, sandbox escape resistance, or external review.
- Suitability for a multi-user hosted deployment; the target remains a local CLI.

See `SECURITY.md` and `OPERATIONS.md` before handling untrusted corpora.
