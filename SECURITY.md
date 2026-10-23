# Security model and validation boundaries

malyz3r is a single-user local analyst application. File contents are scanned
as data, but native YARA and file-parsing dependencies remain attack surfaces.
Do not run untrusted rules or malware collections on a privileged workstation.

## Controls implemented

- Worker launch uses Python isolated mode and the explicitly selected package
  directory. A sample folder cannot substitute a same-named Python package.
  The interpreter's configured user-site dependency directory is retained when
  the parent uses a user-level installation; arbitrary PYTHONPATH is not inherited.
- Worker wall-clock and RSS monitoring, Unix address-space limits, bounded sample
  reads, and engine timeouts contain ordinary crashes and resource overruns.
- Includes remain inside the selected rule root. Compiled source bytes and
  included dependencies are fingerprinted and preserved in each run.
- Reports distinguish errors from nonmatches; unknown labels are not negatives.
- HTML output escapes input strings and CSV export neutralizes formula prefixes.
- The launcher never updates or pulls code automatically.

These controls do not make the native worker a security sandbox. The worker has
the analyst's permissions. Windows memory monitoring can briefly overshoot the
budget; disk operations and enumeration can block. Use an isolated VM, a
restricted account, and network/filesystem controls for adversarial material.

## Reproducible checks

`constraints.txt` records the runtime versions used during validation. Install
with `python -m pip install -c constraints.txt ".[dev]"` for that environment.
Version pins are not package hashes or a complete supply-chain verification;
review and update them through CI rather than freezing vulnerable versions.

GitHub Actions includes runtime-dependency auditing and a medium/high-severity
Bandit gate. Low-severity subprocess and legacy scanner warnings still need
contextual review; absence of findings is not proof of safety. Advisory data can
be incomplete, especially for native libraries. No independent penetration test
or external security certification has been completed.

The Docker validation runner executes as UID 10001 with no network, a read-only
filesystem, dropped capabilities, no-new-privileges, and bounded CPU, RAM, and
process count. Only `/tmp` is writable during the standard test run. This
validates a constrained deployment profile; it does not prove sandbox escape
resistance. The image is for validation, not unrestricted malware detonation.

Keep private samples, manifests, run reports, and client identifiers out of public
Git history. Reports contain local paths and hashes. No sample-upload capability
is required by the lab; the optional VirusTotal feature queries hashes only.
