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

## Optional LLM advice

The assistant is preview-only unless explicitly invoked with `--send`. Requests
contain selected development metrics and case identifiers; rule source requires
separate opt-in. Sample bytes, sample paths, hashes, and provenance fields are
excluded from requests. Rule names and explicitly included rule text can still
be sensitive. Review the saved request and applicable provider data policies.

The model has no tools or execution privileges. Structured output, reference
checks, and input separation improve handling but do not prove prompt-injection
resistance or factual accuracy. Candidate text remains inactive and unvalidated.
Split validation relies on the report's asserted labels; it cannot independently
detect fabricated report metadata. See [ASSISTANT.md](ASSISTANT.md).


## MCP and provider boundaries

MCP defaults to a local stdio evidence reader. Returning evidence to an IDE can
still disclose it to that IDE's model; the no-provider-network default applies
only to this server. Paths are confined to the configured workspace. Enabling
`--allow-network` exposes a provider tool that also requires `confirm_send=true`;
that flag is not proof of a human approval. Use the IDE's approval controls.
Provider/model/endpoint configuration is fixed at startup. Each provider uses a
separate credential variable. Compatible endpoints require HTTPS except loopback
HTTP and never receive another provider's key automatically. This server is for
a trusted local analyst workstation, not hostile multi-tenant use. See [MCP.md](MCP.md).


## Auxiliary scanner hardening

VirusTotal hash lookups reject redirects and oversized/malformed responses and
return failure on missing credentials or unreadable files. Configuration validates
parallelism at load time, updates atomically, and omits inherited VirusTotal keys
when saved. Invalid config is reported instead of silently replaced with defaults.
File investigation reads at most 1 MiB and displays bounded printable strings and
256 bytes of hex. ExifTool has a 30-second deadline and monitored 1 MiB output cap;
its temporary output can briefly exceed the cap between checks. These controls
are not a sandbox for the external/native parser. File-type detection reads a
64 KiB prefix. PE certificate-table presence does not verify a signature or trust.
