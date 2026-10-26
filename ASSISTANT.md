# Optional LLM analyst assistant

`malyz3r-assist` explains development-run evidence and can suggest a candidate
YARA revision when rule source is explicitly included. It supports OpenAI Responses, Claude Messages, Gemini generateContent and
OpenAI-compatible Chat Completions through the existing `requests` dependency. No LangChain, LangGraph,
model training, autonomous execution, or automatic promotion is involved.

## Preview first

Install the updated package and select a complete workbench development run:

```console
python -m pip install -c constraints.txt .
malyz3r-assist runs/DEVELOPMENT_RUN --model YOUR_MODEL_ID --output runs/advice-preview
```

Replace the placeholders with your run directory and a model ID available to your
API account that supports structured JSON output. A model is deliberately
not selected automatically. The equivalent module command is
`python -m malware_scanner.assistant`.

Without `--send`, the command makes **no network request** and requires no API key.
It writes the exact request structure to `request.json`, a private local
`evidence-map.json`, and `status.json`. Output directories must be new.

The request contains per-rule metrics and up to 40 cases: the first 30 label/match
disagreements and the first 10 correct results in report order. This selection is
not a representative sample. Cases include opaque local evidence IDs, labels,
expected/matched rule IDs, and matched string identifiers—not matched bytes.

Sample contents, sample paths, hashes, provenance strings, and client names are
not copied into the request. Rule identifiers may still disclose rule filenames
or naming conventions; review the complete preview before sending. The private
evidence map links IDs to local sample paths and hashes and is never sent.

## Include rules only when appropriate

Add `--include-rule-source` to include source from the captured `inputs/rules`
snapshot. Every included file must remain within the snapshot root and match the
hash recorded in the evaluation report. Limits are 32 KiB per source and 64 KiB
for all included source text. Large rulesets must be evaluated separately.

Rule comments, metadata, strings, and include contents may disclose sensitive
information. The option sends their actual contents; it is not a redaction tool.
Without rule-source opt-in, the assistant only accepts investigation advice and
rejects generated candidate rules.

## Request advice

Configure the selected provider API key in the process environment through your normal secret
management mechanism. Do not put keys in repository files, command arguments,
reports, or chat messages. Then run with the same model and evidence options:

```console
malyz3r-assist runs/DEVELOPMENT_RUN --model YOUR_MODEL_ID --output runs/advice-result --include-rule-source --send
```

`--send` explicitly transmits the selected evidence to the selected provider and may incur API
charges. Use the same source option in preview and send commands to preview the
same payload. OpenAI Responses requests use `store: false`; this does not by itself guarantee
zero provider retention. Account policies and provider data controls still apply.

Native provider endpoints are fixed. Custom endpoints require the compatible provider.
No model tools are enabled.
Requests have connection/read timeouts, a 128 KiB payload cap, a 4,000-token output
budget, a 1 MiB response cap, and no automatic retries. Redirects are rejected.
Timeouts can still occur after a provider has incurred work; do not assume retrying
is free. API keys are not written to artifacts.

The response uses a strict JSON schema and is also validated locally. Refusals,
incomplete output, malformed fields, missing limitations, and findings that cite
unknown evidence IDs fail the operation. Valid references establish traceability,
not the truth of the model's explanations. Report split fields are trusted analyst
assertions: the application cannot detect someone falsely relabeling a held-out run.

## Review and test proposals

Successful advice produces `advice.json` and, when supplied, `candidate.yar.txt`.
The status is **`advice_unvalidated`**, never “approved.” Candidates are not
compiled or scanned automatically and are not placed in an active rules directory.
The original report, labels, policies, and rules are unchanged.

An analyst should inspect the proposal, preserve required rule IDs, and place an
accepted candidate in a separate rules directory. Use the existing workbench to
compile, evaluate on development data, and compare with a baseline. Obtain fresh
independent evidence before promotion; do not tune on previously inspected
held-out results. Compilation success alone says nothing about detection quality.

All input samples must have known labels, successful scans, and the `development`
split. Incomplete reports/inventories, held-out data, mixed partitions, and
unspecified splits are rejected before any network request.

Exit 0 means a preview or advice artifact was produced, not that a candidate is
correct. Exit 2 means invalid input, unavailable configuration, provider failure,
or invalid advice. Inspect `status.json` for persisted failures after preparation.

## Validation boundary

The integration has offline tests for privacy selection, split enforcement,
snapshot verification, transport behavior, schema/citation validation, and
inactive candidate handling. HTTP responses in tests are simulated and clearly
identified as such; they do not establish model quality or live account access.
An offline preview was produced from the actual 1,981-file PHP development run.
No live API call was made because `OPENAI_API_KEY` was not configured.

The next empirical step is to compare analyst-reviewed AI proposals against the
same development baseline, then use fresh independent evaluation data. No recall
improvement, time saving, or production-readiness claim is made for this feature.

API references: [Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)
and [Responses API](https://developers.openai.com/api/reference/resources/responses/methods/create).

## Provider selection

OpenAI is the default. Available providers and environment variables:

- `--provider openai`: `OPENAI_API_KEY`.
- `--provider anthropic`: `ANTHROPIC_API_KEY` (Claude Messages).
- `--provider gemini`: `GEMINI_API_KEY`; use a bare model ID without `models/`.
- `--provider openai-compatible`: `MALYZ3R_COMPAT_API_KEY` and `--base-url`.

```console
malyz3r-assist runs/DEVELOPMENT_RUN --provider anthropic --model YOUR_CLAUDE_MODEL --output runs/claude-preview
malyz3r-assist runs/DEVELOPMENT_RUN --provider gemini --model YOUR_GEMINI_MODEL --output runs/gemini-preview
malyz3r-assist runs/DEVELOPMENT_RUN --provider openai-compatible --base-url https://YOUR_HOST/v1 --model VENDOR/MODEL --output runs/compatible-preview
```

Add `--send` after inspecting the preview. Each provider uses its own key; OpenAI
credentials are never reused for another endpoint. Compatible services must support
Chat Completions with `response_format.type=json_schema`. This does not mean every
LLM service works. Unsupported models fail visibly; no fallback provider or silent
downgrade to unstructured output is used.

Custom base URLs include the API prefix (usually `/v1`); `/chat/completions` is
appended. HTTPS is required except for loopback HTTP, such as
`http://127.0.0.1:8000/v1`. URL credentials, query strings and fragments are rejected.
For an unauthenticated local server, set `MALYZ3R_COMPAT_API_KEY` to a non-secret
placeholder such as `local-unused`. Only do this if the server needs no authentication.
Choose a trusted endpoint: configuration authorizes transmitting evidence there.

See [MCP.md](MCP.md) to use your IDE's model without another application API key.
Provider implementations follow [OpenAI structured output](https://developers.openai.com/api/docs/guides/structured-outputs),
[Claude structured output](https://platform.claude.com/docs/en/build-with-claude/structured-outputs)
and [Gemini generateContent](https://ai.google.dev/api/generate-content).
