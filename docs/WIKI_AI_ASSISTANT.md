# AI Assistant Documentation — Multi-Provider LLM Integration

## Overview

`malyz3r-assist` is an optional, development-only LLM analyst assistant that explains development-run evidence and can suggest candidate YARA revisions when rule source is explicitly included. It supports multiple providers through structured JSON output with strict privacy controls.

**Key Principles:**
- Preview-first workflow (zero network calls by default)
- Strict data sanitization (no sample bytes, paths, or hashes sent)
- Split isolation (held-out data is blocked)
- Unvalidated output (candidates require human review)
- No automatic promotion or execution

---

## Supported Providers

| Provider | Environment Variable | API Reference | Python Version |
| :--- | :--- | :--- | :--- |
| **OpenAI** | `OPENAI_API_KEY` | [Responses API](https://developers.openai.com/api/reference/resources/responses/methods/create) | 3.10+ |
| **Anthropic Claude** | `ANTHROPIC_API_KEY` | [Claude Messages](https://platform.claude.com/docs/en/build-with-claude/structured-outputs) | 3.10+ |
| **Google Gemini** | `GEMINI_API_KEY` | [generateContent](https://ai.google.dev/api/generate-content) | 3.10+ |
| **OpenAI-Compatible** | `MALYZ3R_COMPAT_API_KEY` | Custom endpoint via `--base-url` | 3.10+ |
| **Ollama / vLLM** | `MALYZ3R_COMPAT_API_KEY` | Local instance via compatible endpoint | 3.10+ |

---

## Quick Start

### 1. Install with MCP Support (Optional)

```bash
python -m pip install -c constraints.txt ".[mcp]"
```

The MCP server requires Python 3.11+. Core commands support Python 3.10+.

### 2. Preview Mode (Zero Network Calls)

Generate a sanitized preview before any API calls:

```bash
malyz3r-assist runs/DEVELOPMENT_RUN --model gpt-4o --output runs/advice-preview
```

This writes:
- `request.json` — Exact request structure
- `evidence-map.json` — Private local evidence map (never sent)
- `status.json` — Operation status

**No network request is made.** No API key is required.

### 3. Send to Provider

After reviewing the preview, send to your chosen provider:

```bash
# OpenAI
export OPENAI_API_KEY="sk-..."
malyz3r-assist runs/DEVELOPMENT_RUN --model gpt-4o --output runs/advice-result --send

# Anthropic Claude
export ANTHROPIC_API_KEY="sk-ant-..."
malyz3r-assist runs/DEVELOPMENT_RUN --provider anthropic --model claude-3-5-sonnet-20241022 --output runs/advice-result --send

# Google Gemini
export GEMINI_API_KEY="..."
malyz3r-assist runs/DEVELOPMENT_RUN --provider gemini --model gemini-1.5-pro --output runs/advice-result --send

# Local Ollama
malyz3r-assist runs/DEVELOPMENT_RUN --provider openai-compatible \
  --base-url "http://localhost:11434/v1" --model llama3 --output runs/advice-result --send
```

---

## Privacy Controls

### What IS Sent to LLM

- Per-rule metrics (TP, FP, TN, FN, recall, precision, F1, benign FPR)
- Up to 40 selected cases:
  - First 30 label/match disagreements
  - First 10 correct results (in report order)
- Opaque local evidence IDs
- Labels and expected/matched rule IDs
- Matched string identifiers (not matched bytes)
- Rule source text (only with `--include-rule-source`)

### What is NOT Sent

- Sample contents (raw bytes)
- Sample file paths
- Sample SHA256 hashes
- Provenance strings
- Client names
- Private evidence map

### Split Isolation

The assistant **rejects** runs containing:
- Held-out data
- Mixed partitions
- Unspecified splits
- Incomplete reports/inventories
- Unknown labels

Only **development split** runs are permitted for AI assistance.

---

## Including Rule Source

### When to Include

Include rule source when:
- You need the LLM to suggest concrete YARA syntax changes
- Rule identifiers alone are insufficient context
- You have reviewed the rule contents for sensitive information

### When NOT to Include

Do not include rule source when:
- Rules contain sensitive strings (C2 domains, internal infrastructure names)
- You only need investigation advice (not rule edits)
- The ruleset is large (exceeds 64 KiB total)

### Limits

- **Per source**: 32 KiB
- **Total all sources**: 64 KiB
- Large rulesets must be evaluated separately

### Command

```bash
malyz3r-assist runs/DEVELOPMENT_RUN --model gpt-4o \
  --output runs/advice-preview --include-rule-source
```

---

## Response Schema

The assistant uses a strict JSON schema validated both by the provider and locally:

```json
{
  "summary": "string",
  "findings": [
    {
      "evidence_ids": ["string"],
      "explanation": "string",
      "suggestion": "string"
    }
  ],
  "candidate_yara": "string | null"
}
```

### Validation Rules

- Refusals fail the operation
- Incomplete output fails the operation
- Malformed fields fail the operation
- Missing limitations fail the operation
- Findings citing unknown evidence IDs fail the operation
- `candidate_yara` must be `null` when rule source is not included

---

## Review and Testing Workflow

### 1. Preview Request

```bash
malyz3r-assist runs/DEVELOPMENT_RUN --model gpt-4o --output runs/advice-preview
```

Review:
- `request.json` — Check for any unexpected data
- Evidence selection — Verify the 40 cases are appropriate
- Rule source (if included) — Check for sensitive information

### 2. Send to Provider

```bash
malyz3r-assist runs/DEVELOPMENT_RUN --model gpt-4o \
  --output runs/advice-result --send --include-rule-source
```

### 3. Review Response

Inspect:
- `advice.json` — Structured findings and summary
- `candidate.yar.txt` — Unvalidated candidate rule (if generated)
- `status.json` — Operation status

### 4. Test Candidate

```bash
# Place candidate in separate rules directory
cp runs/advice-result/candidate.yar.txt rules/candidate/webshell.yar

# Evaluate on development data
malyz3r-workbench run manifests/development.json \
  --rules rules/candidate --runs-dir runs/candidate-test

# Compare with baseline
malyz3r-workbench compare runs/baseline/report.json \
  runs/candidate-test/report.json --output comparison.json
```

### 5. Validate on Fresh Data

**Critical**: Do not tune on held-out data. Use fresh independent evaluation data for final validation.

```bash
malyz3r-workbench run manifests/held_out.json \
  --rules rules/candidate --runs-dir runs/candidate-validation \
  --policy policies/production.json
```

---

## Exit Codes

| Exit Code | Meaning |
| :--- | :--- |
| **0** | Preview or advice artifact produced (not that candidate is correct) |
| **2** | Invalid input, unavailable configuration, provider failure, or invalid advice |

Inspect `status.json` for persisted failures after preparation.

---

## Provider-Specific Notes

### OpenAI

- Uses OpenAI Responses API with `store: false`
- Does not by itself guarantee zero provider retention
- Account policies and provider data controls still apply
- Structured outputs via JSON schema

### Anthropic Claude

- Uses Claude Messages API
- Requires `ANTHROPIC_API_KEY` environment variable
- Structured outputs enabled
- No automatic retries

### Google Gemini

- Uses generateContent API
- Use bare model ID without `models/` prefix
- Requires `GEMINI_API_KEY` environment variable
- Structured outputs via JSON schema

### OpenAI-Compatible (Ollama, vLLM, etc.)

- Custom endpoint via `--base-url`
- Base URL must include API prefix (usually `/v1`)
- HTTPS required except loopback HTTP (e.g., `http://127.0.0.1:8000/v1`)
- URL credentials, query strings, and fragments are rejected
- For unauthenticated local server, set `MALYZ3R_COMPAT_API_KEY` to placeholder (e.g., `local-unused`)
- Endpoint must support Chat Completions with `response_format.type=json_schema`

---

## Request Limits

- **Payload cap**: 128 KiB
- **Output budget**: 4,000 tokens
- **Response cap**: 1 MiB
- **Connection timeout**: Configured
- **Read timeout**: Configured
- **Automatic retries**: None (disabled)

Timeouts can still occur after a provider has incurred work. Do not assume retrying is free.

---

## MCP Integration

For IDE integration without another application API key, see [MCP.md](../MCP.md).

The MCP server:
- Defaults to local stdio evidence reader (no network)
- Can enable provider tool with `--allow-network --model <ID>`
- Requires `confirm_send=true` for network requests
- Confines paths to configured workspace
- Configuration fixed at startup (provider/model/endpoint)

---

## Validation Boundary

The integration has offline tests for:
- Privacy selection
- Split enforcement
- Snapshot verification
- Transport behavior
- Schema/citation validation
- Inactive candidate handling

HTTP responses in tests are simulated and clearly identified. They do not establish:
- Model quality
- Live account access
- Production readiness

An offline preview was produced from the actual 1,981-file PHP development run with no live API call.

---

## Limitations and Warnings

### NOT Protected Against

- Prompt injection attacks
- Model hallucinations
- Factual inaccuracies
- Provider data retention (beyond `store: false`)
- Account policy violations

### What It Does NOT Do

- Execute code
- Automatically promote rules
- Compile or scan candidates
- Access held-out data
- Modify labels or policies
- Infer ground truth
- Claim production readiness

### Validation Status

- **No live model request was made** during validation (API keys not configured)
- **Model usefulness, latency, cost, and detection improvement remain unmeasured**
- **No comparative superiority claim is established**
- **See [VALIDATION.md](../VALIDATION.md) for dated validation record**

---

## API References

- [OpenAI Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)
- [OpenAI Responses API](https://developers.openai.com/api/reference/resources/responses/methods/create)
- [Claude Structured Output](https://platform.claude.com/docs/en/build-with-claude/structured-outputs)
- [Gemini generateContent](https://ai.google.dev/api/generate-content)

---

**Related Documentation:**
- [MCP.md](../MCP.md) — IDE integration
- [SECURITY.md](../SECURITY.md) — Security boundaries
- [README.md](../README.md#3-multi-provider-ai-assistant-malyz3r-assist) — CLI interface

**Last Updated**: 26 October 2026
