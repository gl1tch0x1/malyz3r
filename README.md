# malyz3r — YARA Rule Engineering Workbench & Threat Detection Assurance Platform

<p align="center">
  <a href="https://deepwiki.com/gl1tch0x1/malyz3r"><img src="https://deepwiki.com/badge.svg" alt="Ask DeepWiki"></a>
  <a href="tests/"><img src="https://img.shields.io/badge/tests-72%20local%20checks-brightgreen.svg" alt="Validation Suite" /></a>
  <a href="malware_scanner/rules/"><img src="https://img.shields.io/badge/YARA%20Rules-66%20files%20%7C%2069%20detectors-blue.svg" alt="YARA Rules" /></a>
  <a href="docs/MCP.md"><img src="https://img.shields.io/badge/MCP-FastMCP%202.3.0-orange.svg" alt="MCP Server" /></a>
  <a href="pyproject.toml"><img src="https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg" alt="Python Version" /></a>
  <a href="pyproject.toml"><img src="https://img.shields.io/badge/code%20style-ruff-000000.svg" alt="Code Style" /></a>
  <a href="pyrightconfig.json"><img src="https://img.shields.io/badge/type%20checking-pyright%20strict-blueviolet.svg" alt="Type Checking" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT" /></a>
</p>

---

## Executive Summary

**malyz3r** is an enterprise-grade detection engineering framework, empirical static analysis workbench, and local detection assurance platform designed specifically for **threat hunters**, **security researchers**, and **DFIR analysts**. 

Traditional YARA rule deployment frequently suffers from critical operational failure modes: signatures written against single samples without regression testing, deceptive "100% precision" claims on statistically underpowered datasets, unmonitored regex backtracking hangs, and accidental data exposure when leveraging LLMs for rule authoring.

`malyz3r` treats detection engineering as an empirical, test-driven discipline:
- **Local Detection Assurance Workspace**: An authenticated, zero-external-dependency web console providing real-time evaluation analytics, an interactive force-directed relationship graph, and machine-enforceable release gates.
- **Statistical Rigor**: Replaces point estimates with **two-sided 95% Wilson score binomial confidence intervals** on all precision, recall, and false positive metrics.
- **Subprocess Isolation & Supervision**: Executes YARA evaluations in isolated worker processes guarded by wall-clock watchdog timers and resident memory (RSS) caps.
- **Split Isolation & Manifest Governance**: Enforces strict separation between `development` samples (used for iterative tuning) and `held-out` samples (quarantined strictly for release gating).
- **FastMCP 2.3.0 IDE Server**: Native Model Context Protocol server exposing sanitized workspace telemetry to AI-assisted coding environments (Cursor, Claude Desktop, Antigravity) with zero raw binary exfiltration.
- **Curated Threat Catalog**: 66 battle-tested YARA rule files housing 69 discrete detectors mapped against MITRE ATT&CK tactics, nation-state APTs, ransomware, wipers, and stealers.

---

## Table of Contents

- [The Detection Engineering Problem](#the-detection-engineering-problem)
- [System Architecture & Isolation Boundaries](#system-architecture--isolation-boundaries)
- [Comprehensive Documentation Hub (`docs/`)](#comprehensive-documentation-hub-docs)
- [Local Detection Assurance Workspace (`malyz3r-web`)](#local-detection-assurance-workspace-malyz3r-web)
- [Evidence Model & Interactive Detection Map](#evidence-model--interactive-detection-map)
- [Supervisor Execution Protocol & Worker Boundary](#supervisor-execution-protocol--worker-boundary)
- [Sample Classification & Statistical Rigor](#sample-classification--statistical-rigor)
- [Quality Gate Policies & Release Decisions](#quality-gate-policies--release-decisions)
- [The 7-Phase Detection Engineering Lifecycle](#the-7-phase-detection-engineering-lifecycle)
- [Comprehensive Threat Detection Catalog (66 Files / 69 Detectors)](#comprehensive-threat-detection-catalog-66-files--69-detectors)
- [Corpus Manifest Schema & Split Governance](#corpus-manifest-schema--split-governance)
- [Multi-Provider AI Assistant (`malyz3r-assist`)](#multi-provider-ai-assistant-malyz3r-assist)
- [FastMCP IDE Integration (`malyz3r-mcp`)](#fastmcp-ide-integration-malyz3r-mcp)
- [Interactive Threat Hunting CLI & Direct Lab](#interactive-threat-hunting-cli--direct-lab)
- [Continuous Linux Security Monitoring & Background Service](#continuous-linux-security-monitoring--background-service)
- [Multi-Stage Static Analysis Pipeline](#multi-stage-static-analysis-pipeline)
- [AI-Assisted Investigation Service with Untrusted Prompt Fencing](#ai-assisted-investigation-service-with-untrusted-prompt-fencing)
- [Deep Triage HUD & Shannon Entropy Spectrum](#deep-triage-hud--shannon-entropy-spectrum)
- [Controlled AI Learning, Analyst Feedback & Rule Promotion](#controlled-ai-learning-analyst-feedback--rule-promotion)
- [Installation & Environment Setup](#installation--environment-setup)
- [Docker Packaging & Corpus Persistence](#docker-packaging--corpus-persistence)
- [Automated Testing & CI/CD Verification](#automated-testing--cicd-verification)
- [Repository Structure](#repository-structure)
- [Honest Disclaimers & Operational Boundaries](#honest-disclaimers--operational-boundaries)
- [License & Attribution](#license--attribution)

---

## The Detection Engineering Problem

Static signature engineering faces four core operational pitfalls:

```
[Ad-Hoc Authoring]               [malyz3r Test-Driven Engineering]
Single sample inspection   -->   Cryptographic corpus manifests & provenance
Subjective rule tuning     -->   Supervised subprocess workers with memory & time caps
Deceptive point metrics    -->   Two-sided 95% Wilson score confidence intervals
Silent FP regressions     -->   Automated regression diffs & machine release policies
Prompt data leakage        -->   Sanitized evidence schemas & held-out split isolation
```

1. **Small-Corpus Sampling Bias**: A rule tested against 8 positive samples achieving 8 matches is commonly reported as "100% recall." In reality, with $n=8$, the 95% confidence interval spans $[67.6\%, 100\%]$. Deploying rules without interval bounds creates catastrophic blind spots.
2. **Regression Blindness**: Relaxing strings or regexes to detect evasive malware variants frequently causes silent false-positive explosions against benign enterprise software.
3. **Engine Hangs & Resource Exhaustion**: Pathological regular expressions or packed binaries can trigger catastrophic backtracking, freezing the scanner or causing out-of-memory kernel termination.
4. **Data Contamination in AI Refinement**: Sending proprietary malware binaries or validation datasets to cloud LLMs violates OPSEC and leaks sensitive incident data.

---

## System Architecture & Isolation Boundaries

`malyz3r` enforces strict separation between untrusted sample ingestion, supervised subprocess execution, statistical analytics, release policy enforcement, and IDE telemetry:

```mermaid
flowchart TB
    subgraph Interfaces ["Analyst Interfaces"]
        Browser["Local Web Workspace<br/>malyz3r-web (Loopback API)"]
        WB["Operational Workbench<br/>malyz3r-workbench (Supervisor)"]
        Direct["Direct Lab Engine<br/>malyz3r-lab (CI/CD Runner)"]
        MCP["IDE Telemetry Server<br/>malyz3r-mcp (FastMCP 2.3.0)"]
        Assist["Sanitized AI Assistant<br/>malyz3r-assist (Multi-Provider)"]
        CLI["Threat Hunting CLI<br/>malyz3r (Memory / File)"]
    end

    subgraph Ingestion ["Corpus Ingestion & Data Splitting"]
        Corpus[(Raw Samples)] --> Inventory["corpus.py: Inventory & Hashes"]
        Inventory --> Manifest["Manifest JSON: SHA256 & Provenance"]
        Manifest --> SplitDev["Development Split<br/>Permitted for Tuning & AI"]
        Manifest --> SplitHeld["Held-Out Split<br/>Quarantined for Release Gating"]
    end

    subgraph Supervisor ["Subprocess Supervisor Boundary"]
        Browser --> Sup["workbench.py: Supervisor Watchdog"]
        WB --> Sup
        Sup -->|Spawn Subprocess| Worker["worker.py: Isolated Python Subprocess"]
        Direct --> Worker
        Worker --> Compiler["Strict YARA Compiler"]
        Rules[(66 Rule Files)] --> Compiler
        Compiler --> Engine["Native yara-python Engine"]
        SplitDev --> Engine
        SplitHeld --> Engine
    end

    subgraph Analytics ["Analytics & Quality Governance"]
        Engine --> Stream["Streaming Progress Journal"]
        Stream --> Stats["statistics.py: Wilson Score 95% CIs"]
        Stats --> Report["Evaluation Report JSON"]
        Report --> Assurance["assurance.py: Release Policy Engine"]
        Report --> Exports["artifacts.py: JSON, CSV, Sanitized HTML"]
    end

    subgraph Privacy ["Privacy & Sanitization Boundary"]
        SplitDev -. Development Evidence .-> Assist
        SplitHeld -.-x|BLOCKED| Assist
        Assist --> LLM["LLM Provider (OpenAI / Claude / Gemini / Ollama)"]
        LLM --> Draft["Unvalidated candidate.yar.txt"]
        Report -. Confined Telemetry .-> MCP
    end

    classDef interface fill:#142b36,stroke:#5cae9a,color:#e5f5ef;
    classDef supervisor fill:#18302b,stroke:#6bb69e,color:#effff8;
    classDef storage fill:#282536,stroke:#a592cf,color:#f1eaff;
    class Browser,WB,Direct,MCP,Assist,CLI interface;
    class Sup,Worker,Compiler,Engine supervisor;
    class Corpus,Manifest,Rules,Report,Exports,Draft storage;
```

---

## Comprehensive Documentation Hub (`docs/`)

All technical specifications, operational runbooks, AI assistant guides, and architectural deep-dives are organized in the [`docs/`](docs/) directory:

| Document | Focus & Target Audience | Core Topics Covered |
| :--- | :--- | :--- |
| [**`docs/OPERATIONS.md`**](docs/OPERATIONS.md) | **SOC Engineers & System Administrators** | Daemon installation, systemd sandboxing (`ProtectSystem=full`), backpressure monitoring, and live operational triage playbooks. |
| [**`docs/ASSURANCE.md`**](docs/ASSURANCE.md) | **Detection Engineers & Researchers** | Two-sided 95% Wilson score confidence bounds, false-positive budget gates, holdout data governance, and empirical calibration models. |
| [**`docs/ASSISTANT.md`**](docs/ASSISTANT.md) | **AI Engineers & Security Architects** | Multi-provider LLM integrations (OpenAI, Anthropic Claude, Google Gemini, Ollama), untrusted prompt fencing, and offline fallbacks. |
| [**`docs/MCP.md`**](docs/MCP.md) | **Developers & Threat Hunters** | FastMCP 2.3.0 stdio server, IDE integration with Cursor, Claude Desktop, Antigravity, and non-exfiltrating sanitized schemas. |
| [**`docs/LAB.md`**](docs/LAB.md) | **CI/CD Engineers & Automation Teams** | Headless CLI validation runner, reproducible manifest fixtures, memory bounds, and automated release policy regression checks. |
| [**`docs/VALIDATION.md`**](docs/VALIDATION.md) | **QA & Compliance Analysts** | Comprehensive 72-test verification suite, static Pyright type certification matrix, and Playwright browser regression harness. |
| [**`docs/WIKI.md`**](docs/WIKI.md) | **Full Technical Deep Dive** | Architectural encyclopedia covering token security, kernel audit hooks (`kauditd`), inotify debouncing, and SQLite persistence. |
| [**`docs/images/`**](docs/images/) | **Visual UI Gallery** | High-resolution captures of the continuous monitor, deep triage HUD, detection relationship map, and benchmark runs. |

---

## Local Detection Assurance Workspace (`malyz3r-web`)

The `malyz3r-web` interface runs entirely locally over an authenticated loopback connection (`http://127.0.0.1:8765/`). Built with modern bundled HTML5, CSS3 glassmorphism, JavaScript ES2024, and SVG, it requires zero external CDNs, build steps, or cloud infrastructure.

```bash
# Launch the local assurance console
malyz3r-web --workspace . --catalog workspace.example.json --port 8765
```

### 1. Continuous Security Monitoring & Real-Time Telemetry Cockpit

<p align="center">
  <img src="docs/images/continuous-security-monitoring.png" alt="malyz3r Continuous Security Monitoring Cockpit" width="95%" />
</p>

- **DEFCON Posture Banner**: Live status indicator displaying current defense posture, kernel hook integration (`kauditd` / `netlink`), and inotify/fanotify debounce stability.
- **Telemetry HUD Cards**: Real-time state metrics tracking Core Monitor daemon status, Kernel Audit Telemetry syscall counters, Queue & Backpressure health, Reconciliation integrity, and Active threat interceptions.
- **Live Process & Inotify Execution Stream**: Chronological execution trace highlighting newly detected filesystem events, file touches, and execution spikes with one-click **Triage Alert** actions.
- **Configured Monitored Locations**: Dynamic path configuration allowing analysts to add watchpaths (e.g. `/tmp`, `/usr/bin`, `/etc/cron.d`) with instant synchronization.

### 2. Evaluation Runs & Detection Benchmark Workbench

<p align="center">
  <img src="docs/images/evaluations-benchmark-runs.png" alt="malyz3r Evaluation Runs and Benchmarks Workbench" width="95%" />
</p>

- **Docked Benchmark Context Toolbar**: Sleek dark-glass toolbar replacing legacy emojis with crisp SVG vector icons (`radar crosshair` for Baseline Reference, `activity pulse` for Candidate Under Test, and `refresh loop` for Sync Runs). Pinned flush to the top layout to eliminate vertical centering gaps.
- **Single-Vector Navigation Iconography**: High-contrast, tactical sidebar with exactly one vector glyph per navigation element, eliminating duplicate icons.
- **Zero-Barrier Loopback Authentication**: Automatic loopback token handshake (`window.__MALY_TOKEN__`) injected via secure CSP (`script-src 'self' 'unsafe-inline'`), providing immediate access without 401 connection stalls.
- **High-Tech Form Controls**: Glassmorphic cyber dropdowns and buttons with custom cyan chevrons, hover glows, and responsive micro-interactions.

---

## Evidence Model & Interactive Detection Map

In `malyz3r`, detection relationships are modeled as strict empirical evidence. A YARA rule match is an observed relationship to an individual sample byte sequence. It does not warrant an unverified claim that the rule detects an entire malware family:

```mermaid
flowchart LR
    R["YARA Rule<br/>Rule ID & File"] -->|"Observed Match"| S["Evaluated Sample<br/>Outcome & Scan Status"]
    S -->|"Recorded Identity"| H["SHA-256 Digest"]
    S -.->|"Dataset Annotation"| F["Family Label"]
    S -->|"Static Extraction"| T["File Metadata"]
    S --> D["Evidence Inspector<br/>Expected Rules & Matches"]

    classDef observed fill:#122e2c,stroke:#67c8ac,color:#e6fff7;
    classDef annotation fill:#2a2439,stroke:#b49ad6,color:#f3eaff;
    class R,S,H,D observed;
    class F,T annotation;
```

<p align="center">
  <img src="docs/images/detection-map.png" alt="malyz3r Interactive Detection Relationship Map" width="95%" />
</p>

### Graph Explorer Capabilities:
- **Multi-Node Tier Filtering**: Dynamically toggle between Family annotations, compiled Rule detectors, evaluated Samples, and cryptographic SHA-256 Indicators.
- **Strict Evidence Edge Semantics**: Solid lines represent observed scan matches and hash identities; dashed lines indicate analyst-supplied ground truth metadata.
- **High-Performance Rendering**: Paginated (up to 50 samples per view) with strict caps (500 nodes, 1,000 edges) to guarantee fluid rendering on constrained field hardware.
- **Deep Provenance Drawer**: Selecting any node opens recorded details, evaluated sample counts, detected target counts, missed targets, and observed rule IDs.

---

## Supervisor Execution Protocol & Worker Boundary

To guarantee that untrusted binaries or catastrophic regex backtracking cannot compromise evaluation pipelines, `malyz3r` executes all YARA scans inside an isolated subprocess monitored by an active watchdog supervisor:

```mermaid
sequenceDiagram
    actor Analyst as Analyst / Web UI
    participant S as Workbench Supervisor
    participant D as Local Run Directory
    participant W as Worker Process (Python)
    participant E as Evaluator & Native YARA

    Analyst->>S: Run manifest, rules, limits (--wall-seconds, --memory-mb)
    S->>D: Write request.json, policy.json, status: running
    S->>W: Launch isolated worker subprocess
    W->>E: Validate manifest schema and compile rule snapshot
    E->>D: Persist input snapshots (manifest.json, rules_snapshot/)
    loop Each Sample in Manifest
        E->>E: Bounded read, compute SHA-256, timed scan
        E->>D: Stream progress journal entry
        S->>W: Watchdog check: poll elapsed wall-time & RSS memory
        alt Limits Exceeded (Timeout or OOM)
            S->>W: SIGKILL worker subprocess immediately
            S->>D: Write status: timed_out or resource_limit
        end
    end
    W->>D: Write report.json and resolved_manifest.json
    W-->>S: Exit status code
    S->>S: Verify completion and evaluate quality policy
    S->>D: Export artifacts (JSON, CSV, HTML)
    S-->>Analyst: Final run status and exit code
```

### Subprocess Run Lifecycle State Machine

Every execution run transitions deterministically through well-defined lifecycle states:

```mermaid
stateDiagram-v2
    [*] --> running: Run directory initialized
    running --> completed: Full evaluation completed; policy passed
    running --> rejected: Complete evaluation completed; policy failed
    running --> incomplete: Evaluation incomplete; scan errors present
    running --> timed_out: Worker exceeded --wall-seconds deadline
    running --> resource_limit: Worker RSS memory exceeded --memory-mb
    running --> failed: Native compiler crash or operational error
    running --> cancelled: Analyst user interrupt (SIGINT)
    completed --> [*]
    rejected --> [*]
    incomplete --> [*]
    timed_out --> [*]
    resource_limit --> [*]
    failed --> [*]
    cancelled --> [*]
```

---

## Sample Classification & Statistical Rigor

### Ground-Truth Metric Decision Flow

Every sample scan is classified through a rigorous decision tree to ensure that unknown labels, scan timeouts, and unexpected rule matches are never miscounted as clean negatives:

```mermaid
flowchart TD
    Result["Sample Scan Result"] --> Valid{"Scan Succeeded?"}
    Valid -->|"No (Error / Timeout)"| Incomplete["Mark Scan Incomplete<br/>Exclude from Clean TN"]
    Valid -->|"Yes"| Known{"Known Ground Truth?"}
    Known -->|"No (Unknown Label)"| Unscored["Unscored Observation<br/>Preserve in Journal"]
    Known -->|"Yes"| Expected{"Rule Expected on Target?"}
    Expected -->|"Yes (Target Sample)"| MatchPositive{"Rule Matched?"}
    MatchPositive -->|"Yes"| TP["True Positive (TP)"]
    MatchPositive -->|"No"| FN["False Negative (FN)"]
    Expected -->|"No (Benign Control)"| MatchNegative{"Rule Matched?"}
    MatchNegative -->|"Yes"| FP["False Positive (FP)"]
    MatchNegative -->|"No"| TN["True Negative (TN)"]

    TP --> Stats["Wilson Score 95% Confidence Intervals"]
    FN --> Stats
    FP --> Stats
    TN --> Stats
    Stats --> PolicyGate{"Quality Policy Gate"}
    Incomplete --> PolicyGate

    classDef pass fill:#173c30,stroke:#6cc7a2,color:#e8fff3;
    classDef fail fill:#3b222b,stroke:#db8798,color:#ffedf1;
    classDef triage fill:#383022,stroke:#d0af73,color:#fff4de;
    class TP,TN pass;
    class FP,FN fail;
    class Incomplete,Unscored triage;
```

### Wilson Score Binomial Confidence Intervals

`malyz3r` automatically calculates **two-sided 95% Wilson score intervals** for all metric ratios:

$$\hat{p} = \frac{k + \frac{z^2}{2}}{n + z^2} \pm \frac{z}{n + z^2}\sqrt{\frac{k(n-k)}{n} + \frac{z^2}{4}}$$

*(where $k$ is successes, $n$ is trials, and $z = 1.96$ for a 95% confidence level)*

#### Point Estimates vs. Statistical Reality:
- **Small Corpus ($k=10, n=10$)**: Point Recall = **100%**, but 95% CI = **$[72.2\%, 100.0\%]$**.
- **Medium Corpus ($k=50, n=50$)**: Point Recall = **100%**, but 95% CI = **$[92.8\%, 100.0\%]$**.
- **Large Corpus ($k=200, n=200$)**: Point Recall = **100%**, but 95% CI = **$[98.1\%, 100.0\%]$**.

Quality policies enforce lower-bound confidence thresholds (`min_recall_lower95`), preventing rules from passing based on small-sample anomalies.

---

## Quality Gate Policies & Release Decisions

Candidate rule packs must satisfy automated release policies before production promotion:

```mermaid
flowchart TD
    Reports["Baseline & Candidate Reports"] --> Inputs{"Valid Inputs & Policy JSON?"}
    Inputs -->|"No"| Exit2["Operational Error<br/>Exit Code 2"]
    Inputs -->|"Yes"| Aligned{"Identical Manifest & Engine?"}
    Aligned -->|"No"| Exit4["Inconclusive / Incompatible<br/>Exit Code 4"]
    Aligned -->|"Yes"| Conditions{"Policy Thresholds Satisfied?<br/>max_new_false_positives == 0<br/>max_regressions == 0<br/>min_recall satisfied"}
    Conditions -->|"No"| Exit3["Policy Failed<br/>Exit Code 3"]
    Conditions -->|"Yes"| Exit0["Policy Passed<br/>Exit Code 0"]
    Exit0 --> Promotion["Analyst Review & Production Promotion"]

    classDef good fill:#173c30,stroke:#6cc7a2,color:#e8fff3;
    classDef bad fill:#3b222b,stroke:#db8798,color:#ffedf1;
    classDef warn fill:#383022,stroke:#d0af73,color:#fff4de;
    class Exit0,Promotion good;
    class Exit2,Exit3 bad;
    class Exit4,Inputs,Aligned,Conditions warn;
```

<p align="center">
  <img src="docs/images/release-comparison.png" alt="malyz3r Release Comparison & Quality Gate Matrix" width="95%" />
</p>

### Versioned Release Policy Schema (`policies/release-example.json`):
```json
{
  "version": "local-v1",
  "max_new_false_positives": 0,
  "max_regressions": 0,
  "min_samples": 1,
  "min_recall": 0.90,
  "require_provenance": true
}
```

### Deterministic Exit Codes for CI/CD Pipelines:
- **`0`**: **Pass** — Candidate satisfies all policy thresholds without regressions.
- **`3`**: **Fail** — Policy threshold violated (new false positive or dropped detection).
- **`4`**: **Inconclusive** — Incompatible evaluation manifests, unknown labels, or incomplete runs.
- **`2`**: **Operational Error** — Malformed JSON, missing files, or runtime exception.

---

## The 7-Phase Detection Engineering Lifecycle

```mermaid
flowchart LR
    Phase1["1. Ingest & Hash<br/>Deduplicate & Inventory"] --> Phase2["2. Assign Splits<br/>Dev vs. Held-Out"]
    Phase2 --> Phase3["3. Baseline Run<br/>Establish Benchmarks"]
    Phase3 --> Phase4["4. Author / Tune<br/>Edit Rules or AI Assist"]
    Phase4 --> Phase5["5. Candidate Run<br/>Supervised Worker"]
    Phase5 --> Phase6["6. Regression Diff<br/>Sample Transitions"]
    Phase6 --> Phase7["7. Release Gate<br/>Policy Decision"]
    Phase7 -->|"Fail (Exit 3)"| Phase4
    Phase7 -->|"Pass (Exit 0)"| Promote["Analyst Promotion<br/>Production Deploy"]

    classDef phase fill:#162d38,stroke:#75acbf,color:#e7f5fa;
    classDef promote fill:#173c30,stroke:#6cc7a2,color:#e8fff3;
    class Phase1,Phase2,Phase3,Phase4,Phase5,Phase6,Phase7 phase;
    class Promote promote;
```

1. **Ingest & Hash**: Scans incoming samples with `malyz3r-workbench inventory`, computing SHA-256 digests and deduplicating identical binaries.
2. **Assign Splits**: Explicitly marks samples as `development` (used for active tuning) or `held-out` (quarantined strictly for unbiased quality gating).
3. **Baseline Run**: Evaluates production rules against the manifest to establish baseline metrics.
4. **Author & Tune**: Detection engineers modify YARA rules in `malware_scanner/rules/` or use `malyz3r-assist`.
5. **Candidate Run**: Evaluates candidate rules against the identical dataset manifest under supervisor control.
6. **Regression Diffing**: Executes `malyz3r-workbench compare` or `malyz3r-assurance` to trace sample transitions.
7. **Release Gate**: Enforces the release policy, generating deterministic exit codes.

---

## Comprehensive Threat Detection Catalog (66 Files / 69 Detectors)

The detection catalog in [`malware_scanner/rules/`](malware_scanner/rules/) covers **66 battle-tested YARA rule files** containing **69 discrete threat detectors** mapped against MITRE ATT&CK tactics:

| Category | Files | Threat Families & Detectors | MITRE ATT&CK Mapping | Detection Mechanism |
| :--- | :---: | :--- | :--- | :--- |
| **Advanced Persistent Threats (APT)** | 8 | • APT28 (Sofacy / Fancy Bear CHOPSTICK/SPLM)<br>• APT29 (Cozy Bear / Nobelium / SolarWinds)<br>• Lazarus Group (HIDDEN COBRA / BlueNoroff)<br>• MuddyWater (Seed / POWERSTATS)<br>• OilRig (Helix Kitten / BONDUPDATER)<br>• Sandworm (BlackEnergy / Industroyer)<br>• Turla (Snake / Uroburos)<br>• Winnti Group (APT41 / Barlaiy) | T1071 (Application Layer Protocol)<br>T1059 (Command & Scripting)<br>T1105 (Ingress Tool Transfer)<br>T1027 (Obfuscated Files) | Characteristic C2 URI patterns, registry persistence keys, unique XOR decryption routines, and hardcoded mutex strings. |
| **Ransomware** | 12 | • Babuk Locker (ESXi / Win)<br>• BlackCat (ALPHV Rust-based)<br>• Clop (TA505 / FIN11)<br>• Conti (Wizard Spider v1-v3)<br>• DarkSide / BlackMatter<br>• Hive (Go/Rust variants)<br>• LockBit 3.0 (LockBit Black)<br>• Phobos / Elrond / 8base<br>• Play (PlayCrypt)<br>• REvil (Sodinokibi)<br>• Rhysida<br>• WannaCry (WanaCrypt0r 2.0) | T1486 (Data Encrypted for Impact)<br>T1490 (Inhibit System Recovery)<br>T1489 (Service Stop) | VSS deletion commands (`vssadmin delete shadows`), ransom note templates, encryption marker footers, and cryptographic API imports (`BCryptGenRandom`, `CryptEncrypt`). |
| **Infostealers** | 9 | • AgentTesla (.NET Keylogger)<br>• Ducktail (Facebook Business Stealer)<br>• FormBook / XLoader<br>• LummaC2 (Lumma Stealer C2)<br>• Meduza Stealer<br>• Raccoon Stealer (v1 & v2)<br>• RedLine Stealer<br>• Stealc (C-based Stealer)<br>• Vidar Stealer | T1005 (Data from Local System)<br>T1555 (Credentials from Password Stores)<br>T1539 (Steal Web Session Cookie)<br>T1115 (Clipboard Data) | Browser profile paths (`Login Data`, `Cookies`), crypto wallet directory targets, Telegram session paths, and base64 C2 exfiltration patterns. |
| **Remote Access Trojans (RAT)** | 9 | • AsyncRAT (.NET open-source RAT)<br>• Cobalt Strike Beacon (Malleable C2 & Shellcode)<br>• Havoc Demon C2<br>• IcedID (BokBot Banking RAT)<br>• njRAT (Bladabindi)<br>• QuasarRAT (.NET RAT)<br>• Remcos RAT (BreakingSecurity)<br>• ShadowPad (APT41 shared tool)<br>• Sliver C2 (BishopFox Go framework) | T1219 (Remote Access Software)<br>T1059.001 (PowerShell)<br>T1056.001 (Keylogging)<br>T1095 (Non-Application Layer Protocol) | Default C2 TLS certificates, protocol handshakes, reflective loader stubs, beacon configuration blocks, and keylogger hooks. |
| **WebShells** | 6 | • ASPX Spy<br>• b374k (PHP WebShell)<br>• China Chopper (Minimal 1-liner & Client)<br>• Godzilla Memory Shell<br>• Weevely (Steganographic PHP WebShell)<br>• WSO (Web Shell by Orb) | T1505.003 (Server Component: Web Shell)<br>T1059.004 (Unix Shell)<br>T1059.006 (Python) | PHP `eval(base64_decode(...))`, ASPX `.NET` compilation directives, JSP reflective classloader invocations, and command execution primitives (`system`, `passthru`, `proc_open`). |
| **Botnets & Loaders** | 6 | • Emotet (HeLoader / Geodo)<br>• Gafgyt / Qbot (BASHLITE IoT)<br>• Mirai (Telnet brute-force IoT)<br>• Mozi (P2P IoT Botnet)<br>• QakBot (Pinkslipbot / Qbot)<br>• TrickBot (Anchor / BazarLoader) | T1584.005 (Botnet)<br>T1110.001 (Password Guessing)<br>T1498 (Network Denial of Service)<br>T1105 (Ingress Tool Transfer) | Telnet credential dictionaries, IoT cross-compilation strings (MIPS/ARM), P2P DHT routing signatures, and multi-stage DLL unpacker exports. |
| **Destructive Wipers** | 4 | • CaddyWiper<br>• HermeticWiper (FoxBlade)<br>• NotPetya (EternalBlue wiper)<br>• Shamoon (Disttrack wiper) | T1561.001 (Disk Content Wipe)<br>T1561.002 (Disk Structure Wipe)<br>T1490 (Inhibit System Recovery) | Raw disk handles (`\\.\PhysicalDrive0`), MBR overwriting loops, partition table zeroing, and SCSI/IDE miniport driver manipulation. |
| **Exploitation & Injections** | 4 | • EternalBlue (MS17-010 SMBv1 exploit)<br>• Log4Shell (CVE-2021-44228 JNDI injection)<br>• Process Hollowing (`NtUnmapViewOfSection`)<br>• Reflective DLL Injection (`ReflectiveLoader`) | T1210 (Exploitation of Remote Services)<br>T1190 (Exploit Public-Facing Application)<br>T1055.012 (Process Hollowing)<br>T1055.001 (Dynamic-link Library Injection) | SMBv1 FEA list buffer overflow patterns, `${jndi:ldap://}` string patterns, API injection sequences (`VirtualAllocEx` -> `WriteProcessMemory` -> `SetThreadContext`), and MZ PE search loops. |
| **Miners & Rootkits** | 2 | • XMRig Stratum Cryptominer<br>• Kernel Hooking Rootkits (Win/Linux) | T1496 (Resource Hijacking)<br>T1014 (Rootkit)<br>T1068 (Privilege Escalation) | Stratum mining protocol commands (`mining.subscribe`, `mining.authorize`), Monero pool endpoints, `/dev/kmem` manipulation, and SSDT hook signatures. |
| **Baseline Heuristics** | 6 | • Generic Trojans<br>• Generic Ransomware indicators<br>• Generic Worm propagation<br>• Phishing login scripts<br>• Static PE header anomalies<br>• Advanced heuristic behavioral markers | T1204 (User Execution)<br>T1566 (Phishing)<br>T1027 (Obfuscated Files)<br>T1129 (Shared Modules) | High PE section entropy (> 7.2), suspicious section names (`.upx`, `.vmp`, `.themida`), suspicious import hashes, and phishing form actions (`action="http..."`). |

---

## Corpus Manifest Schema & Split Governance

Corpus manifests establish ground truth for empirical verification:

```json
{
  "name": "apt28-and-ransomware-corpus-2026",
  "kind": "empirical",
  "samples": [
    {
      "path": "samples/apt28_dropper.bin",
      "label": "target",
      "expected_rules": [
        "apt_fancybear_sofaciy.yar:APT28_Sofacy_CHOPSTICK"
      ],
      "split": "development",
      "provenance": "CISA-Alert-AA23-180A",
      "family": "Sofacy",
      "sha256": "450dd0ace070e08635b19c9179150da4f81e30ea5c77538dbc880ad86863db37"
    },
    {
      "path": "samples/clean_system32_calc.exe",
      "label": "benign",
      "expected_rules": [],
      "split": "held-out",
      "provenance": "Windows-11-23H2-Clean-Install",
      "sha256": "a9538c5f4654a0752920c45015febcc0e37fb83f32c73e26025747d33d10b6af"
    }
  ]
}
```

### Split Governance Rules:
- **`development`**: Permitted for active rule authoring, iterative tuning, and LLM assistant evidence generation.
- **`held-out`**: Quarantined strictly for unbiased quality gating. Never shared with AI providers or tuning loops.
- **`unspecified`**: Evaluated normally, but rejected by policies requiring split isolation (`require_held_out: true`).

---

## Multi-Provider AI Assistant (`malyz3r-assist`)

Leverages Large Language Models to analyze development misclassifications and suggest candidate rule refinements with guaranteed zero data leakage:

```mermaid
sequenceDiagram
    actor Analyst
    participant Assistant as malyz3r-assist
    participant Run as Local Run Artifacts
    participant LLM as External LLM Provider

    Analyst->>Assistant: malyz3r-assist runs/dev-run output/ --model gpt-4o --send
    Assistant->>Run: Inspect run manifest & report
    alt Contains Held-Out Samples
        Assistant-->>Analyst: ERROR: Execution blocked! Held-out data detected.
    else Development Data Only
        Assistant->>Assistant: Strip paths, file names & raw binary bytes
        Assistant->>Assistant: Format sanitized misclassification prompt
        Assistant->>LLM: Send anonymized rule & match context
        LLM-->>Assistant: Candidate rule recommendation
        Assistant->>Analyst: Write unvalidated output/candidate.yar.txt
    end
```

### Supported Providers & Invocation:
```bash
# 1. Safe Offline Preview Mode (Zero network calls)
malyz3r-assist runs/run-2026-01 preview-output/ --model gpt-4o

# 2. OpenAI GPT-4o
export OPENAI_API_KEY="sk-..."
malyz3r-assist runs/run-2026-01 advice-openai/ --model gpt-4o --send --include-rule-source

# 3. Anthropic Claude 3.5 Sonnet
export ANTHROPIC_API_KEY="sk-ant-..."
malyz3r-assist runs/run-2026-01 advice-claude/ --provider anthropic --model claude-3-5-sonnet-20241022 --send --include-rule-source

# 4. Google Gemini 1.5 Pro
export GEMINI_API_KEY="..."
malyz3r-assist runs/run-2026-01 advice-gemini/ --provider gemini --model gemini-1.5-pro --send --include-rule-source

# 5. Local Offline LLM (Ollama or vLLM)
malyz3r-assist runs/run-2026-01 advice-local/ --provider openai-compatible \
  --base-url "http://localhost:11434/v1" --model llama3 --send --include-rule-source
```

---

## FastMCP IDE Integration (`malyz3r-mcp`)

Implements the Model Context Protocol (FastMCP 2.3.0) over stdio, allowing AI coding assistants in Cursor, Claude Desktop, and Antigravity to inspect runs safely:

### Configuration (`cursor.json` / `claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "malyz3r": {
      "command": "python",
      "args": [
        "-m", "malware_scanner.mcp_server",
        "--workspace", "C:/Users/Acer/Documents/ChatGPT/YARA"
      ]
    }
  }
}
```

### Exposed MCP Tools:
- **`development_evidence`** (`readOnlyHint=true`): Reads a completed development run confined strictly to the local workspace; immediately rejects runs containing `held-out` validation data.
- **`request_advice`** (`readOnlyHint=false`): Submits sanitized development evidence to the configured provider upon explicit user confirmation (`confirm_send=true`).

---

## Interactive Threat Hunting CLI & Direct Lab

### 1. Direct Evaluation Engine (`malyz3r-lab`)
Fast, single-process evaluator designed for CI/CD smoke tests:
```bash
python -m malware_scanner.lab samples/lab/manifest.json \
  --rules malware_scanner/rules \
  --strict \
  --timeout 10 \
  --output report.json
```

### 2. Operational Workbench (`malyz3r-workbench`)
Manage manifests, execute supervised runs, and compare diffs:
```bash
# Inventory sample directory
malyz3r-workbench inventory /path/to/samples --provenance "IR-Case-01" \
  --label target --split development --output manifest.json

# Supervised execution run
malyz3r-workbench run manifest.json malware_scanner/rules runs/run-01 \
  --wall-seconds 180 --memory-mb 512 --policy policies/research.json

# Regression diff
malyz3r-workbench compare runs/baseline runs/candidate --output comparison.json
```

### 3. Interactive Threat Hunting CLI (`malyz3r`)
Interactive terminal tool for memory scanning and ad-hoc file inspection:
```bash
python run_scanner.py
# or
malyz3r
```
- File & Directory multi-threaded scanning against 66 rule packs.
- Process Virtual Memory scanning for injected payloads and reflective DLLs.
- Hexdump and string preview for suspicious byte sequences.
- VirusTotal v3 hash queries (requires `VT_API_KEY`).

---

## Continuous Linux Security Monitoring & Background Service

`malyz3r` extends detection engineering into continuous, persistent background monitoring for Linux endpoints. It operates autonomously without requiring an open browser or interactive terminal.

```mermaid
flowchart LR
    FS[(Linux Filesystem)] -->|inotify events| Normalizer["Event Normalizer & Debouncer"]
    FS -->|Periodic Sweep| Reconcile["Reconciliation Scanner"]
    Normalizer --> Queue["Bounded Work Queue (Backpressure Guard)"]
    Reconcile --> Queue
    Queue --> Pipeline["Multi-Stage Analysis Pipeline"]
    Pipeline --> Storage[(SQLite Store: ~/.malyz3r_store.db)]
    Storage --> UI["Assurance Dashboard (Loopback API)"]
```

### 1. Service Architecture & Privilege Separation
The monitoring service is built with strict principle-of-least-privilege hardening:
- **Systemd Service Unit**: Integrated generator with security isolation flags:
  - `NoNewPrivileges=true`: Disallows privilege escalation.
  - `ProtectSystem=full`: Mounts `/usr`, `/boot`, and `/etc` as read-only.
  - `ProtectHome=read-only`: Guards user home directories, permitting writes only to explicit database/config paths.
  - `PrivateTmp=true`: Isolates `/tmp` namespace from the host.
  - `Restart=on-failure`: Recovers automatically from unexpected faults with backoff (`RestartSec=5s`).
- **Signal Handling**: Responds cleanly to `SIGTERM` and `SIGINT` (graceful worker drainage and lock release) and `SIGHUP` (on-demand reconciliation sweep).

### 2. Service Management Commands
```bash
# Install systemd unit (system-wide or user service)
malyz3r service install
malyz3r service install --user

# Service controls via systemctl
malyz3r service start
malyz3r service stop
malyz3r service status

# Run directly in foreground (development/testing)
malyz3r service run

# Trigger an immediate reconciliation sweep across monitored locations
malyz3r service reconcile
```

### 3. File-System Stabilization & Deduplication
To prevent partial scans of active downloads or expanding archives:
- **Debounce Stabilization**: Verifies file size and `mtime` remain stable across configurable intervals (`debounce_seconds: 0.5s`, up to 4 retries).
- **Exclusion Filters**: Automatically ignores temporary swap files, build outputs, and runtime directories (`*.tmp`, `*.swp`, `*/.git/*`, `*/__pycache__/*`, `/proc/*`, `/sys/*`).
- **Backpressure Work Queues**: Enforces strict queue bounds (`max_queue_size: 1000`). If saturated, drops/defers work and increments `events_dropped` without silent failure or memory bloat.

---

## Multi-Stage Static Analysis Pipeline

Suspicious files observed by the monitoring agent or submitted via CLI undergo a staged, safe inspection pipeline. **Samples are strictly read as inert data and never executed on the host.**

```mermaid
flowchart TD
    S1["Stage 1: Fingerprinting & Headers<br/>SHA256, MD5, MIME magic, Extension mismatch"] --> S2
    S2["Stage 2: Deterministic YARA Engine<br/>Compiled 66 rule packs with timeout protection"] --> S3
    S3["Stage 3: Deep Static Inspection<br/>ELF/PE headers, Shannon entropy, Indicators"] --> S4
    S4["Stage 4: Evidence Aggregation<br/>Distinguishes observed facts from hypotheses"] --> S5
    S5["Stage 5: AI-Assisted Interpretation<br/>Structured LLM analysis with prompt fencing"] --> S6
    S6["Stage 6: Investigation Report<br/>Sanitized standalone HTML & JSON exports"]
```

1. **Stage 1: Fingerprint & Format Verification**: Calculates cryptographic digests (SHA-256, MD5), byte size, permissions, and validates actual magic bytes against file extensions (detecting masked executables like `invoice.pdf` containing ELF/PE headers).
2. **Stage 2: Deterministic YARA Scan**: Compiles the verified detection ruleset and scans bounded byte buffers with a strict 15-second timeout. Scanning errors and timeouts are recorded explicitly rather than reported as clean non-matches.
3. **Stage 3: Static Binary Inspection**:
   - **ELF Header Parser**: Reads machine architecture (x86_64, AArch64, ARM, RISC-V), endianness, ABI, and binary type (`ET_EXEC`, `ET_DYN`).
   - **PE Authenticode Table**: Detects PE structure and validates Authenticode certificate directory bounds without trusting self-signed signatures.
   - **Shannon Entropy Calculation**: Computes mathematical entropy ($0.0$ to $8.0$). Chunks exceeding $7.0$ are flagged as potential packed code or encrypted payloads.
   - **Suspicious String Extraction**: Bounded extraction of C2 indicators (IPv4 addresses, HTTP/HTTPS URLs, shell execution commands like `curl`, `wget`, `bash -i`, `/dev/tcp`).
   - **Safe Archive Inspection**: Inspects ZIP and TAR archives without disk extraction, immediately detecting directory traversal risks (Zip-Slip `../`) and enforcing entries/size limits.
4. **Stage 4: Evidence Aggregation**: Compiles observed evidence, inferred hypotheses, and limitations into an immutable investigation record.

---

## AI-Assisted Investigation Service with Untrusted Prompt Fencing

`malyz3r` integrates multi-provider LLMs (OpenAI, Anthropic Claude, Google Gemini, and Local Ollama/vLLM) to assist analysts in interpreting complex evidence.

### Prompt Injection Defenses
Malware binaries frequently embed adversarial strings intended to hijack AI systems. `malyz3r` enforces strict security boundaries:
- **Untrusted Fencing**: All sample strings, paths, and headers are strictly quarantined inside `<untrusted_sample_evidence>` tags.
- **System Guardrails**: Explicit instructions command the model never to treat sample content as instructions, never grant shell execution or tool access, and never overturn deterministic YARA matches.
- **Strict Schema Enforcement**: Responses must conform to the required JSON schema:
```json
{
  "assessment": "malicious | suspicious | benign | unknown",
  "summary": "Evidence-grounded explanation",
  "confidence": 0.85,
  "confidence_basis": "Matched known backdoor signature and suspicious binary features.",
  "supporting_evidence": ["YARA match: backdoor", "ELF 64-bit architecture"],
  "contradicting_evidence": [],
  "matched_rules": ["ruleset:backdoor"],
  "indicators": ["192.168.1.100"],
  "limitations": ["Static analysis only"],
  "recommended_actions": ["Isolate host immediately"],
  "analysis_status": "complete"
}
```
- **Deterministic Offline Fallback**: If an AI provider is unconfigured, rate-limited, or unreachable, `malyz3r` automatically falls back to an evidence-grounded rule-based assessment without failing the scan or reporting false clean results.

---

## Deep Triage HUD & Shannon Entropy Spectrum

When investigating active alerts or suspicious binaries, analysts can launch the **Deep Triage HUD** for in-depth static decomposition and evidence-linked telemetry:

<p align="center">
  <img src="docs/images/investigations-deep-triage.png" alt="malyz3r Deep Triage HUD and Entropy Analysis" width="95%" />
</p>

### Analytical Capabilities in Deep Triage:
1. **Tri-Vector Risk Radar**: Breaks down overall risk score ($0$ to $100$) into three independent dimensions:
   - **Signature Threat**: Matches against compiled YARA rule packs with confidence weights.
   - **Heuristic Threat**: Extension spoofing, executable headers disguised as documents, Zip-Slip path traversals, and anomalous section names.
   - **Behavioral Indicators**: Extracted plain-text/encoded C2 URLs, IP addresses, persistence commands (`cron`, `systemd`, `init.d`), and privilege escalation artifacts.
2. **Shannon Entropy Spectrum**: Visualizes byte randomness across binary segments ($0.0$ to $8.0$ bits/byte). Chunks exceeding $7.2$ bits/byte are automatically flagged as packed routines, cryptographic key material, or encrypted payloads.
3. **MITRE ATT&CK Tactical Matrix**: Automatically correlates rule tags to MITRE Tactics (e.g. `TA0002 Execution`, `TA0003 Persistence`, `TA0005 Defense Evasion`) and discrete sub-techniques.
4. **Header Architecture & Authenticode Inspector**: Parses ELF/PE headers to extract machine target (x86_64, ARM, RISC-V), compiler timestamps, section permissions (e.g. `W+X` memory segments), and Authenticode certificate table offsets.

---

## Controlled AI Learning, Analyst Feedback & Rule Promotion

To continuously improve detection quality without risking autonomous model hallucinations or uncontrolled self-training, `malyz3r` implements a human-in-the-loop detection engineering workflow:

```mermaid
sequenceDiagram
    autonumber
    actor Analyst
    participant Dashboard as Web Dashboard / API
    participant Store as SQLite Store
    participant Engine as Learning & Regression Engine
    participant Rules as Production Ruleset (~/rules)

    Analyst->>Dashboard: Submit Verified Feedback (Confirmed Malicious / FP)
    Dashboard->>Store: Record Feedback & Append to Versioned Manifest
    Analyst->>Dashboard: Propose Candidate YARA Rule
    Dashboard->>Engine: Validate YARA Syntax & Compile
    Engine->>Engine: Run Regression Tests on Baseline vs Candidate
    Engine-->>Dashboard: Return Wilson Score Delta & Gate Decision
    Analyst->>Dashboard: Authorize Rule Promotion
    Dashboard->>Rules: Promote Rule to Production (Save Rollback Source)
    Dashboard->>Store: Audit Log Promotion Event
```

1. **Analyst Feedback Collection**: Authorized analysts record ground-truth verdicts (`confirmed_malicious`, `confirmed_benign`, `false_positive`, `inconclusive`) with technical rationale.
2. **Versioned Learning Dataset**: Verified feedback records are automatically formatted into reproducible manifest files for evaluation in `malyz3r-lab`.
3. **Regression Testing Gate**: Proposed candidate rules are evaluated against baseline datasets using `assurance.compare` and `assurance.gate`. A rule causing false-positive regressions fails the release gate.
4. **Human Authorization Gate**: Candidate rules **never enter production automatically**. Promotion requires explicit human authorization, and previous rule sources are preserved as rollback backups.

---

## Installation & Environment Setup

### Prerequisites
- **Python**: 3.10, 3.11, 3.12, or 3.13 (64-bit).
- **Windows**: Microsoft Visual C++ 2015-2022 Redistributable.
- **Linux**: Build essentials and OpenSSL development headers:
  ```bash
  sudo apt-get update && sudo apt-get install -y build-essential libssl-dev python3-dev
  ```

### Installation Steps
```bash
# 1. Clone repository
git clone https://github.com/gl1tch0x1/malyz3r.git
cd malyz3r

# 2. Create isolated virtual environment
python -m venv .venv

# Activate (Linux/macOS):
source .venv/bin/activate
# Activate (Windows PowerShell):
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies pinned against strict constraints
python -m pip install -c constraints.txt .

# 4. (Optional) Install FastMCP IDE telemetry server (Python 3.11+ required)
python -m pip install ".[mcp]"
```

---

## Docker Packaging & Corpus Persistence

The Docker image packages the runtime and public detectors while keeping private malware corpora outside the build context:

```bash
# Build analyst container
docker build -t malyz3r:latest .

# Run complete validation suite in container
docker run --rm malyz3r:latest python tests/run_validation.py

# Execute supervised evaluation mounting host corpus and runs directory
docker run --rm -v "$(pwd)/runs:/app/runs" -v "/path/to/corpus:/app/local-corpus:ro" malyz3r:latest \
  malyz3r-workbench run samples/lab/manifest.json --rules malware_scanner/rules \
  --runs-dir runs/container-run-01 --wall-seconds 120 --memory-mb 512
```

---

## Automated Testing & CI/CD Verification

```bash
# 1. Run all unit tests
python -m unittest discover -s tests -v

# 2. Check formatting and linting with Ruff
python -m ruff check
python -m ruff format --check

# 3. Execute the full end-to-end CI validation suite
python tests/run_validation.py

# 4. Verify clean wheel build and installation
python tests/smoke_install.py

# 5. Run Playwright browser UI assurance checks
python tests/browser_assurance.py --channel chrome --screenshot runs/ui-validation/release-comparison.png
```

### Static Type Safety
- Configured for **Pyright / Pylance** static analysis (`pyproject.toml`).
- Native C-extension type stubs defined in [`typings/yara.pyi`](typings/yara.pyi).

---

## Repository Structure

```
.
├── malware_scanner/          # Core Python package
│   ├── rules/                # 66 candidate YARA rule files (69 detectors)
│   ├── __init__.py           # Package version definition
│   ├── assurance.py          # Sample comparisons, coverage & release policy
│   ├── web.py                # Authenticated loopback API & web entry point
│   ├── web_workspace.py      # Graph, compatible history & draft adapters
│   ├── web_assets/           # Bundled HTML, CSS, JavaScript and SVG UI
│   ├── artifacts.py          # Report export (JSON, CSV, sanitized HTML)
│   ├── assistant.py          # Multi-provider LLM assistant (OpenAI, Claude, Gemini, Ollama)
│   ├── benchmark.py          # Benchmark harness and performance matrix
│   ├── cli.py                # Interactive threat hunting terminal CLI
│   ├── corpus.py             # Manifest inventory, merge, and verification
│   ├── lab.py                # Strict YARA compiler and evaluation engine
│   ├── mcp_server.py         # FastMCP stdio server for IDE integration
│   ├── providers.py          # API client adapters for LLM providers
│   ├── quality.py            # Quality policy enforcement and regression diffs
│   ├── scanner.py            # Core file and memory scanning engine
│   ├── statistics.py         # Wilson score binomial confidence interval calculator
│   ├── workbench.py          # Subprocess supervisor and analyst workflow CLI
│   └── worker.py             # Supervised child process worker
├── datasets/                 # Packaged evaluation and calibration datasets
├── docs/                     # Comprehensive documentation hub & technical guides
│   ├── ASSISTANT.md          # Multi-provider LLM assistant, guardrails & prompt fencing
│   ├── ASSURANCE.md          # Mathematical scoring, Wilson score CIs & release gates
│   ├── LAB.md                # Headless CI/CD evaluation runner & smoke validation
│   ├── MCP.md                # FastMCP 2.3.0 stdio server guide for IDE integration
│   ├── OPERATIONS.md         # SOC runbooks, systemd sandboxing & incident response
│   ├── VALIDATION.md         # Platform test matrix, Pyright typing & Playwright harness
│   ├── WIKI.md               # Technical encyclopedia & deep system internals
│   ├── diagrams/             # Architectural Mermaid diagrams and vector SVGs
│   └── images/               # High-resolution dashboard screenshots & triage HUD
├── local-corpus/             # Local sample corpora mount point
├── samples/lab/              # Harmless synthetic test fixtures and manifests
├── scripts/                  # Automation and rule generation scripts
├── tests/                    # 72 comprehensive unit/integration tests and browser harness
├── typings/                  # Static type stubs for native extensions (yara.pyi)
├── Dockerfile                # Production Docker container definition
├── Dockerfile.validation     # Pinned CI validation container
├── pyproject.toml            # Project packaging metadata, Ruff and Pyright config
├── constraints.txt           # Pinned dependency constraints
├── workspace.example.json    # Example catalog using synthetic fixtures
├── policies/                 # Per-rule and versioned release policies
└── README.md                 # Project documentation
```

> [!NOTE]
> **Patch File Cleanup**: Legacy patch files such as `malyz3r-user-gitignore.patch` are obsolete and have been pruned from the workspace. All ignore patterns (including `*.log`, `report.json`, `.pytest_cache/`, `.ruff_cache/`, `runs/`, and virtual environment directories) are natively incorporated and version-controlled directly within [`.gitignore`](.gitignore).

---

## Honest Disclaimers & Operational Boundaries

> [!IMPORTANT]
> **Project Status: Single-analyst evaluation workbench and research harness. Read the following operational realities before deploying or evaluating this software.**

1. **Not an Antivirus, EDR, or Real-Time Shield**: `malyz3r` is an on-demand, batch-oriented static rule evaluator. It does **not** install a kernel minifilter, intercept live system calls, monitor network packets, or terminate processes in real time.
2. **Not a Dynamic Sandbox or Detonation Chamber**: Files are parsed strictly as byte buffers. `malyz3r` does not execute binaries, unpack runtime payloads, or inspect dynamic API call traces. Live malware **must be isolated in an air-gapped or dedicated analysis virtual machine**.
3. **Static Rule Limitations (Packers & Crypters)**: YARA operates on static byte sequences and PE headers. If a binary is packed with UPX, Themida, VMProtect, or a custom polymorphic runtime crypter, plain-text string signatures will fail until unpacked.
4. **Worker Process Boundary != OS Sandbox**: The workbench supervisor executes rule evaluations inside a child Python subprocess guarded by wall-clock timers and memory caps. **It is not an operating system security boundary** (such as a seccomp jail or microVM).
5. **Heuristic Candidate Rules, Not Certified Feeds**: The 66 bundled YARA rule files are open-source detection engineering heuristics curated from public threat reports. Local tuning and allowlisting are mandatory.
6. **Analysts Establish Ground Truth**: `malyz3r` calculates detection metrics strictly against analyst-provided manifests. It has no independent awareness of true malware status. Inaccurate ground truth manifests will produce deceptive metrics.
7. **Synthetic Fixtures vs. Wild Corpora**: The test fixtures in [`samples/lab/`](samples/lab/) are harmless synthetic files crafted for deterministic CI regression testing. Achieving 100% precision and recall on synthetic fixtures **does not imply high real-world efficacy against evolving malware in the wild**.
8. **AI Assistant Guardrails**: Large Language Models frequently hallucinate invalid YARA syntax and regex constructs. `malyz3r-assist` outputs non-executable draft suggestions (`candidate.yar.txt`). Human review is mandatory.
9. **VirusTotal OPSEC & Rate Limits**: VirusTotal API v3 integration requires an analyst API key. Querying or submitting proprietary hashes or sensitive incident artifacts to public multi-scanner engines may expose confidential engagement data.

---

## License & Attribution

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

Created by [gl1tch0x1](https://github.com/gl1tch0x1). Enhanced and maintained by detection engineering and threat research teams.
