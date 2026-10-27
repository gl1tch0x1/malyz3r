# malyz3r Documentation Wiki

Welcome to the comprehensive documentation wiki for **malyz3r** — the YARA Rule Engineering Workbench & Threat Analysis Platform.

This wiki serves as the central index for all detailed technical documentation, operational guides, and reference materials.

---

## Quick Start

**New to malyz3r?** Start with the main [README.md](README.md) for:
- Project overview and architecture
- Installation instructions
- Quick start guide
- Comprehensive threat detection catalog
- All five CLI interfaces

---

## Documentation Index

### Core Documentation

| Document | Description | Audience |
| :--- | :--- | :--- |
| [README.md](README.md) | Main project documentation with architecture, installation, and quick start | All users |
| [WIKI.md](WIKI.md) | This central documentation index | All users |

### Operational Guides

| Document | Description | Audience |
| :--- | :--- | :--- |
| [OPERATIONS.md](OPERATIONS.md) | Local analyst workflow runbook, inventory procedures, and evaluation operations | Analysts, Security Researchers |
| [LAB.md](LAB.md) | Evaluator technical details, dataset contract, and lab implementation details | Detection Engineers, Developers |

### AI & LLM Integration

| Document | Description | Audience |
| :--- | :--- | :--- |
| [ASSISTANT.md](ASSISTANT.md) | Multi-provider LLM assistant configuration, usage guide, and provider selection | Detection Engineers, AI-Assisted Analysts |
| [MCP.md](MCP.md) | Model Context Protocol integration for IDEs (Cursor, Antigravity, OpenCode, Claude Desktop) | IDE Users, AI-Assisted Analysts |

### Security & Validation

| Document | Description | Audience |
| :--- | :--- | :--- |
| [SECURITY.md](SECURITY.md) | Security model, threat boundaries, isolation controls, and validation limits | Security Engineers, Auditors |
| [VALIDATION.md](VALIDATION.md) | Dated validation record, test coverage evidence, and certification boundaries | QA Engineers, Security Reviewers |

### Datasets & Research

| Document | Description | Audience |
| :--- | :--- | :--- |
| [datasets/README.md](datasets/README.md) | GitHub PHP research corpus, calibration data, and interpretation limits | Researchers, Detection Engineers |

### Visual Documentation

| Document | Description | Audience |
| :--- | :--- | :--- |
| [docs/images/GALLERY.md](docs/images/GALLERY.md) | Image gallery with all diagrams and demo screenshots | All users |
| [docs/images/DEMO_SCREENSHOTS.md](docs/images/DEMO_SCREENSHOTS.md) | Detailed guide for capturing demo screenshots | Documentation Contributors |

---

## Documentation by Role

### For Threat Hunters & Security Researchers

**Start here:**
1. [README.md](README.md) — Architecture, threat detection catalog, and installation
2. [OPERATIONS.md](OPERATIONS.md) — Local analyst workflow and evaluation procedures
3. [SECURITY.md](SECURITY.md) — Security boundaries and safe handling procedures

**Key Topics:**
- [Threat Detection Catalog](README.md#comprehensive-threat-detection-catalog-66-files--69-detectors) — 66 YARA rule files covering APTs, ransomware, infostealers, RATs, webshells, botnets, and more
- [Interactive Threat Hunting CLI](README.md#5-interactive-threat-hunting-cli-malyz3r) — Ad-hoc file scanning, memory hunting, and VirusTotal lookup
- [Detection Engineering Lifecycle](README.md#detection-engineering-lifecycle-7-phases) — 7-phase workflow for rule development and validation

### For Detection Engineers

**Start here:**
1. [README.md](README.md) — Complete system architecture and interfaces
2. [LAB.md](LAB.md) — Evaluator technical details and dataset contract
3. [OPERATIONS.md](OPERATIONS.md) — Inventory, merge, and evaluation procedures
4. [ASSISTANT.md](ASSISTANT.md) — AI-assisted rule refinement workflow

**Key Topics:**
- [Operational Workbench](README.md#1-operational-workbench-malyz3r-workbench) — Supervised evaluation with quality gates
- [Quality Gate Policies](README.md#quality-gate-policies--production-promotion) — Machine-enforceable rule promotion criteria
- [Statistical Honesty](README.md#statistical-honesty-wilson-score-confidence-intervals) — Wilson score confidence intervals for metrics
- [Manifest Schema](README.md#manifest-schema-split-isolation--data-integrity) — Ground truth assertion and split isolation

### For AI-Assisted Analysts

**Start here:**
1. [ASSISTANT.md](ASSISTANT.md) — LLM assistant configuration and usage
2. [MCP.md](MCP.md) — IDE integration via Model Context Protocol
3. [README.md](README.md#3-multi-provider-ai-assistant-malyz3r-assist) — AI assistant CLI interface

**Key Topics:**
- [Multi-Provider Support](ASSISTANT.md#provider-selection) — OpenAI, Anthropic Claude, Google Gemini, and Ollama
- [Safe Preview Mode](ASSISTANT.md#preview-first) — Zero-network-call preview before sending to LLM
- [IDE Integration](MCP.md) — FastMCP stdio server for Cursor, Antigravity, OpenCode, and Claude Desktop
- [Data Privacy Controls](ASSISTANT.md) — Sanitization, split isolation, and held-out blocking

### For Security Engineers & Auditors

**Start here:**
1. [SECURITY.md](SECURITY.md) — Security model and threat boundaries
2. [VALIDATION.md](VALIDATION.md) — Validation record and test coverage
3. [README.md](README.md#threat-model--security-considerations) — Threat model diagram

**Key Topics:**
- [Security Controls](SECURITY.md#controls-implemented) — Worker isolation, bounded reads, include confinement
- [LLM Advice Boundaries](SECURITY.md#optional-llm-advice) — Assistant privacy controls and limitations
- [MCP Boundaries](SECURITY.md#mcp-and-provider-boundaries) — IDE integration security considerations
- [Validation Record](VALIDATION.md) — Dated evidence, test coverage, and certification boundaries

### For Developers & Contributors

**Start here:**
1. [README.md](README.md#automated-testing--cicd-verification) — Testing and CI/CD procedures
2. [LAB.md](LAB.md) — Evaluator implementation details
3. [VALIDATION.md](VALIDATION.md) — Validation procedures and reproducible checks
4. [README.md](README.md#repository-structure) — Codebase organization

**Key Topics:**
- [Automated Testing](README.md#automated-testing--cicd-verification) — 71 unit tests, linting, and Docker validation
- [Dataset Contract](LAB.md#dataset-contract) — Manifest schema and validation rules
- [Calibration Research](datasets/README.md) — GitHub PHP corpus and reproducible experiments
- [Docker Packaging](README.md#docker-packaging--corpus-persistence) — Containerized builds and validation

---

## Diagram Architecture

The following Mermaid diagrams are available in the main README.md:

1. **System Architecture & Boundaries** — Complete flowchart with 5 subsystems
2. **MCP Integration Flow** — IDE to provider workflow with data flow
3. **Detection Engineering Lifecycle** — 7-phase workflow with iteration loops
4. **Threat Model & Security** — Isolation boundaries, threat surface, and protection mechanisms

For rendered SVG versions, see [docs/diagrams/](docs/diagrams/).

---

## Version-Specific Information

### Current Release

- **Python Support**: 3.10, 3.11, 3.12, 3.13
- **YARA Rules**: 66 files, 69 detectors
- **Tests**: 71 unit tests passing
- **MCP SDK**: v2.3.0 (requires Python 3.11+)
- **Validation Date**: 23 October 2026

### Validation Status

See [VALIDATION.md](VALIDATION.md) for:
- Multi-provider and MCP update (23 October 2026)
- Optional LLM integration validation (23 October 2026)
- Core application validation (23 October 2026)
- Security automation results
- Not-established requirements

---

## Contributing to Documentation

When updating documentation:

1. **Update the relevant .md file** (e.g., ASSISTANT.md for AI assistant changes)
2. **Update README.md** if the change affects the main documentation
3. **Update WIKI.md** if you add a new documentation file or significantly change the structure
4. **Regenerate diagrams** if you modify Mermaid sources in [docs/diagrams/](docs/diagrams/)
5. **Run validation** to ensure all tests pass:
   ```bash
   python tests/run_validation.py
   ```

---

## Need Help?

- **Installation Issues**: See [README.md#installation--environment-setup](README.md#installation--environment-setup)
- **Usage Questions**: See [OPERATIONS.md](OPERATIONS.md) for workflows
- **AI Assistant Problems**: See [ASSISTANT.md](ASSISTANT.md) for troubleshooting
- **Security Concerns**: See [SECURITY.md](SECURITY.md) for threat model
- **Validation Failures**: See [VALIDATION.md](VALIDATION.md) for test procedures

---

## License

All documentation is distributed under the same MIT license as the main project. See [LICENSE](LICENSE) for details.

---

**Last Updated**: 26 October 2026
