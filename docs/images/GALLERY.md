# Documentation Image Gallery

This page serves as a visual index for all demo screenshots and diagrams in the malyz3r documentation.

## Mermaid Architecture Diagrams

### 1. System Architecture (`docs/diagrams/01.svg`)
- **Purpose**: Shows complete system architecture with 5 subsystems
- **Components**: Operational Interfaces, Corpus & Manifest Ingestion, Execution & Supervisor Boundary, Analytics & Governance, Assist & IDE Telemetry
- **Reference**: [README.md - System Architecture](../README.md#system-architecture--boundaries)

### 2. Analyst Workflow (`docs/diagrams/02.svg`)
- **Purpose**: 3-phase analyst workflow with decision gates
- **Phases**: Prepare corpus, Develop rules, Freeze and validate
- **Reference**: [README.md - Analyst Workflow](../README.md#analyst-workflow)

### 3. Execution Sequence (`docs/diagrams/03.svg`)
- **Purpose**: Sequence diagram showing workbench execution flow
- **Components**: Analyst, Supervisor, Run Directory, Worker Process, Evaluator and YARA
- **Reference**: [README.md - Execution and Failure Handling](../README.md#execution-and-failure-handling)

### 4. Terminal States (`docs/diagrams/04.svg`)
- **Purpose**: State diagram showing all possible run terminal states
- **States**: running, completed, rejected, incomplete, timed_out, resource_limit, failed, cancelled
- **Reference**: [README.md - Execution and Failure Handling](../README.md#execution-and-failure-handling)

### 5. Metrics Computation (`docs/diagrams/05.svg`)
- **Purpose**: Flowchart showing how metrics are computed from scan results
- **Components**: Sample scan result, validation, classification, metrics calculation, quality policy
- **Reference**: [README.md - Metrics and Quality Gates](../README.md#metrics-and-quality-gates)

### 6. Revision Comparison (`docs/diagrams/06.svg`)
- **Purpose**: Flowchart showing baseline vs candidate comparison process
- **Components**: Corpus, Baseline revision, Candidate revision, Compatibility check, Delta calculation
- **Reference**: [README.md - Evidence and Comparison](../README.md#evidence-and-comparison)

---

## Demo Screenshots (To Be Added)

### Dashboard & Interface Screenshots

| # | Image File | Description | Status | Reference |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `workbench-dashboard.png` | Main workbench interface showing run history, status indicators, and quick actions | ⏳ Placeholder | [README.md Figure 2](../README.md#1-operational-workbench-malyz3r-workbench) |
| 2 | `html-report-view.png` | Standalone HTML report showing metrics, confusion matrices, and detailed results | ⏳ Placeholder | [README.md Figure 3](../README.md#1-operational-workbench-malyz3r-workbench) |
| 3 | `rule-editor.png` | YARA rule editing interface with syntax highlighting and validation | ⏳ Placeholder | Not yet referenced |
| 4 | `mcp-ide-integration.png` | Cursor or Claude Desktop showing MCP tools and development evidence | ⏳ Placeholder | [README.md Figure 5](../README.md#4-fastmcp-ide-integration-malyz3r-mcp) |
| 5 | `ai-assistant-response.png` | LLM assistant showing findings, suggestions, and candidate rule proposal | ⏳ Placeholder | [README.md Figure 4](../README.md#3-multi-provider-ai-assistant-malyz3r-assist) |
| 6 | `comparison-diff.png` | Baseline vs candidate comparison showing metric deltas and sample changes | ⏳ Placeholder | [README.md Figure 8](../README.md#1-operational-workbench-malyz3r-workbench) |
| 7 | `cli-terminal.png` | Interactive threat hunting CLI showing file scan results | ⏳ Placeholder | [README.md Figure 6](../README.md#5-interactive-threat-hunting-cli-malyz3r) |
| 8 | `threat-catalog.png` | Visual catalog of 66 YARA rule files organized by category | ⏳ Placeholder | [README.md Figure 7](../README.md#comprehensive-threat-detection-catalog-66-files--69-detectors) |

---

## Additional Diagrams in Documentation

### README.md

1. **System Architecture** - Complex flowchart with 5 subsystems
2. **MCP Integration Flow** - IDE to provider workflow with data flow
3. **Detection Engineering Lifecycle** - 7-phase workflow with iteration loops
4. **Threat Model & Security** - Isolation boundaries, threat surface, and protection mechanisms

### docs/WIKI_SECURITY.md

1. **Protection Mechanisms** - Implemented controls diagram
2. **Not Protected Boundaries** - Security limitations diagram

### docs/WIKI_OPERATIONS.md

1. **Workflow Overview** - 7-phase analyst workflow diagram

---

## Image File Naming Convention

### Mermaid Diagrams
- Pattern: `docs/diagrams/{number}.svg`
- Example: `docs/diagrams/01.svg`
- Source: `docs/diagrams/{number}.mmd`

### Demo Screenshots
- Pattern: `docs/images/{descriptive-name}.png`
- Example: `docs/images/workbench-dashboard.png`
- Maximum file size: 2MB
- Recommended resolution: 1920x1080px

---

## Rendering Status

### Mermaid Diagrams
- [x] All 6 diagrams rendered as SVG
- [x] Visually inspected
- [x] References in README.md
- [x] Source files (.mmd) preserved

### Demo Screenshots
- [ ] Workbench dashboard screenshot
- [ ] HTML report view screenshot
- [ ] Rule editor interface screenshot
- [ ] MCP IDE integration screenshot
- [ ] AI assistant response screenshot
- [ ] Comparison diff view screenshot
- [ ] CLI terminal interface screenshot
- [ ] Threat detection catalog visualization

---

## How to Add Screenshots

### Quick Start

1. **Run malyz3r** and perform the action you want to capture
2. **Take a screenshot** using your preferred tool
3. **Save to** `docs/images/` with the appropriate filename
4. **Redact sensitive information** (paths, IPs, keys, identifiers)
5. **Optimize** the image (PNG, <2MB, 1920x1080px minimum)
6. **Test** rendering in Markdown viewer

### Detailed Guide

See [DEMO_SCREENSHOTS.md](DEMO_SCREENSHOTS.md) for:
- Detailed specifications for each screenshot
- Suggested layouts and what to include
- Privacy and security checklist
- Capture tools and guidelines
- Image optimization tips

---

## Gallery Thumbnails

When screenshots are added, this section will display thumbnail previews:

```
┌─────────────────────────────────────────────────────────────┐
│  Demo Screenshots Gallery                                    │
├─────────────────────────────────────────────────────────────┤
│                                                           │
│  [Thumbnail: workbench-dashboard.png]                      │
│  Main workbench interface showing run history               │
│                                                           │
│  [Thumbnail: html-report-view.png]                          │
│  Standalone HTML report with metrics and results            │
│                                                           │
│  [Thumbnail: mcp-ide-integration.png]                       │
│  Cursor IDE showing MCP tools and evidence retrieval         │
│                                                           │
│  [Thumbnail: ai-assistant-response.png]                      │
│  LLM assistant findings and candidate rule proposal         │
│                                                           │
│  [Additional thumbnails...]                                  │
│                                                           │
└─────────────────────────────────────────────────────────────┘
```

---

## Image Accessibility

### Alt Text Guidelines

When adding images to documentation:

```markdown
![Descriptive text](path/to/image.png)
*Figure N: Detailed caption explaining the image content*
```

**Alt text should:**
- Be descriptive and concise
- Convey the essential information
- Not repeat the caption verbatim
- Be meaningful when image is not displayed

**Example:**
```markdown
![Workbench dashboard showing run history with three completed evaluations and one policy rejection](docs/images/workbench-dashboard.png)
*Figure 2: Workbench dashboard interface displaying run history, status indicators, and quick action buttons (demo screenshot)*
```

---

## Maintenance

### When to Update Images

- **Major UI changes**: When the interface significantly changes
- **New features**: When new features are added that need visual documentation
- **Bug fixes**: When images show incorrect or outdated information
- **Style updates**: When the visual theme changes (dark/light mode)

### Update Checklist

- [ ] Capture new screenshot following existing guidelines
- [ ] Redact sensitive information
- [ ] Optimize image size and resolution
- [ ] Update image references in documentation
- [ ] Test rendering in Markdown viewers
- [ ] Update this gallery if filename changes
- [ ] Archive old version if needed

---

## Troubleshooting

### Images Not Displaying

**Problem**: Images show as broken links

**Solutions:**
1. Check file path is correct (relative to .md file)
2. Verify image file exists in `docs/images/`
3. Check filename case sensitivity (Linux)
4. Ensure file is not in .gitignore
5. Test with absolute path as fallback

### Images Too Large

**Problem**: File size exceeds 2MB

**Solutions:**
1. Use PNG optimization tool (pngquant, optipng)
2. Reduce resolution if acceptable
3. Crop unnecessary margins
4. Consider JPEG for screenshots (if transparency not needed)

### Images Blurry

**Problem**: Text not readable when scaled

**Solutions:**
1. Capture at higher resolution (2x or 3x)
2. Use lossless PNG format
3. Ensure display is at 100% zoom when capturing
4. Check monitor resolution settings

---

## Related Documentation

- [DEMO_SCREENSHOTS.md](DEMO_SCREENSHOTS.md) - Detailed screenshot specifications
- [README.md](../README.md) - Main documentation with image references
- [WIKI.md](../WIKI.md) - Central documentation index

---

**Last Updated**: 26 October 2026
**Status**: Framework complete, awaiting actual screenshots
