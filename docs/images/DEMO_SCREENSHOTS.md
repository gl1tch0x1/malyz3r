# Demo Screenshots Guide

This document provides guidance on capturing and adding demo screenshots for the malyz3r documentation.

## Required Screenshots

### 1. Workbench Dashboard (`workbench-dashboard.png`)

**When to Capture:**
- After running multiple evaluations
- Show different run states (completed, failed, rejected)
- Display the main interface with sidebar and statistics

**What to Include:**
- Run history list with timestamps
- Status indicators (✓ completed, ✗ failed, ⚠ rejected)
- Quick action buttons (inventory, run, inspect, compare)
- Summary statistics (total runs, pass rate, etc.)
- Selected run details panel

**Suggested Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│  malyz3r Workbench                              [Search 🔍]   │
├─────────────────────────────────────────────────────────────┤
│  Sidebar │ Main Content Area                              │
│          │                                                │
│  • Run    │  Run History                                    │
│  • Inspect│  ┌─────────────────────────────────────────┐   │
│  • Compare│  │ ✓ run-2026-01-15-001  Completed 100%    │   │
│  • Policy │  │ ✗ run-2026-01-14-002  Failed           │   │
│          │  │ ⚠ run-2026-01-13-003  Rejected (Policy)│   │
│  [+] New │  │ ✓ run-2026-01-12-004  Completed 98%     │   │
│          │  └─────────────────────────────────────────┘   │
│          │                                                │
│          │  Selected Run Details:                         │
│          │  • Samples: 1,234                              │
│          │  • Duration: 45.2s                             │
│          │  • Policy: ✓ Passed                            │
└─────────────────────────────────────────────────────────────┘
```

---

### 2. HTML Report View (`html-report-view.png`)

**When to Capture:**
- After a successful evaluation run
- Open the generated report.html in a browser
- Show metrics and detailed results

**What to Include:**
- Overall summary (total samples, TP, FP, FN, TN)
- Per-rule metrics table
- Confusion matrix visualization
- False positive listings
- Missed target listings
- Scan errors section

**Suggested Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│  Evaluation Report - run-2026-01-15-001                     │
├─────────────────────────────────────────────────────────────┤
│  Summary                                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Total Samples: 1,234  ✓ Complete  Policy: Passed    │  │
│  │ TP: 456  FP: 12  FN: 23  TN: 743                   │  │
│  │ Recall: 95.2%  Precision: 97.4%  F1: 96.3%        │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                           │
│  Per-Rule Metrics                                        │
│  ┌──────────────┬─────────┬─────────┬─────────┬────────┐│
│  │ Rule         │ Recall  │ Prec.   │ F1      │ FPR    ││
│  ├──────────────┼─────────┼─────────┼─────────┼────────┤│
│  │ ransomware   │ 98.5%   │ 99.1%   │ 98.8%   │ 0.1%   ││
│  │ webshell     │ 92.3%   │ 95.6%   │ 93.9%   │ 0.8%   ││
│  └──────────────┴─────────┴─────────┴─────────┴────────┘│
│                                                           │
│  [View False Positives] [View Missed Targets]            │
└─────────────────────────────────────────────────────────────┘
```

---

### 3. Rule Editor Interface (`rule-editor.png`)

**When to Capture:**
- While editing a YARA rule file
- Show syntax highlighting and validation
- Display compilation results

**What to Include:**
- Code editor with YARA syntax highlighting
- Line numbers
- Rule structure visualization
- Validation status (✓ valid or ✗ errors)
- Error messages if any
- Compile button and status

**Suggested Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│  ransom_lockbit.yar                          [Compile] [Save] │
├─────────────────────────────────────────────────────────────┤
│  1  rule Ransomware_LockBit3 {                             │
│  2      meta:                                             │
│  3          description = "LockBit 3.0 ransomware"         │
│  4          author = "malyz3r"                             │
│  5          date = "2026-01-15"                           │
│  6                                                           │
│  7      strings:                                          │
│  8          $s1 = "LOCKBIT" wide ascii                     │
│  9          $s2 = {B2 4A 6E 8F 3C}  // Magic bytes       │
│ 10                                                           │
│ 11      condition:                                        │
│ 12          2 of ($s*) and filesize < 10MB               │
│ 13  }                                                       │
├─────────────────────────────────────────────────────────────┤
│  ✓ Compilation successful                                   │
│  Rule identifier: ransom_lockbit.yar:Ransomware_LockBit3   │
└─────────────────────────────────────────────────────────────┘
```

---

### 4. MCP IDE Integration (`mcp-ide-integration.png`)

**When to Capture:**
- In Cursor, Claude Desktop, or compatible IDE
- Show MCP tools panel
- Display development evidence retrieval

**What to Include:**
- IDE interface with MCP sidebar
- Available tools list (development_evidence, request_advice)
- Tool execution panel
- Response display area
- Workspace file tree

**Suggested Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│  Cursor IDE - malyz3r Project                               │
├──────────┬──────────────────────────────────────────────────┤
│  Files   │  Editor Area                      │ MCP Tools  │
│          │                                  │             │
│  📁 src  │  // AI Assistant context:       │ ┌───────────┐│
│  📁 runs │  "Analyze the false positives"  │ │ MCP:      ││
│    ├─001 │                                  │ │ malyz3r   ││
│    ├─002 │  Use development_evidence...    │ │           ││
│          │                                  │ │ Tools:    ││
│  📁 rules│  [AI Response Area]              │ │ • evidence││
│          │                                  │ │ • advice  ││
│          │  The assistant found 12 FPs...  │ │           ││
│          │  Suggested: tighten string $s1  │ │ [Request] ││
│          │                                  │ └───────────┘│
└──────────┴──────────────────────────────────────────────────┘
```

---

### 5. AI Assistant Response (`ai-assistant-response.png`)

**When to Capture:**
- After receiving LLM assistant response
- Show structured findings and suggestions
- Display candidate rule if generated

**What to Include:**
- Summary section
- Findings list with evidence IDs
- Explanations and suggestions
- Candidate YARA rule (if generated)
- Status indicator (unvalidated)

**Suggested Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│  AI Assistant Analysis - runs/advice-result                  │
├─────────────────────────────────────────────────────────────┤
│  Summary                                                   │
│  Analysis identified 12 false positives and 5 missed        │
│  targets. Primary issue: overly broad string pattern.      │
│                                                           │
│  Findings                                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ [✓] Finding 1 (evidence IDs: samp_001, samp_005)  │  │
│  │   Explanation: Pattern matches benign config files │  │
│  │   Suggestion: Add file size constraint              │  │
│  │                                                      │  │
│  │ [✓] Finding 2 (evidence IDs: samp_012, samp_018)  │  │
│  │   Explanation: Unicode variation causes FP          │  │
│  │   Suggestion: Use ascii only                        │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                           │
│  Candidate Rule (Unvalidated)                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ rule Ransomware_LockBit3_v2 {                        │  │
│  │     strings:                                        │  │
│  │         $s1 = "LOCKBIT" ascii                       │  │
│  │         $s2 = {B2 4A 6E 8F 3C}                     │  │
│  │     condition:                                      │  │
│  │         2 of ($s*) and filesize < 10MB             │  │
│  │ }                                                    │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                           │
│  ⚠ Status: advice_unvalidated - Requires human review   │
└─────────────────────────────────────────────────────────────┘
```

---

### 6. Comparison Diff View (`comparison-diff.png`)

**When to Capture:**
- After running baseline vs candidate comparison
- Show metric deltas and sample changes
- Highlight regressions and improvements

**What to Include:**
- Baseline metrics
- Candidate metrics
- Delta calculations
- New detections list
- Missed detections list
- New false positives list
- Removed false positives list

**Suggested Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│  Comparison: Baseline vs Candidate                          │
├─────────────────────────────────────────────────────────────┤
│  Metric Deltas                                            │
│  ┌─────────────────┬──────────┬──────────┬──────────┬─────┐│
│  │ Rule            │ Baseline │ Candidate │ Delta    │ Trend││
│  ├─────────────────┼──────────┼──────────┼──────────┼─────┤│
│  │ ransomware      │ 98.5%    │ 99.1%    │ +0.6%    │  ↑  ││
│  │ webshell        │ 92.3%    │ 94.5%    │ +2.2%    │  ↑  ││
│  │ benign_fpr      │ 0.8%     │ 0.3%     │ -0.5%    │  ↓  ││
│  └─────────────────┴──────────┴──────────┴──────────┴─────┘│
│                                                           │
│  Sample Changes                                          │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ ✓ New Detections (5):                              │  │
│  │   • samp_456 (TP) - ransomware.yar:Ransomware      │  │
│  │   • samp_789 (TP) - webshell.yar:PHP_Webshell     │  │
│  │                                                      │  │
│  │ ✗ Missed Detections (2):                            │  │
│  │   • samp_123 (FN) - Was detected by baseline       │  │
│  │   • samp_456 (FN) - Was detected by baseline       │  │
│  │                                                      │  │
│  │ ⚠ New False Positives (1):                          │  │
│  │   • samp_999 (FP) - Newly matches ransomware rule  │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

### 7. CLI Terminal Interface (`cli-terminal.png`)

**When to Capture:**
- During interactive CLI session
- Show file/directory scanning
- Display match results
- Show memory scanning if applicable

**What to Include:**
- Terminal window with command prompt
- Scan progress indicators
- Match results with highlighting
- File paths and rule names
- Timestamp and duration

**Suggested Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│  PowerShell - malyz3r CLI                                    │
├─────────────────────────────────────────────────────────────┤
│  PS C:\malyz3r> malyz3r --directory samples/suspicious     │
│                                                           │
│  [*] Loading 66 YARA rules...                             │
│  [*] Scanning 124 files...                                  │
│                                                           │
│  [████████████████████████] 100% Complete                  │
│                                                           │
│  Scan Results:                                             │
│  ========================================================  │
│  ✓ samples/suspicious/malware.bin                         │
│    Matched: ransom_lockbit.yar:Ransomware_LockBit3        │
│    Matched: trojan_cobaltstrike.yar:CobaltStrike_Beacon  │
│    SHA256: a1b2c3d4e5f6...                              │
│                                                           │
│  ✓ samples/suspicious/webshell.php                        │
│    Matched: webshell_china_chopper.yar:China_Chopper      │
│    SHA256: f6e5d4c3b2a1...                              │
│                                                           │
│  [✓] Scan complete: 2 matches in 124 files (0.12s)       │
│                                                           │
│  PS C:\malyz3r> _                                          │
└─────────────────────────────────────────────────────────────┘
```

---

### 8. Threat Detection Catalog (`threat-catalog.png`)

**When to Capture:**
- Visual representation of the 66 rule files
- Organized by category
- Show coverage statistics

**What to Include:**
- Category breakdown (APT, Ransomware, Infostealers, etc.)
- File count per category
- MITRE ATT&CK mapping
- Detection mechanism highlights
- Visual grid or card layout

**Suggested Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│  Threat Detection Catalog - 66 Files / 69 Detectors         │
├─────────────────────────────────────────────────────────────┤
│                                                           │
│  APT Groups (8 files)                                     │
│  ┌────────┬────────┬────────┬────────┬────────┬────────┐   │
│  │APT28   │APT29   │Lazarus │Muddy   │OilRig  │Sandworm│   │
│  │Fancy   │Cozy    │BlueNor │Water   │Helix   │Black   │   │
│  │Bear    │Bear    │off     │Seed    │Kitten  │Energy  │   │
│  └────────┴────────┴────────┴────────┴────────┴────────┘   │
│                                                           │
│  Ransomware (12 files)                                    │
│  ┌─────────┬─────────┬─────────┬─────────┬─────────┬─────┐│
│  │Babuk    │BlackCat │Clop     │Conti    │DarkSide │Hive ││
│  │LockBit  │ALPHV    │TA505    │Wizard   │BlackM   │Go/  ││
│  │ESXi/Win │Rust     │FIN11    │Spider   │atter    │Rust ││
│  └─────────┴─────────┴─────────┴─────────┴─────────┴─────┘│
│                                                           │
│  Infostealers (9 files)  │  RATs (9 files)               │
│  WebShells (6 files)     │  Botnets (6 files)            │
│  Wipers (4 files)        │  Exploits (4 files)           │
│  Miners/Rootkits (2)     │  Heuristics (6)               │
│                                                           │
│  Total Coverage:                                     │
│  • 69 unique detectors                                      │
│  • 10 MITRE ATT&CK tactics                                 │
│  • 66 YARA rule files                                      │
└─────────────────────────────────────────────────────────────┘
```

---

## Capture Guidelines

### Image Specifications

- **Format**: PNG (lossless compression)
- **Resolution**: 1920x1080px minimum (16:9 aspect ratio)
- **File Size**: Keep under 2MB per image
- **Color Depth**: 24-bit RGB
- **Background**: Use consistent theme (dark mode recommended)

### Privacy and Security

**Before Capturing:**
- Redact sensitive file paths
- Mask IP addresses and domain names
- Hide API keys and credentials
- Remove personal identifiers
- Use sample data, not real case material

**Redaction Checklist:**
- [ ] No real malware sample names
- [ ] No confidential client information
- [ ] No internal infrastructure names
- [ ] No IP addresses or domain names
- [ ] No API keys or tokens
- [ ] No personal identifiers

### Tools for Capturing

**Windows:**
- Snipping Tool (built-in)
- ShareX (open-source)
- Greenshot (open-source)

**Linux:**
- GNOME Screenshot
- Kazam
- Shutter

**macOS:**
- Cmd+Shift+4 (built-in)
- Skitch
- CleanShot X

### Image Optimization

After capturing:
1. Use PNG optimization tools (pngquant, optipng)
2. Ensure text is readable at 100% zoom
3. Check contrast ratios for accessibility
4. Verify image scaling in documentation

---

## Adding Images to Documentation

### README.md

```markdown
![Description](docs/images/filename.png)
*Figure N: Caption text (demo screenshot)*
```

### Wiki Files

```markdown
![Description](../images/filename.png)
*Figure: Caption text (demo screenshot)*
```

### Best Practices

- Use descriptive filenames
- Add figure numbers for reference
- Include captions explaining what's shown
- Maintain consistent figure numbering
- Update image references when changing filenames

---

## Current Status

**Status**: Placeholder phase
- Images directory created: ✓
- Image guide created: ✓
- Documentation updated with references: ✓
- Actual screenshots needed: ⏳

**Next Steps**:
1. Capture actual screenshots from running malyz3r
2. Optimize images for web display
3. Replace placeholder references with real images
4. Test image rendering in Markdown viewers
5. Update image captions if needed

---

**Last Updated**: 26 October 2026
