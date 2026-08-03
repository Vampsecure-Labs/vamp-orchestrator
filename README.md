<p align="center">
  <img src="https://img.shields.io/badge/version-1.0-crimson?style=flat-square" />
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/tools-12%20VSL%20slots-teal?style=flat-square" />
  <img src="https://img.shields.io/badge/VampSecure_Labs-Security_Research-8b0000?style=flat-square" />
</p>

<h1 align="center">vamp-orchestrator</h1>
<p align="center"><em>Multi-Tool Security Assessment Orchestrator — VampSecure Labs</em></p>

---

## Overview

**vamp-orchestrator** is the meta-orchestrator for the VampSecure Labs toolkit. It auto-discovers installed VSL tools, selects the appropriate subset based on the assessment objective (domain, URL, host, path, or CVE list), executes them sequentially or in parallel, deduplicates findings across tools, and produces a unified risk-scored report.

The orchestrator solves the coordination overhead of running multiple specialized scanners: each tool result is parsed, normalized, and merged into a single finding set. Duplicate findings (same severity + title prefix) are collapsed and attributed to all contributing tools. A composite risk score (capped at 100) is computed from the deduplicated finding set and drives the final exit code.

---

## Features

- Auto-discovery of up to 12 VampSecure Labs tool slots in the tool directory
- Objective-driven tool selection: domain, URL, host, path, JWT, and CVE targets each trigger a different tool subset
- Sequential and parallel execution modes with configurable parallelism limit
- Finding deduplication across tool outputs (matched by severity + title prefix, 60 characters)
- Composite risk scoring: CRITICAL=25, HIGH=10, MEDIUM=5, LOW=1, INFO=0 (capped at 100)
- Per-tool execution log directory for full audit trail
- Unified JSON and HTML reporting via the `vampsec_report` module
- Custom tool path and Python interpreter configuration for virtual environment isolation

---

## Requirements

```
Python 3.11+
rich >= 13.7.0
```

Individual tool dependencies must be installed per their own `requirements.txt`. Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Installation

```bash
git clone https://github.com/belky-me/vamp-orchestrator.git
cd vamp-orchestrator
pip install -r requirements.txt
```

Ensure the other VSL tools are present and their dependencies installed. By default, the orchestrator looks for tools in the same parent directory.

---

## Usage

```
python vamp_orchestrator.py [TARGET OPTIONS] [TOOL OPTIONS] [OUTPUT OPTIONS]

Assessment objective (use one or more):
  -d, --domain DOMAIN            Target apex domain
  -u, --url URL                  Target URL (enables HTTP/web tool subset)
  -H, --host HOST[:PORT]         Target IP or hostname with optional port
  -p, --path PATH                File path for secrets scanning
      --jwt TOKEN                JWT token for analysis
      --cve CVE-ID [CVE-ID ...]  CVE identifiers to analyze

Tool selection:
      --tools TOOL,...           Comma-separated tool names, or 'all' (default: auto-select)
      --skip TOOL,...            Tools to exclude from the run
      --tool-dir DIR             Directory containing VSL tools (default: parent dir)
      --python PATH              Python interpreter to use for tool execution

Execution:
      --parallel                 Run tools in parallel instead of sequentially
      --max-parallel N           Maximum simultaneous tool processes (default: 3)
      --timeout N                Per-tool execution timeout in seconds (default: 300)
      --log-dir DIR              Directory for per-tool execution logs

Output:
      --json FILE                Write unified findings to JSON
      --html FILE                Generate unified HTML report
```

---

## Examples

Full domain assessment using auto-selected tools:

```bash
python vamp_orchestrator.py -d example.com --json assessment.json --html report.html
```

Host assessment targeting a specific IP and port:

```bash
python vamp_orchestrator.py -H 203.0.113.1:443 --json host_findings.json
```

Domain assessment in parallel mode with a 5-tool concurrency limit:

```bash
python vamp_orchestrator.py -d example.com --parallel --max-parallel 5 --html full_report.html
```

Run only specific tools against a domain:

```bash
python vamp_orchestrator.py -d example.com \
  --tools vamp-passive-recon,vamp-subdomain-takeover,vamp-cloud-enum \
  --json selected_tools.json
```

CVE batch analysis via orchestrator (delegates to vamp-cve-oracle):

```bash
python vamp_orchestrator.py --cve CVE-2024-21762 CVE-2023-27997 CVE-2022-40684 \
  --json cve_report.json
```

---

## Output Formats

| Format | How to enable | Description |
|--------|---------------|-------------|
| Console | Default | Rich execution log with per-tool status, finding counts, and composite score |
| JSON | `--json FILE` | Deduplicated unified findings from all tools with source attribution |
| HTML | `--html FILE` | Standalone consolidated report via `vampsec_report` |
| Per-tool logs | `--log-dir DIR` | Raw stdout/stderr per tool for debugging and audit trail |

---

## Exit Codes

| Code | Meaning | CI/CD usage |
|------|---------|-------------|
| `0` | No findings — all tools clean | Pass gate |
| `1` | HIGH findings in the unified set | Review recommended |
| `2` | CRITICAL findings detected | Fail gate — escalate immediately |

---

## Risk Scoring

The composite score is computed from deduplicated findings across all tools:

| Severity | Points |
|----------|--------|
| CRITICAL | 25 |
| HIGH | 10 |
| MEDIUM | 5 |
| LOW | 1 |
| INFO | 0 |

Score is capped at 100. Duplicate findings (same severity + first 60 characters of title from different tools) are merged into a single finding and counted once.

---

## Auto-Selected Tool Subsets

| Objective flag | Tools auto-selected |
|----------------|-------------------|
| `-d` (domain) | passive-recon, ssl-audit, http-scanner, cloud-enum, subdomain-takeover, mail-security |
| `-H` (host) | ssl-audit, forticheck |
| `-u` (URL) | http-scanner, ssl-audit, secrets-scanner |
| `-p` (path) | secrets-scanner |
| `--cve` | cve-oracle |

---

## Part of VampSecure Labs Toolkit

`vamp-orchestrator` is part of the **VampSecure Labs Security Research Toolkit** — a collection of professional-grade, self-hosted security assessment tools.

| Tool | Purpose |
|------|---------|
| [vamp-forticheck](https://github.com/belky-me/vamp-forticheck) | Multi-vendor edge device CVE scanner |
| [vamp-cve-oracle](https://github.com/belky-me/vamp-cve-oracle) | CVE intelligence and RBVM engine |
| [vamp-passive-recon](https://github.com/belky-me/vamp-passive-recon) | Passive recon and attack surface mapping |
| [vamp-subdomain-takeover](https://github.com/belky-me/vamp-subdomain-takeover) | Subdomain takeover vulnerability scanner |
| [vamp-cloud-enum](https://github.com/belky-me/vamp-cloud-enum) | Cloud storage bucket enumerator |
| [vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator) | Multi-tool assessment orchestrator |

---

<p align="center">
  © VampSecure Studios — VampSecure Labs Security Research Division<br/>
  For authorized security assessments only. Unauthorized use is prohibited.
</p>
