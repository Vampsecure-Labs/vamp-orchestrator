<p align="center">
  <img src="https://img.shields.io/badge/version-2.0-crimson?style=flat-square" />
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/tools-16%20VSL%20slots-teal?style=flat-square" />
  <img src="https://img.shields.io/badge/VampSecure_Labs-Security_Research-8b0000?style=flat-square" />
</p>

<h1 align="center">vamp-orchestrator</h1>
<p align="center"><em>Multi-Tool Security Assessment Orchestrator — VampSecure Labs</em></p>

---

## Overview

**vamp-orchestrator** is the meta-orchestrator for the VampSecure Labs toolkit. It auto-discovers installed VSL tools, selects the appropriate subset based on the assessment objective (domain, URL, host, path, log directory, Kubernetes cluster, or LLM endpoint), executes them sequentially or in parallel, deduplicates findings across tools, and produces a unified risk-scored report.

Each tool result is parsed by a dedicated extractor, normalized to the VSL finding schema, and merged into a single deduplicated finding set. Findings from forensic log analysis preserve their MITRE ATT&CK mapping (tactic, technique). A logarithmic composite risk score differentiates engagements with few versus many high-severity findings.

---

## Features

- Auto-discovery of up to **16 VampSecure Labs tool slots** in the tool directory
- Objective-driven tool selection: domain, URL, host, path, JWT, log directory, K8s context, LLM endpoint, and CVE targets each trigger a different tool subset
- Sequential and parallel execution modes with configurable parallelism limit
- **Improved deduplication**: findings matched by `severity + title[:60] + affected[:30]` — same finding type on different hosts is never collapsed
- **Logarithmic risk scoring**: `score = 100 × (1 − e^(−raw/75))` — differentiates engagements with 4 vs. 20 critical findings instead of saturating at the same value
- Dedicated extractor for `vamp-log-analyzer` preserving MITRE ATT&CK fields (`mitre_tactic`, `mitre_technique`, `event_count`)
- Auto-detection of Docker daemon and `kubectl` availability for containerized target selection
- Unified JSON (`schema_version: 2.0`) and HTML reporting
- Custom tool path and Python interpreter configuration for virtual environment isolation

---

## Requirements

```
Python 3.11+
rich >= 13.7.0
```

Individual tool dependencies must be installed per their own `requirements.txt`.

```bash
pip install -r requirements.txt
```

---

## Installation

```bash
git clone https://github.com/Vampsecure-Labs/vamp-orchestrator.git
cd vamp-orchestrator
pip install -r requirements.txt
```

Ensure the other VSL tools are present in the same directory and their dependencies installed.

---

## Usage

```
python vamp_orchestrator.py [TARGET OPTIONS] [TOOL OPTIONS] [OUTPUT OPTIONS]

Assessment objectives (use one or more):
  -d, --domain DOMAIN            Target apex domain
  -u, --url URL                  Target URL (enables HTTP/web tool subset)
  -H, --host HOST[:PORT]         Target IP or hostname with optional port
  -p, --path PATH                File system path for secrets and entropy scanning
      --log-dir DIR              Directory of logs for forensic analysis (vamp-log-analyzer)
      --jwt TOKEN                JWT token for analysis
      --cve CVE-ID [CVE-ID ...]  CVE identifiers to analyze
      --k8s-context CONTEXT      Kubernetes context for cluster audit (omit = active context)
      --llm-endpoint URL         LLM endpoint for AI security probing

Tool selection:
      --tools TOOL,...           Comma-separated tool names, or 'all' (default: auto-select)
      --skip TOOL,...            Tools to exclude from the run
      --tool-dir DIR             Directory containing VSL tools (default: parent dir)
      --python PATH              Python interpreter to use for tool execution

Execution:
      --parallel                 Run tools in parallel instead of sequentially
      --max-parallel N           Maximum simultaneous tool processes (default: 3)
      --timeout N                Per-tool execution timeout in seconds (default: 300)

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

Domain + forensic log analysis in parallel:

```bash
python vamp_orchestrator.py -d example.com \
  --log-dir /var/log/nginx \
  --parallel --max-parallel 5 \
  --html full_report.html
```

Kubernetes cluster audit using a named context:

```bash
python vamp_orchestrator.py --k8s-context prod-cluster --json k8s_findings.json
```

LLM endpoint security assessment:

```bash
python vamp_orchestrator.py --llm-endpoint http://localhost:11434 --json llm_audit.json
```

Path scan (secrets + entropy anomalies):

```bash
python vamp_orchestrator.py -p /opt/myapp --json path_scan.json
```

CVE batch analysis:

```bash
python vamp_orchestrator.py --cve CVE-2024-21762 CVE-2023-27997 CVE-2022-40684 \
  --json cve_report.json
```

---

## Output Formats

| Format | How to enable | Description |
|--------|---------------|-------------|
| Console | Default | Rich execution log with per-tool status, finding counts, and composite score |
| JSON | `--json FILE` | Deduplicated unified findings (schema_version 2.0) |
| HTML | `--html FILE` | Standalone consolidated dark-theme report |

---

## Exit Codes

| Code | Meaning | CI/CD usage |
|------|---------|-------------|
| `0` | No findings — all tools clean | Pass gate |
| `1` | HIGH findings in the unified set | Review recommended |
| `2` | CRITICAL findings detected | Fail gate — escalate immediately |

---

## Risk Scoring

The composite score uses a logarithmic scale that saturates gracefully as findings accumulate:

```
raw   = CRITICAL×25 + HIGH×10 + MEDIUM×5 + LOW×1
score = 100 × (1 − e^(−raw/75))
```

| Scenario | raw | Score |
|----------|-----|-------|
| 1 CRITICAL | 25 | 28 |
| 4 CRITICALs | 100 | 74 |
| 8 CRITICALs | 200 | 93 |
| 5 HIGHs | 50 | 49 |
| 10 MEDIUMs | 50 | 49 |

Duplicate findings (same severity + title + affected host) are merged and counted once.

---

## Auto-Selected Tool Subsets

| Objective flag | Tools auto-selected |
|----------------|-------------------|
| `-d` (domain) | passive-recon, ssl, http, wp, mail, cloud, **takeover** |
| `-H` (host) | ssl, forticheck |
| `-u` (URL) | http, wp; ssl + recon if no domain/host |
| `-p` (path) | secrets-scanner, **entropy-watch** |
| `--log-dir` | **forensic** (vamp-log-analyzer with MITRE ATT&CK) |
| `--k8s-context` or kubectl present | **k8s-audit** |
| `--llm-endpoint` | **llm-probe** |
| `--cve` | cve-oracle |
| Docker daemon accessible | docker-audit |

---

## Tool Catalog (v2.0)

| Slot | Script | Prefix | Trigger |
|------|--------|--------|---------|
| `recon` | vamp_passive_recon.py | RECON | domain |
| `ssl` | vamp_ssl_audit.py | SSL | host / domain |
| `http` | vamp_http_audit.py | HTTP | url / domain |
| `wp` | vamp_wp2shell_audit.py | WP | url / domain |
| `secrets` | vamp_secrets_scanner.py | SEC | path |
| `jwt` | vamp_jwt_audit.py | JWT | --jwt |
| `mail` | vamp_mail_audit.py | MAIL | domain |
| `docker` | vamp_docker_audit.py | DOCK | auto (docker daemon) |
| `forensic` | vamp_log_analyzer.py | FORA | --log-dir |
| `cloud` | vamp_cloud_enum.py | CLOUD | domain |
| `fort` | vamp_forticheck.py | FTC | host |
| `cve` | vamp_cve_oracle.py | RBVM | --cve |
| `takeover` | vamp_subdomain_takeover.py | SDT | domain |
| `k8s` | vamp_k8s_audit.py | K8S | auto (kubectl) / --k8s-context |
| `entropy` | vamp_entropy_watch.py | ENT | path |
| `llm` | vamp_llm_probe.py | LLM | --llm-endpoint |

---

## Part of VampSecure Labs Toolkit

`vamp-orchestrator` is part of the **VampSecure Labs Security Research Toolkit**.

| Tool | Purpose |
|------|---------|
| [vamp-passive-recon](https://github.com/Vampsecure-Labs/vamp-passive-recon) | Passive recon and ASM |
| [vamp-subdomain-takeover](https://github.com/Vampsecure-Labs/vamp-subdomain-takeover) | Subdomain takeover scanner |
| [vamp-log-analyzer](https://github.com/Vampsecure-Labs/vamp-log-analyzer) | Forensic log analysis — 25 MITRE ATT&CK detectors |
| [vamp-k8s-audit](https://github.com/Vampsecure-Labs/vamp-k8s-audit) | Kubernetes cluster security audit |
| [vamp-entropy-watch](https://github.com/Vampsecure-Labs/vamp-entropy-watch) | Entropy-based ransomware / exfil detector |
| [vamp-llm-probe](https://github.com/Vampsecure-Labs/vamp-llm-probe) | LLM endpoint security assessment |
| [vamp-penreport](https://github.com/Vampsecure-Labs/vamp-penreport) | Executive report aggregator |

---

<p align="center">
  © VampSecure Studios — VampSecure Labs Security Research Division<br/>
  For authorized security assessments only. Unauthorized use is prohibited.
</p>
