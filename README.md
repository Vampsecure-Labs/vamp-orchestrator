<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
<p align="center">
  <img src="https://img.shields.io/badge/version-2.6-crimson?style=flat-square" />
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/tools-16%20VSL%20slots-teal?style=flat-square" />
  <img src="https://img.shields.io/badge/VampSecure_Labs-Security_Research-8b0000?style=flat-square" />
  <img src="https://github.com/Vampsecure-Labs/vamp-orchestrator/actions/workflows/ci.yml/badge.svg" alt="CI"/>
</p>

<h1 align="center">vamp-orchestrator</h1>
<p align="center"><em>Multi-Tool Security Assessment Orchestrator — VampSecure Labs</em></p>

> 🇬🇧 [English](#english) · 🇪🇸 [Español](#español)

---

<a name="english"></a>
## 🇬🇧 English

**vamp-orchestrator** is the meta-orchestrator for the VampSecure Labs toolkit. It auto-discovers installed VSL tools, selects the appropriate subset based on the assessment objective (domain, URL, host, path, log directory, Kubernetes cluster, or LLM endpoint), executes them sequentially or in parallel, deduplicates findings across tools, and produces a unified risk-scored report.

Each tool result is parsed by a dedicated extractor, normalized to the VSL finding schema, and merged into a single deduplicated finding set. Findings from forensic log analysis preserve their MITRE ATT&CK mapping (tactic, technique). A logarithmic composite risk score differentiates engagements with few versus many high-severity findings.

---

### Features

- Auto-discovery of up to **16 VampSecure Labs tool slots** in the tool directory
- Objective-driven tool selection: domain, URL, host, path, JWT, log directory, K8s context, LLM endpoint, and CVE targets each trigger a different tool subset
- Sequential and parallel execution modes with configurable parallelism limit
- **Improved deduplication**: findings matched by `severity + title[:60] + affected[:30]` — same finding type on different hosts is never collapsed
- **Logarithmic risk scoring**: `score = 100 × (1 − e^(−raw/75))` — differentiates engagements with 4 vs. 20 critical findings instead of saturating at the same value
- Dedicated extractor for `vamp-log-analyzer` preserving MITRE ATT&CK fields (`mitre_tactic`, `mitre_technique`, `event_count`)
- Auto-detection of Docker daemon and `kubectl` availability for containerized target selection
- Unified JSON (`schema_version: 2.2`) and HTML reporting
- Custom tool path and Python interpreter configuration for virtual environment isolation

---

### Requirements

```
Python 3.11+
rich >= 13.7.0
```

Individual tool dependencies must be installed per their own `requirements.txt`.

```bash
pip install -r requirements.txt
```

---

### Installation

```bash
pip install vamp-orchestrator
# or with Homebrew:
brew install vampsecure-labs/labs/vamp-orchestrator
```

```bash
git clone https://github.com/Vampsecure-Labs/vamp-orchestrator.git
cd vamp-orchestrator
pip install -r requirements.txt
```

Ensure the other VSL tools are present in the same directory and their dependencies installed.

---

### Usage

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

### Examples

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

### Output Formats

| Format | How to enable | Description |
|--------|---------------|-------------|
| Console | Default | Rich execution log with per-tool status, finding counts, and composite score |
| JSON | `--json FILE` | Deduplicated unified findings (schema_version 2.2) |
| HTML | `--html FILE` | Standalone consolidated dark-theme report |

---

### Exit Codes

| Code | Meaning | CI/CD usage |
|------|---------|-------------|
| `0` | No findings — all tools clean | Pass gate |
| `1` | HIGH findings in the unified set | Review recommended |
| `2` | CRITICAL findings detected | Fail gate — escalate immediately |

---

### Risk Scoring

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

### Auto-Selected Tool Subsets

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

### Tool Catalog (v2.6)

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

### Sample Output

```bash
$ python vamp_orchestrator.py -d example.com \
    --log-dir /var/log/nginx \
    --parallel --max-parallel 4 \
    --json assessment.json --html report.html
```

```
╭──────────────────────────────────────────────────────────────────────────────╮
│  vamp-orchestrator v2.6 · VampSecure Labs Security Research Division         │
│  Target: example.com  ·  Log dir: /var/log/nginx  ·  Mode: parallel (4)     │
╰──────────────────────────────────────────────────────────────────────────────╯

Auto-selecting tools for objectives: domain + log-dir
  Tools selected: recon, ssl, http, mail, cloud, takeover, forensic

[1/7] vamp-passive-recon       running …  ✓  3 findings (1 HIGH, 2 MEDIUM)                4.2s
[2/7] vamp-ssl-audit           running …  ✓  2 findings (1 HIGH, 1 LOW)                   1.8s
[3/7] vamp-http-audit          running …  ✓  5 findings (2 HIGH, 3 MEDIUM)               3.1s
[4/7] vamp-mail-audit          running …  ✓  1 finding  (1 MEDIUM)                        1.3s
[5/7] vamp-cloud-enum          running …  ✓  0 findings                                   2.7s
[6/7] vamp-subdomain-takeover  running …  ✓  1 finding  (1 CRITICAL)                      5.6s
[7/7] vamp-log-analyzer        running …  ✓  4 findings (1 CRITICAL, 2 HIGH, 1 MEDIUM)   12.4s

Deduplication: 16 raw findings → 15 unique (1 merged across tools)

╭────────────────────────────── Unified Findings ──────────────────────────────╮
│ ID         │ Tool       │ Sev.      │ Title                                   │
│ SDT-007    │ takeover   │ 💀 CRIT   │ Subdomain takeover: cdn.example.com     │
│ FORA-001   │ forensic   │ 💀 CRIT   │ Brute force — 2.847 failed logins       │
│ HTTP-019   │ http       │ 🔴 HIGH   │ Missing Content-Security-Policy         │
│ RECON-003  │ recon      │ 🔴 HIGH   │ GitHub dork: .env file exposed          │
│ SSL-002    │ ssl        │ 🔴 HIGH   │ TLS 1.0 enabled                         │
│ FORA-009   │ forensic   │ 🔴 HIGH   │ Reconnaissance scan pattern             │
│ …          │ …          │ …         │ …                                       │
╰──────────────────────────────────────────────────────────────────────────────╯

Risk score: raw=185  →  score=91/100  [Critical]

Unified JSON  → assessment.json
HTML report   → report.html
Total time:     31.1 s
```

---

### Why vamp-orchestrator vs. DefectDojo · Plextrac

| Capability | vamp-orchestrator | DefectDojo | Plextrac |
|---|---|---|---|
| Auto-tool selection by objective | ✅ | ❌ (manual import) | ❌ |
| Natively runs VSL tools | ✅ | ❌ (ingestion only) | ❌ |
| Cross-tool deduplication | ✅ | ✅ | ✅ |
| Logarithmic scoring (does not saturate with many findings) | ✅ | ❌ | ❌ |
| MITRE ATT&CK preservation (FORA-NNN) | ✅ | ✅ | ✅ |
| Self-hosted, no external APIs | ✅ | ✅ | ❌ (SaaS) |
| Single-command CLI | ✅ | ❌ (web interface) | ❌ (web interface) |
| Open source / AGPL | ✅ | ✅ | ❌ (commercial) |

- Runs the full VSL toolkit in a single command without manually importing files or opening a web panel.
- Automatic tool selection by objective ensures uniform coverage across engagements and eliminates configuration errors.
- Cross-tool deduplication prevents the same finding from appearing multiple times when detected by two different tools on the same host.
- Logarithmic scoring differentiates a target with 1 CRITICAL from one with 8, instead of saturating both to the same maximum value.

---

### Orchestration Coverage

| Tool slot | VSL Tool | Finding types aggregated | Trigger |
|---|---|---|---|
| `recon` | vamp-passive-recon | OSINT, subdomains, HTTP headers, Shodan CVEs | `-d` domain |
| `ssl` | vamp-ssl-audit | Certificates, TLS/SSL protocols, cipher suites | `-H` host / `-d` |
| `http` | vamp-http-audit | HTTP security headers, WAF, insecure redirects | `-u` / `-d` |
| `wp` | vamp-wp2shell-audit | Vulnerable WordPress plugins, exposed users | `-u` / `-d` |
| `secrets` | vamp-secrets-scanner | Hardcoded credentials, tokens, private keys | `-p` path |
| `forensic` | vamp-log-analyzer | 25 MITRE ATT&CK detectors in logs (brute force, RCE, exfil…) | `--log-dir` |
| `takeover` | vamp-subdomain-takeover | Orphan subdomains (CNAME → active external service) | `-d` |
| `k8s` | vamp-k8s-audit | RBAC, privileged pods, plaintext secrets, network policies | `--k8s-context` |
| `docker` | vamp-docker-audit | Exposed daemons, unsigned images, dangerous capabilities | auto (docker daemon) |
| `cloud` | vamp-cloud-enum | Public S3/GCS/Azure buckets, exposed cloud assets | `-d` |
| `entropy` | vamp-entropy-watch | Files with anomalous entropy (ransomware, exfiltration) | `-p` path |
| `llm` | vamp-llm-probe | Prompt injection, jailbreak, info disclosure on LLM endpoints | `--llm-endpoint` |
| `mail` | vamp-mail-audit | Missing or misconfigured SPF / DKIM / DMARC | `-d` |
| `cve` | vamp-cve-oracle | CVE/CVSS correlation by software version or library | `--cve` |
| `fort` | vamp-forticheck | CVEs in network devices (Fortinet, Cisco, Palo Alto) | `-H` host |
| `jwt` | vamp-jwt-audit | alg=none, insecure claims, excessive TTL, audience in JWT tokens | `--jwt` |

---

### Part of VampSecure Labs Toolkit

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

### Version History

| Version | Main changes |
|---------|-------------|
| v2.6 | Bilingual README (EN/ES) |
| v2.5 | Mobile/waf/windows tool slots; endpoint_hardening playbook |
| v2.4 | Built-in playbooks (`--playbook devops_audit\|cloud_posture`); 6 new tools in VSL_TOOLS (azure, gcp, ci, iac, supply, cloud_posture) |
| v2.3 | Telegram notifications (bot_token + chat_id in ~/.config/vampsec/config.toml) |
| v2.2 | Initial orchestrator: 19 tools, YAML pipeline (--config), diff, HTML/JSON report |

---

<p align="center">
  © VampSecure Studios — VampSecure Labs Security Research Division<br/>
  For authorized security assessments only. Unauthorized use is prohibited.
</p>

---

<a name="español"></a>
## 🇪🇸 Español

**vamp-orchestrator** es el meta-orquestador del toolkit de VampSecure Labs. Detecta automáticamente las herramientas VSL instaladas, selecciona el subconjunto adecuado según el objetivo de la evaluación (dominio, URL, host, ruta, directorio de logs, clúster Kubernetes o endpoint LLM), las ejecuta de forma secuencial o en paralelo, deduplica los hallazgos entre herramientas y genera un informe unificado con puntuación de riesgo.

Cada resultado de herramienta es parseado por un extractor dedicado, normalizado al esquema de hallazgos VSL y fusionado en un conjunto de hallazgos deduplicado. Los hallazgos del análisis forense de logs conservan su mapping MITRE ATT&CK (táctica, técnica). Una puntuación de riesgo compuesta logarítmica diferencia los engagements con pocos hallazgos de alta severidad frente a muchos.

---

### Características

- Auto-descubrimiento de hasta **16 slots de herramientas VampSecure Labs** en el directorio de herramientas
- Selección de herramientas guiada por objetivo: dominio, URL, host, ruta, JWT, directorio de logs, contexto K8s, endpoint LLM y objetivos CVE activan subconjuntos de herramientas diferentes
- Modos de ejecución secuencial y en paralelo con límite de paralelismo configurable
- **Deduplicación mejorada**: hallazgos comparados por `severity + title[:60] + affected[:30]` — el mismo tipo de hallazgo en hosts distintos nunca se colapsa
- **Scoring logarítmico**: `score = 100 × (1 − e^(−raw/75))` — diferencia engagements con 4 vs. 20 hallazgos críticos en lugar de saturar al mismo valor
- Extractor dedicado para `vamp-log-analyzer` que preserva los campos MITRE ATT&CK (`mitre_tactic`, `mitre_technique`, `event_count`)
- Auto-detección del daemon de Docker y disponibilidad de `kubectl` para la selección de objetivos en contenedores
- Informes unificados JSON (`schema_version: 2.2`) y HTML
- Configuración de ruta de herramientas e intérprete Python personalizados para aislamiento en entornos virtuales

---

### Requisitos

```
Python 3.11+
rich >= 13.7.0
```

Las dependencias individuales de cada herramienta deben instalarse con su propio `requirements.txt`.

```bash
pip install -r requirements.txt
```

---

### Instalación

```bash
pip install vamp-orchestrator
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-orchestrator
```

```bash
git clone https://github.com/Vampsecure-Labs/vamp-orchestrator.git
cd vamp-orchestrator
pip install -r requirements.txt
```

Asegúrate de que las demás herramientas VSL estén en el mismo directorio y sus dependencias instaladas.

---

### Uso

```
python vamp_orchestrator.py [OPCIONES DE TARGET] [OPCIONES DE HERRAMIENTAS] [OPCIONES DE SALIDA]

Objetivos de evaluación (usar uno o más):
  -d, --domain DOMINIO           Dominio apex objetivo
  -u, --url URL                  URL objetivo (activa subconjunto de herramientas HTTP/web)
  -H, --host HOST[:PUERTO]       IP o hostname objetivo con puerto opcional
  -p, --path RUTA                Ruta del sistema de ficheros para escaneo de secretos y entropía
      --log-dir DIR              Directorio de logs para análisis forense (vamp-log-analyzer)
      --jwt TOKEN                Token JWT para análisis
      --cve CVE-ID [CVE-ID ...]  Identificadores CVE a analizar
      --k8s-context CONTEXTO     Contexto Kubernetes para auditoría de clúster (omitir = contexto activo)
      --llm-endpoint URL         Endpoint LLM para sondeo de seguridad IA

Selección de herramientas:
      --tools HERR,...           Nombres de herramientas separados por coma, o 'all' (por defecto: auto-selección)
      --skip HERR,...            Herramientas a excluir de la ejecución
      --tool-dir DIR             Directorio con herramientas VSL (por defecto: directorio padre)
      --python RUTA              Intérprete Python para la ejecución de herramientas

Ejecución:
      --parallel                 Ejecutar herramientas en paralelo en lugar de secuencialmente
      --max-parallel N           Máximo de procesos simultáneos (por defecto: 3)
      --timeout N                Timeout por herramienta en segundos (por defecto: 300)

Salida:
      --json FICHERO             Guardar hallazgos unificados en JSON
      --html FICHERO             Generar informe HTML unificado
```

---

### Ejemplos

Evaluación completa de dominio con herramientas auto-seleccionadas:

```bash
python vamp_orchestrator.py -d example.com --json assessment.json --html report.html
```

Dominio + análisis forense de logs en paralelo:

```bash
python vamp_orchestrator.py -d example.com \
  --log-dir /var/log/nginx \
  --parallel --max-parallel 5 \
  --html informe_completo.html
```

Auditoría de clúster Kubernetes con contexto nombrado:

```bash
python vamp_orchestrator.py --k8s-context prod-cluster --json k8s_findings.json
```

Evaluación de seguridad de endpoint LLM:

```bash
python vamp_orchestrator.py --llm-endpoint http://localhost:11434 --json llm_audit.json
```

Escaneo de ruta (secretos + anomalías de entropía):

```bash
python vamp_orchestrator.py -p /opt/myapp --json path_scan.json
```

Análisis por lotes de CVEs:

```bash
python vamp_orchestrator.py --cve CVE-2024-21762 CVE-2023-27997 CVE-2022-40684 \
  --json cve_report.json
```

---

### Formatos de salida

| Formato | Cómo activarlo | Descripción |
|---------|----------------|-------------|
| Consola | Por defecto | Log de ejecución Rich con estado por herramienta, conteo de hallazgos y puntuación compuesta |
| JSON | `--json FICHERO` | Hallazgos unificados deduplicados (schema_version 2.2) |
| HTML | `--html FICHERO` | Informe dark-theme consolidado y autocontenido |

---

### Exit codes

| Código | Significado | Uso en CI/CD |
|--------|-------------|-------------|
| `0` | Sin hallazgos — todas las herramientas limpias | Pasar gate |
| `1` | Hallazgos HIGH en el conjunto unificado | Revisión recomendada |
| `2` | Hallazgos CRITICAL detectados | Fallar gate — escalar inmediatamente |

---

### Scoring de riesgo

La puntuación compuesta usa una escala logarítmica que satura de forma gradual a medida que se acumulan hallazgos:

```
raw   = CRITICAL×25 + HIGH×10 + MEDIUM×5 + LOW×1
score = 100 × (1 − e^(−raw/75))
```

| Escenario | raw | Score |
|-----------|-----|-------|
| 1 CRITICAL | 25 | 28 |
| 4 CRITICALs | 100 | 74 |
| 8 CRITICALs | 200 | 93 |
| 5 HIGHs | 50 | 49 |
| 10 MEDIUMs | 50 | 49 |

Los hallazgos duplicados (misma severidad + título + host afectado) se fusionan y se cuentan una sola vez.

---

### Subconjuntos de herramientas auto-seleccionados

| Flag de objetivo | Herramientas auto-seleccionadas |
|------------------|-------------------------------|
| `-d` (dominio) | passive-recon, ssl, http, wp, mail, cloud, **takeover** |
| `-H` (host) | ssl, forticheck |
| `-u` (URL) | http, wp; ssl + recon si no hay dominio/host |
| `-p` (ruta) | secrets-scanner, **entropy-watch** |
| `--log-dir` | **forensic** (vamp-log-analyzer con MITRE ATT&CK) |
| `--k8s-context` o kubectl presente | **k8s-audit** |
| `--llm-endpoint` | **llm-probe** |
| `--cve` | cve-oracle |
| Daemon Docker accesible | docker-audit |

---

### Catálogo de herramientas (v2.5)

| Slot | Script | Prefijo | Trigger |
|------|--------|---------|---------|
| `recon` | vamp_passive_recon.py | RECON | dominio |
| `ssl` | vamp_ssl_audit.py | SSL | host / dominio |
| `http` | vamp_http_audit.py | HTTP | url / dominio |
| `wp` | vamp_wp2shell_audit.py | WP | url / dominio |
| `secrets` | vamp_secrets_scanner.py | SEC | ruta |
| `jwt` | vamp_jwt_audit.py | JWT | --jwt |
| `mail` | vamp_mail_audit.py | MAIL | dominio |
| `docker` | vamp_docker_audit.py | DOCK | auto (daemon docker) |
| `forensic` | vamp_log_analyzer.py | FORA | --log-dir |
| `cloud` | vamp_cloud_enum.py | CLOUD | dominio |
| `fort` | vamp_forticheck.py | FTC | host |
| `cve` | vamp_cve_oracle.py | RBVM | --cve |
| `takeover` | vamp_subdomain_takeover.py | SDT | dominio |
| `k8s` | vamp_k8s_audit.py | K8S | auto (kubectl) / --k8s-context |
| `entropy` | vamp_entropy_watch.py | ENT | ruta |
| `llm` | vamp_llm_probe.py | LLM | --llm-endpoint |

---

### Why vamp-orchestrator vs. DefectDojo · Plextrac

| Capacidad | vamp-orchestrator | DefectDojo | Plextrac |
|---|---|---|---|
| Auto-selección de tools por objetivo | ✅ | ❌ (importación manual) | ❌ |
| Ejecuta tools VSL de forma nativa | ✅ | ❌ (solo ingesta) | ❌ |
| Deduplicación cross-tool | ✅ | ✅ | ✅ |
| Scoring logarítmico (no satura con muchos findings) | ✅ | ❌ | ❌ |
| Preservación de MITRE ATT&CK (FORA-NNN) | ✅ | ✅ | ✅ |
| Self-hosted, sin APIs externas | ✅ | ✅ | ❌ (SaaS) |
| CLI de un único comando | ✅ | ❌ (interfaz web) | ❌ (interfaz web) |
| Open source / AGPL | ✅ | ✅ | ❌ (comercial) |

- Ejecuta todo el toolkit VSL en un único comando sin importar ficheros manualmente ni abrir un panel web.
- La selección automática de herramientas por objetivo garantiza cobertura uniforme entre engagements y elimina errores de configuración.
- La deduplicación cross-tool evita que el mismo hallazgo aparezca varias veces por haber sido detectado por dos herramientas distintas sobre el mismo host.
- El scoring logarítmico diferencia un objetivo con 1 CRITICAL de uno con 8, en lugar de saturar ambos al mismo valor máximo.

---

### Cobertura de orquestación

| Slot herramienta | Herramienta VSL | Tipo de findings que agrega | Trigger |
|---|---|---|---|
| `recon` | vamp-passive-recon | OSINT, subdominios, headers HTTP, Shodan CVEs | `-d` dominio |
| `ssl` | vamp-ssl-audit | Certificados, protocolos TLS/SSL, cipher suites | `-H` host / `-d` |
| `http` | vamp-http-audit | Cabeceras de seguridad HTTP, WAF, redirecciones inseguras | `-u` / `-d` |
| `wp` | vamp-wp2shell-audit | Plugins WordPress vulnerables, usuarios expuestos | `-u` / `-d` |
| `secrets` | vamp-secrets-scanner | Credenciales hardcodeadas, tokens, claves privadas | `-p` ruta |
| `forensic` | vamp-log-analyzer | 25 detectores MITRE ATT&CK en logs (brute force, RCE, exfil…) | `--log-dir` |
| `takeover` | vamp-subdomain-takeover | Subdominios huérfanos (CNAME → servicio externo activo) | `-d` |
| `k8s` | vamp-k8s-audit | RBAC, pods privilegiados, secretos en claro, network policies | `--k8s-context` |
| `docker` | vamp-docker-audit | Daemons expuestos, imágenes sin firmar, capabilities peligrosas | auto (docker daemon) |
| `cloud` | vamp-cloud-enum | Buckets S3/GCS/Azure públicos, assets cloud expuestos | `-d` |
| `entropy` | vamp-entropy-watch | Ficheros con entropía anómala (ransomware, exfiltración) | `-p` ruta |
| `llm` | vamp-llm-probe | Prompt injection, jailbreak, info disclosure en endpoints LLM | `--llm-endpoint` |
| `mail` | vamp-mail-audit | SPF / DKIM / DMARC ausentes o mal configurados | `-d` |
| `cve` | vamp-cve-oracle | Correlación CVE/CVSS por versión de software o biblioteca | `--cve` |
| `fort` | vamp-forticheck | CVEs en dispositivos de red (Fortinet, Cisco, Palo Alto) | `-H` host |
| `jwt` | vamp-jwt-audit | alg=none, claims inseguros, TTL excesivo, audience en tokens JWT | `--jwt` |

---

### Parte del toolkit VampSecure Labs

`vamp-orchestrator` forma parte del **VampSecure Labs Security Research Toolkit**.

| Herramienta | Propósito |
|-------------|-----------|
| [vamp-passive-recon](https://github.com/Vampsecure-Labs/vamp-passive-recon) | Reconocimiento pasivo y ASM |
| [vamp-subdomain-takeover](https://github.com/Vampsecure-Labs/vamp-subdomain-takeover) | Escáner de subdomain takeover |
| [vamp-log-analyzer](https://github.com/Vampsecure-Labs/vamp-log-analyzer) | Análisis forense de logs — 25 detectores MITRE ATT&CK |
| [vamp-k8s-audit](https://github.com/Vampsecure-Labs/vamp-k8s-audit) | Auditoría de seguridad de clústeres Kubernetes |
| [vamp-entropy-watch](https://github.com/Vampsecure-Labs/vamp-entropy-watch) | Detector de ransomware/exfiltración por entropía |
| [vamp-llm-probe](https://github.com/Vampsecure-Labs/vamp-llm-probe) | Evaluación de seguridad de endpoints LLM |
| [vamp-penreport](https://github.com/Vampsecure-Labs/vamp-penreport) | Agregador de informes ejecutivos |

---

### Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v2.6 | README bilingüe (EN/ES) |
| v2.5 | Slots mobile/waf/windows; playbook endpoint_hardening |
| v2.4 | Playbooks integrados (`--playbook devops_audit\|cloud_posture`); 6 tools nuevas en VSL_TOOLS (azure, gcp, ci, iac, supply, cloud_posture) |
| v2.3 | Notificaciones Telegram (bot_token + chat_id en ~/.config/vampsec/config.toml) |
| v2.2 | Orquestador inicial: 19 tools, pipeline YAML (--config), diff, informe HTML/JSON |

---

<p align="center">
  © VampSecure Studios — VampSecure Labs Security Research Division<br/>
  Solo para evaluaciones de seguridad autorizadas. El uso no autorizado está prohibido.
</p>
