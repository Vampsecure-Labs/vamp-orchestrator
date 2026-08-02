#!/usr/bin/env python3
"""
vamp_orchestrator.py — Meta-orquestador VampSecure Labs
========================================================
© VampSecure Studios — VampSecure Labs Security Research Division
Para Uso Exclusivo en Pruebas de Penetración Autorizadas

DESCRIPCIÓN
-----------
Meta-herramienta de orquestación para el toolkit VampSecure Labs. Descubre
las herramientas VSL instaladas en el mismo directorio o en el PATH, las
ejecuta contra los objetivos especificados, recopila sus salidas JSON y
fusiona todos los resultados en un único informe consolidado de auditoría.

Características
---------------
  · Descubrimiento automático de herramientas VSL disponibles
  · Selección automática de herramientas según objetivos proporcionados
  · Ejecución secuencial o paralela con control de concurrencia
  · Seguimiento de progreso en tiempo real (Rich Live)
  · Deduplicación de hallazgos similares entre herramientas
  · Cálculo de puntuación de riesgo compuesta (0–100)
  · Generación de informe HTML unificado dark-theme
  · Exportación JSON estructurada con esquema VSL estándar

DEPENDENCIAS
------------
  rich>=13.7.0    pip install rich
  vampsec_report  (módulo compartido VSL, mismo directorio)

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape as _he
from pathlib import Path
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

from rich.columns import Columns
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from vampsec_report import (
    VampSecReport,
    add_report_args,
    meta_from_args,
    Finding as VSLFinding,
    SEVERITY_ORDER,
)

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

VERSION   = "1.0"
TOOL_NAME = "vamp-orchestrator"
AUTHOR    = "© VampSecure Studios — VampSecure Labs Security Research Division"

RISK_WEIGHTS: Dict[str, int] = {
    "CRITICAL": 25,
    "HIGH":     10,
    "MEDIUM":    5,
    "LOW":       1,
    "INFO":      0,
}

SEV_STYLE: Dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold magenta",
    "LOW":      "bold blue",
    "INFO":     "dim",
}

SEV_BADGE_COLOR: Dict[str, str] = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#d35400",
    "MEDIUM":   "#d4ac0d",
    "LOW":      "#2980b9",
    "INFO":     "#7f8c8d",
}

STATUS_ICON: Dict[str, str] = {
    "pending":  "⏳",
    "running":  "🔄",
    "done":     "✅",
    "error":    "❌",
    "skipped":  "⏭️",
}

# ---------------------------------------------------------------------------
# Catálogo de herramientas VSL
# ---------------------------------------------------------------------------

VSL_TOOLS: Dict[str, Dict] = {
    "recon":   {
        "script":    "vamp_passive_recon.py",
        "prefix":    "RECON",
        "needs":     ["domain"],
        "json_flag": "--json",
    },
    "ssl":     {
        "script":    "vamp_ssl_audit.py",
        "prefix":    "SSL",
        "needs":     ["host"],
        "json_flag": "--json",
    },
    "http":    {
        "script":    "vamp_http_audit.py",
        "prefix":    "HTTP",
        "needs":     ["url"],
        "json_flag": "--json",
    },
    "wp":      {
        "script":    "vamp_wp2shell_audit.py",
        "prefix":    "WP",
        "needs":     ["url"],
        "json_flag": "-o",
    },
    "secrets": {
        "script":    "vamp_secrets_scanner.py",
        "prefix":    "SEC",
        "needs":     ["path"],
        "json_flag": "-o",
    },
    "jwt":     {
        "script":    "vamp_jwt_audit.py",
        "prefix":    "JWT",
        "needs":     ["token"],
        "json_flag": "--json",
    },
    "mail":    {
        "script":    "vamp_mail_audit.py",
        "prefix":    "MAIL",
        "needs":     ["domain"],
        "json_flag": "--json",
    },
    "docker":  {
        "script":    "vamp_docker_audit.py",
        "prefix":    "DOCK",
        "needs":     [],
        "json_flag": "--json",
    },
    "logs":    {
        "script":    "vamp_log_hunter.py",
        "prefix":    "LOG",
        "needs":     ["log_dir"],
        "json_flag": "--json",
    },
    "cloud":   {
        "script":    "vamp_cloud_enum.py",
        "prefix":    "CLOUD",
        "needs":     ["domain"],
        "json_flag": "--json",
    },
    "fort":    {
        "script":    "vamp_forticheck.py",
        "prefix":    "FTC",
        "needs":     ["host"],
        "json_flag": "-o",
    },
    "cve":     {
        "script":    "vamp_cve_oracle.py",
        "prefix":    "RBVM",
        "needs":     ["cve"],
        "json_flag": "-o",
    },
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ToolRun:
    """Estado y resultados de la ejecución de una herramienta VSL."""
    name:           str
    script:         str
    status:         str = "pending"   # pending / running / done / error / skipped
    start_time:     Optional[float] = None
    end_time:       Optional[float] = None
    findings_count: int = 0
    findings:       List[dict] = field(default_factory=list)
    error_msg:      str = ""
    returncode:     int = 0

    @property
    def duration(self) -> float:
        """Duración en segundos (en curso si end_time es None)."""
        if self.start_time is None:
            return 0.0
        return (self.end_time or time.monotonic()) - self.start_time

    @property
    def duration_str(self) -> str:
        """Duración formateada como «mm:ss»."""
        secs = int(self.duration)
        return f"{secs // 60:02d}:{secs % 60:02d}"


@dataclass
class OrchestratorResult:
    """Resultado global de la orquestación completa."""
    target_domain: Optional[str]
    target_url:    Optional[str]
    target_host:   Optional[str]
    tools_run:     List[ToolRun]
    all_findings:  List[dict]
    risk_score:    int
    duration:      float


# ---------------------------------------------------------------------------
# Extracción de hallazgos por herramienta
# ---------------------------------------------------------------------------

def _norm_sev(s: str) -> str:
    """Normaliza una cadena de severidad al conjunto VSL estándar."""
    s = (s or "INFO").upper().strip()
    return s if s in SEVERITY_ORDER else "INFO"


def _make_finding(prefix: str, idx: int, severity: str, title: str,
                  description: str = "", evidence: str = "",
                  affected: str = "", remediation: str = "",
                  cvss: Optional[float] = None, cve: Optional[str] = None,
                  tags: Optional[List[str]] = None,
                  references: Optional[List[str]] = None) -> dict:
    """Crea un dict de hallazgo normalizado con formato VSL."""
    return {
        "id":          f"{prefix}-{idx:03d}",
        "severity":    _norm_sev(severity),
        "title":       (title or "Hallazgo sin título")[:200],
        "description": description or "",
        "evidence":    evidence or "",
        "affected":    (affected or "—")[:200],
        "remediation": remediation or "",
        "cvss":        cvss,
        "cve":         cve,
        "tags":        tags or [],
        "references":  references or [],
    }


def _extract_recon(data: dict, prefix: str) -> List[dict]:
    """
    Extrae hallazgos del JSON de vamp_passive_recon.

    Esquema fuente:
      headers.{host}[].findings[].{severity, name, message, remediation}
    """
    out: List[dict] = []
    idx = 1
    headers = data.get("headers", {})
    for host, reports in (headers.items() if isinstance(headers, dict) else []):
        for rep in (reports if isinstance(reports, list) else []):
            for f in rep.get("findings", []):
                out.append(_make_finding(
                    prefix, idx,
                    severity    = f.get("severity", "INFO"),
                    title       = f.get("name", f.get("title", "Cabecera de seguridad")),
                    description = f.get("message", f.get("description", "")),
                    evidence    = f.get("evidence", rep.get("url", host)),
                    affected    = host,
                    remediation = f.get("remediation", ""),
                    tags        = ["recon", "headers"],
                ))
                idx += 1
    # GitHub ASM findings
    asm = data.get("asm", {})
    for f in asm.get("github_findings", []):
        out.append(_make_finding(
            prefix, idx,
            severity    = f.get("severity", "HIGH"),
            title       = f.get("title", "Exposición en GitHub"),
            description = f.get("description", str(f.get("url", ""))),
            evidence    = f.get("url", ""),
            affected    = data.get("target", ""),
            remediation = f.get("remediation", "Revisar y eliminar datos sensibles del repositorio."),
            tags        = ["recon", "github", "asm"],
        ))
        idx += 1
    return out


def _extract_ssl_http(data: dict, prefix: str, tool_key: str) -> List[dict]:
    """
    Extrae hallazgos del JSON de vamp_ssl_audit y vamp_http_audit.

    Esquema fuente:
      results[].{host|url, findings[].{severity, name, detail, remediation}}
    """
    out: List[dict] = []
    idx = 1
    for result in data.get("results", []):
        affected = result.get("host", result.get("url", ""))
        if result.get("port"):
            affected = f"{affected}:{result['port']}"
        for f in result.get("findings", []):
            out.append(_make_finding(
                prefix, idx,
                severity    = f.get("severity", "INFO"),
                title       = f.get("name", "Configuración de seguridad"),
                description = f.get("detail", f.get("description", "")),
                evidence    = f.get("evidence", ""),
                affected    = affected,
                remediation = f.get("remediation", ""),
                tags        = [tool_key, f.get("category", "")],
            ))
            idx += 1
    return out


def _extract_wp(data: dict, prefix: str) -> List[dict]:
    """
    Extrae hallazgos del JSON de vamp_wp2shell_audit.

    Esquema fuente:
      results[].{target, plugin_findings[], theme_findings[], sqli_vectors[]}
    """
    out: List[dict] = []
    idx = 1
    for result in data.get("results", []):
        affected = result.get("target", result.get("url", ""))
        # Hallazgos de plugins
        for f in result.get("plugin_findings", []):
            sev   = _norm_sev(f.get("severity", "MEDIUM"))
            cve   = f.get("cve")
            desc  = f.get("description", f.get("summary", ""))
            cvss  = f.get("cvss")
            out.append(_make_finding(
                prefix, idx,
                severity    = sev,
                title       = f.get("title", f"Plugin vulnerable: {f.get('plugin_slug','')}"),
                description = desc,
                evidence    = f.get("evidence", f"Plugin: {f.get('plugin_slug','')} — CVE: {cve or '—'}"),
                affected    = f"{affected} / plugin:{f.get('plugin_slug','')}",
                remediation = f.get("remediation", "Actualizar o desinstalar el plugin afectado."),
                cvss        = float(cvss) if cvss is not None else None,
                cve         = cve,
                tags        = ["wordpress", "plugin"],
            ))
            idx += 1
        # Hallazgos de temas
        for f in result.get("theme_findings", []):
            sev  = _norm_sev(f.get("severity", "MEDIUM"))
            cve  = f.get("cve")
            cvss = f.get("cvss")
            out.append(_make_finding(
                prefix, idx,
                severity    = sev,
                title       = f.get("title", f"Tema vulnerable: {f.get('theme_slug','')}"),
                description = f.get("description", ""),
                evidence    = f"Tema: {f.get('theme_slug','')} — CVE: {cve or '—'}",
                affected    = f"{affected} / theme:{f.get('theme_slug','')}",
                remediation = f.get("remediation", "Actualizar o sustituir el tema afectado."),
                cvss        = float(cvss) if cvss is not None else None,
                cve         = cve,
                tags        = ["wordpress", "theme"],
            ))
            idx += 1
        # Vectores SQLi
        for f in result.get("sqli_vectors", []):
            out.append(_make_finding(
                prefix, idx,
                severity    = "HIGH",
                title       = "Vector de inyección SQL detectado",
                description = f.get("description", str(f)),
                evidence    = f.get("url", affected),
                affected    = affected,
                remediation = "Validar y sanitizar las entradas de usuario; usar prepared statements.",
                tags        = ["wordpress", "sqli"],
            ))
            idx += 1
    return out


def _extract_secrets(data: dict, prefix: str) -> List[dict]:
    """
    Extrae hallazgos del JSON de vamp_secrets_scanner.

    Esquema fuente:
      findings[].{severity, pattern, category, file, line_no, preview}
    """
    out: List[dict] = []
    idx = 1
    for f in data.get("findings", []):
        sev  = _norm_sev(f.get("severity", "HIGH"))
        loc  = f"{f.get('file','?')}:{f.get('line_no','?')}"
        git_info = ""
        if f.get("git_commit"):
            git_info = f" (commit: {f['git_commit'][:8]})"
        out.append(_make_finding(
            prefix, idx,
            severity    = sev,
            title       = f"Secreto expuesto: {f.get('category', f.get('pattern', 'desconocido'))}",
            description = (
                f"Patrón detectado: {f.get('pattern','?')} — "
                f"Categoría: {f.get('category','?')}{git_info}"
            ),
            evidence    = f"Fichero: {loc}\nExtracto: {f.get('preview','[censurado]')}",
            affected    = loc,
            remediation = (
                "Rotar el secreto inmediatamente. Eliminar del repositorio con "
                "git-filter-repo. Añadir al .gitignore. Usar variables de entorno."
            ),
            tags        = ["secrets", f.get("category", "")],
        ))
        idx += 1
    return out


def _extract_jwt(data: dict, prefix: str) -> List[dict]:
    """
    Extrae hallazgos del JSON de vamp_jwt_audit.

    Esquema fuente:
      results[].findings[].{severity, name, detail}
    """
    out: List[dict] = []
    idx = 1
    for result in data.get("results", []):
        header = result.get("header", {})
        affected = f"alg={header.get('alg','?')} kid={header.get('kid','?')}"
        for f in result.get("findings", []):
            out.append(_make_finding(
                prefix, idx,
                severity    = f.get("severity", "MEDIUM"),
                title       = f.get("name", "Problema en JWT"),
                description = f.get("detail", f.get("description", "")),
                evidence    = f.get("evidence", affected),
                affected    = affected,
                remediation = f.get("remediation", "Revisar la implementación del JWT."),
                tags        = ["jwt", "auth"],
            ))
            idx += 1
    return out


def _extract_mail(data: dict, prefix: str) -> List[dict]:
    """
    Extrae hallazgos del JSON de vamp_mail_audit.

    Esquema fuente:
      results[].{domain, findings[].{severity, title, description, evidence, remediation}}
    """
    out: List[dict] = []
    idx = 1
    for result in data.get("results", []):
        domain = result.get("domain", "")
        for f in result.get("findings", []):
            out.append(_make_finding(
                prefix, idx,
                severity    = f.get("severity", "MEDIUM"),
                title       = f.get("title", f.get("name", "Configuración de correo")),
                description = f.get("description", ""),
                evidence    = f.get("evidence", ""),
                affected    = domain,
                remediation = f.get("remediation", ""),
                tags        = ["mail", "dns", f.get("category", "")],
            ))
            idx += 1
    return out


def _extract_docker(data: dict, prefix: str) -> List[dict]:
    """
    Extrae hallazgos del JSON de vamp_docker_audit.

    Esquema fuente (todos los grupos de findings):
      containers[].findings[] + image_findings[] + network_findings[] + env_findings[]
      Cada finding: {id, severity, category, title, description, evidence, remediation, container}
    """
    out: List[dict] = []
    idx = 1
    host = data.get("host", "localhost")

    def _collect(findings_list: List[dict], scope: str) -> None:
        nonlocal idx
        for f in findings_list:
            container = f.get("container", scope)
            out.append(_make_finding(
                prefix, idx,
                severity    = f.get("severity", "MEDIUM"),
                title       = f.get("title", f.get("name", "Configuración Docker")),
                description = f.get("description", ""),
                evidence    = f.get("evidence", ""),
                affected    = f"{host}/{container}" if container else host,
                remediation = f.get("remediation", ""),
                tags        = ["docker", f.get("category", ""), scope],
            ))
            idx += 1

    for container in data.get("containers", []):
        _collect(container.get("findings", []), container.get("name", "contenedor"))
    _collect(data.get("image_findings", []),   "imágenes")
    _collect(data.get("network_findings", []), "redes")
    _collect(data.get("env_findings", []),     "env-vars")
    return out


def _extract_logs(data: dict, prefix: str) -> List[dict]:
    """
    Extrae hallazgos del JSON de vamp_log_hunter.

    Esquema fuente:
      findings[].{id, severity, category, title, description, source_ips,
                  evidence_lines, remediation, tags}
    """
    out: List[dict] = []
    idx = 1
    for f in data.get("findings", []):
        ips = f.get("source_ips", [])
        ev_lines = f.get("evidence_lines", [])
        evidence = "\n".join(str(l) for l in ev_lines[:10]) if ev_lines else ""
        out.append(_make_finding(
            prefix, idx,
            severity    = f.get("severity", "MEDIUM"),
            title       = f.get("title", f.get("name", "Evento de seguridad en logs")),
            description = f.get("description", ""),
            evidence    = evidence,
            affected    = ", ".join(str(ip) for ip in ips[:5]) if ips else "—",
            remediation = f.get("remediation", ""),
            tags        = ["logs"] + (f.get("tags", []) or []),
        ))
        idx += 1
    return out


def _extract_fort(data: dict, prefix: str) -> List[dict]:
    """
    Extrae hallazgos del JSON de vamp_forticheck.

    Esquema fuente:
      results[].{target, banner, risk_level, cve_findings[].{cve, severity, description, remediation}}
    """
    out: List[dict] = []
    idx = 1
    for result in data.get("results", []):
        target  = result.get("target", "")
        banner  = result.get("banner", "")
        vendor  = result.get("vendor", "")
        for f in result.get("cve_findings", []):
            sev  = _norm_sev(f.get("severity", result.get("risk_level", "HIGH")))
            cve  = f.get("cve")
            cvss_raw = f.get("cvss_score", f.get("cvss"))
            try:
                cvss = float(cvss_raw) if cvss_raw is not None else None
            except (TypeError, ValueError):
                cvss = None
            out.append(_make_finding(
                prefix, idx,
                severity    = sev,
                title       = f.get("title", f"CVE en {vendor or 'dispositivo'}: {cve}"),
                description = f.get("description", ""),
                evidence    = f"Target: {target} — Banner: {banner} — CVE: {cve}",
                affected    = target,
                remediation = f.get("remediation", "Aplicar el parche del fabricante."),
                cvss        = cvss,
                cve         = cve,
                tags        = ["forticheck", vendor or "network-device"],
                references  = f.get("references", []),
            ))
            idx += 1
        # Vectores de exposición secundarios
        for vec in result.get("exposure_vectors", []):
            if not vec:
                continue
            out.append(_make_finding(
                prefix, idx,
                severity    = _norm_sev(vec.get("severity", "MEDIUM")),
                title       = vec.get("name", "Vector de exposición"),
                description = vec.get("description", ""),
                evidence    = f"Target: {target}",
                affected    = target,
                remediation = vec.get("remediation", "Restringir acceso al servicio."),
                tags        = ["forticheck", "exposure"],
            ))
            idx += 1
    return out


def _extract_cve(data: dict, prefix: str) -> List[dict]:
    """
    Extrae hallazgos del JSON de vamp_cve_oracle.

    Esquema fuente:
      results[].{cve_id, cvss_severity, cvss_score, description,
                 kev_listed, epss_score, remediation_notes}
    """
    out: List[dict] = []
    idx = 1
    for r in data.get("results", []):
        if not r.get("found", True):
            continue
        sev     = _norm_sev(r.get("cvss_severity", "INFO"))
        cve_id  = r.get("cve_id", "")
        kev     = "[KEV] " if r.get("kev_listed") else ""
        epss    = r.get("epss_score")
        epss_s  = f" | EPSS: {epss:.4f}" if epss is not None else ""
        cvss_raw = r.get("cvss_score")
        try:
            cvss = float(cvss_raw) if cvss_raw is not None else None
        except (TypeError, ValueError):
            cvss = None
        desc = r.get("description", "")[:800]
        out.append(_make_finding(
            prefix, idx,
            severity    = sev,
            title       = f"{kev}{cve_id}: {desc[:60]}",
            description = desc,
            evidence    = (
                f"CVSS: {cvss or '—'}{epss_s} | "
                f"KEV: {'Sí' if r.get('kev_listed') else 'No'} | "
                f"Prioridad RBVM: {r.get('rbvm_priority', '—')}"
            ),
            affected    = cve_id,
            remediation = r.get("remediation_notes", "Aplicar el parche del proveedor."),
            cvss        = cvss,
            cve         = cve_id,
            tags        = ["cve", "rbvm"] + (["kev"] if r.get("kev_listed") else []),
        ))
        idx += 1
    return out


def _extract_generic(data: dict, prefix: str) -> List[dict]:
    """
    Extractor genérico de último recurso para herramientas sin extractor específico.
    Intenta localizar findings en estructuras comunes.
    """
    out: List[dict] = []
    idx = 1

    # Intento 1: findings en raíz
    raw = data.get("findings", [])

    # Intento 2: findings anidados en results[]
    if not raw:
        for result in data.get("results", []):
            raw.extend(result.get("findings", []))

    for f in raw:
        if not isinstance(f, dict):
            continue
        out.append(_make_finding(
            prefix, idx,
            severity    = f.get("severity", "INFO"),
            title       = f.get("title", f.get("name", "Hallazgo")),
            description = f.get("description", f.get("detail", f.get("message", ""))),
            evidence    = f.get("evidence", ""),
            affected    = f.get("affected", f.get("host", f.get("url", "—"))),
            remediation = f.get("remediation", ""),
        ))
        idx += 1
    return out


# Mapa de extractores por nombre de herramienta
_EXTRACTORS: Dict[str, Callable[[dict, str], List[dict]]] = {
    "recon":   _extract_recon,
    "ssl":     lambda d, p: _extract_ssl_http(d, p, "ssl"),
    "http":    lambda d, p: _extract_ssl_http(d, p, "http"),
    "wp":      _extract_wp,
    "secrets": _extract_secrets,
    "jwt":     _extract_jwt,
    "mail":    _extract_mail,
    "docker":  _extract_docker,
    "logs":    _extract_logs,
    "cloud":   _extract_generic,
    "fort":    _extract_fort,
    "cve":     _extract_cve,
}


def extract_findings(tool_name: str, json_data: dict) -> List[dict]:
    """
    Extrae y normaliza hallazgos del JSON de salida de una herramienta VSL.

    Selecciona el extractor específico de la herramienta o cae al genérico
    si la herramienta no tiene uno registrado.
    """
    prefix = VSL_TOOLS.get(tool_name, {}).get("prefix", tool_name.upper())
    extractor = _EXTRACTORS.get(tool_name, _extract_generic)
    try:
        findings = extractor(json_data, prefix)
    except Exception as exc:
        # Nunca abortar por un fallo de extracción; degradar silenciosamente
        findings = []
    # Inyectar el nombre de la herramienta en cada hallazgo
    for f in findings:
        f.setdefault("tool", tool_name)
    return findings


# ---------------------------------------------------------------------------
# Descubrimiento de herramientas
# ---------------------------------------------------------------------------

def discover_tools(tool_dir: Path) -> Dict[str, bool]:
    """
    Verifica qué scripts VSL están disponibles en tool_dir.

    Devuelve un dict {nombre_herramienta: disponible}.
    """
    availability: Dict[str, bool] = {}
    for tool_name, info in VSL_TOOLS.items():
        script = tool_dir / info["script"]
        availability[tool_name] = script.is_file()
    return availability


# ---------------------------------------------------------------------------
# Selección automática de herramientas
# ---------------------------------------------------------------------------

def auto_select_tools(args: argparse.Namespace,
                      availability: Dict[str, bool]) -> List[str]:
    """
    Determina qué herramientas ejecutar en función de los objetivos proporcionados.

    Lógica:
      · --domain  → recon, ssl (desde dominio), http, wp, mail, cloud
      · --url     → http, wp; ssl y recon si no hay --host/--domain
      · --host    → ssl, fort
      · --path    → secrets
      · --jwt     → jwt
      · --log-dir → logs
      · Docker accesible → docker (siempre que esté disponible)
    """
    selected: set = set()
    domain = getattr(args, "domain", None)
    url    = getattr(args, "url", None)
    host   = getattr(args, "host", None)
    path   = getattr(args, "path", None)
    jwt    = getattr(args, "jwt", None)
    log_dir = getattr(args, "log_dir", None)

    if domain:
        selected.update(["recon", "ssl", "http", "wp", "mail", "cloud"])
    if url:
        selected.update(["http", "wp"])
        if not domain and not host:
            selected.update(["ssl", "recon"])
    if host:
        selected.update(["ssl", "fort"])
    if path:
        selected.add("secrets")
    if jwt:
        selected.add("jwt")
    if log_dir:
        selected.add("logs")

    # Docker: comprobar si el daemon responde
    docker_available = shutil.which("docker") is not None
    if docker_available:
        try:
            r = subprocess.run(
                ["docker", "info"],
                capture_output=True, timeout=5,
            )
            if r.returncode == 0:
                selected.add("docker")
        except Exception:
            pass

    # Filtrar por disponibilidad
    return [t for t in VSL_TOOLS if t in selected and availability.get(t, False)]


# ---------------------------------------------------------------------------
# Construcción del comando de una herramienta
# ---------------------------------------------------------------------------

def build_command(tool_name: str, info: Dict, args: argparse.Namespace,
                  python: str, tool_dir: Path, json_out: str) -> Optional[List[str]]:
    """
    Construye la lista de argumentos para invocar una herramienta VSL.

    Retorna None si faltan argumentos obligatorios.
    """
    script = str(tool_dir / info["script"])
    cmd    = [python, script]
    needs  = info["needs"]
    domain  = getattr(args, "domain", None)
    url     = getattr(args, "url", None)
    host    = getattr(args, "host", None)
    path    = getattr(args, "path", None)
    jwt_tok = getattr(args, "jwt", None)
    log_dir = getattr(args, "log_dir", None)
    cve_ids = getattr(args, "cve", None)  # puede ser lista o str

    # Mapear argumentos de objetivo a cada herramienta
    if "domain" in needs:
        target = domain
        if not target and url:
            target = urlparse(url).netloc or None
        if not target:
            return None
        if tool_name in ("recon", "mail", "cloud"):
            cmd.extend(["-d", target])
        elif tool_name == "ssl":
            cmd.extend(["-H", target])
        elif tool_name == "http":
            cmd.extend(["-u", f"https://{target}"])

    if "url" in needs:
        target_url = url or (f"https://{domain}" if domain else None)
        if not target_url:
            return None
        if tool_name == "http":
            cmd.extend(["-u", target_url])
        elif tool_name == "wp":
            cmd.extend(["-t", target_url])

    if "host" in needs:
        target_host = host
        if not target_host and domain:
            target_host = domain
        if not target_host and url:
            target_host = urlparse(url).netloc or None
        if not target_host:
            return None
        if tool_name == "ssl":
            cmd.extend(["-H", target_host])
        elif tool_name == "fort":
            cmd.extend(["-t", target_host])

    if "path" in needs:
        if not path:
            return None
        # path es argumento posicional para secrets-scanner
        cmd.append(path)

    if "token" in needs:
        if not jwt_tok:
            return None
        cmd.extend(["--token", jwt_tok])

    if "log_dir" in needs:
        if not log_dir:
            return None
        cmd.extend(["--log-dir", log_dir])

    if "cve" in needs:
        targets = cve_ids if isinstance(cve_ids, list) else ([cve_ids] if cve_ids else [])
        if not targets:
            return None
        # CVE IDs son argumentos posicionales
        cmd.extend(targets)

    # Flag de salida JSON
    cmd.extend([info["json_flag"], json_out])
    return cmd


# ---------------------------------------------------------------------------
# Ejecución de una herramienta individual
# ---------------------------------------------------------------------------

def run_tool(tool_run: ToolRun, cmd: List[str], timeout: int,
             console: Console) -> None:
    """
    Ejecuta una herramienta VSL como subproceso y captura su JSON de salida.

    La función modifica tool_run en-lugar con el estado, hallazgos y errores.
    """
    tool_run.status     = "running"
    tool_run.start_time = time.monotonic()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
        )
        tool_run.returncode = result.returncode
        tool_run.end_time   = time.monotonic()

        # El último argumento es el fichero JSON de salida
        json_path = Path(cmd[-1])
        if json_path.is_file():
            try:
                data = json.loads(json_path.read_text(encoding="utf-8"))
                findings = extract_findings(tool_run.name, data)
                tool_run.findings       = findings
                tool_run.findings_count = len(findings)
                tool_run.status         = "done"
            except Exception as exc:
                tool_run.status    = "error"
                tool_run.error_msg = f"Error parseando JSON: {exc}"
        else:
            # Herramienta terminó sin producir JSON
            stderr_tail = (result.stderr or b"")[-500:].decode("utf-8", errors="replace")
            if result.returncode == 0:
                tool_run.status = "done"
            else:
                tool_run.status    = "error"
                tool_run.error_msg = f"rc={result.returncode} — {stderr_tail}"

    except subprocess.TimeoutExpired:
        tool_run.end_time  = time.monotonic()
        tool_run.status    = "error"
        tool_run.error_msg = f"Timeout ({timeout}s)"
    except Exception as exc:
        tool_run.end_time  = time.monotonic()
        tool_run.status    = "error"
        tool_run.error_msg = str(exc)[:200]


# ---------------------------------------------------------------------------
# Tabla Rich de progreso
# ---------------------------------------------------------------------------

def _build_status_table(tool_runs: List[ToolRun]) -> Table:
    """Construye la tabla Rich de estado en tiempo real."""
    tbl = Table(
        title="Herramientas VSL — Estado de ejecución",
        title_style="bold cyan",
        border_style="bright_black",
        header_style="bold",
        expand=True,
    )
    tbl.add_column("Herramienta",  style="bold white",  no_wrap=True, width=12)
    tbl.add_column("Estado",       justify="center",    no_wrap=True, width=16)
    tbl.add_column("Duración",     justify="right",     no_wrap=True, width=9)
    tbl.add_column("Hallazgos",    justify="right",     no_wrap=True, width=10)
    tbl.add_column("Info",         style="dim",         ratio=1)

    for tr in tool_runs:
        icon    = STATUS_ICON.get(tr.status, "?")
        dur     = tr.duration_str if tr.start_time else "—"
        count   = str(tr.findings_count) if tr.status in ("done", "error") else "—"
        info    = tr.error_msg[:60] if tr.error_msg else ""

        status_map = {
            "pending": "dim",
            "running": "bold cyan",
            "done":    "green",
            "error":   "red",
            "skipped": "dim yellow",
        }
        status_style = status_map.get(tr.status, "white")
        status_text  = Text(f"{icon} {tr.status.capitalize()}", style=status_style)

        tbl.add_row(tr.name, status_text, dur, count, info)
    return tbl


# ---------------------------------------------------------------------------
# Deduplicación de hallazgos
# ---------------------------------------------------------------------------

def deduplicate_findings(findings: List[dict]) -> List[dict]:
    """
    Detecta y agrupa hallazgos casi-duplicados (mismo título + misma severidad)
    provenientes de distintas herramientas.

    El primer hallazgo del grupo es el canónico; los duplicados se eliminan y
    se añade una nota «(+N duplicados)» al título del hallazgo canónico.
    """
    groups: Dict[str, List[dict]] = {}
    order:  List[str] = []

    for f in findings:
        key = f"{f.get('severity','INFO')}|{(f.get('title','') or '')[:60].lower()}"
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)

    merged: List[dict] = []
    for key in order:
        group = groups[key]
        canonical = group[0]
        if len(group) > 1:
            extras = len(group) - 1
            canonical = dict(canonical)
            canonical["title"] = f"{canonical.get('title','')} (+{extras} duplicado{'s' if extras > 1 else ''})"
        merged.append(canonical)

    return merged


# ---------------------------------------------------------------------------
# Puntuación de riesgo
# ---------------------------------------------------------------------------

def compute_risk_score(findings: List[dict]) -> int:
    """
    Calcula la puntuación de riesgo compuesta (0–100).

    Ponderación: CRITICAL=25 pts, HIGH=10, MEDIUM=5, LOW=1, INFO=0.
    El resultado se recorta a 100.
    """
    score = 0
    for f in findings:
        score += RISK_WEIGHTS.get(f.get("severity", "INFO"), 0)
    return min(score, 100)


# ---------------------------------------------------------------------------
# Salida unificada en consola
# ---------------------------------------------------------------------------

def _sev_text(sev: str) -> Text:
    """Devuelve un Text Rich con el badge de severidad coloreado."""
    return Text(f" {sev} ", style=f"bold white on {SEV_BADGE_COLOR.get(sev,'#555')}")


def print_unified_report(result: OrchestratorResult, console: Console) -> None:
    """
    Imprime el informe unificado en consola usando Rich.

    Secciones:
      1. Resumen ejecutivo (panel)
      2. Hallazgos CRITICAL y HIGH (paneles por severidad)
      3. Tabla completa de hallazgos
      4. TOP-10 de prioridades de remediación
    """
    console.print()
    console.print(Rule("[bold red]INFORME UNIFICADO VAMPSECURE LABS[/]", style="red"))
    console.print()

    # ── 1. Resumen ejecutivo ────────────────────────────────────────────────
    by_sev: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in result.all_findings:
        by_sev[f.get("severity", "INFO")] = by_sev.get(f.get("severity", "INFO"), 0) + 1

    target_str = " | ".join(filter(None, [
        f"Dominio: {result.target_domain}" if result.target_domain else "",
        f"URL: {result.target_url}"        if result.target_url    else "",
        f"Host: {result.target_host}"      if result.target_host   else "",
    ])) or "—"

    tools_ok  = sum(1 for t in result.tools_run if t.status == "done")
    tools_err = sum(1 for t in result.tools_run if t.status == "error")

    sev_parts = [
        f"[bold red]CRITICAL: {by_sev['CRITICAL']}[/]",
        f"[yellow]HIGH: {by_sev['HIGH']}[/]",
        f"[magenta]MEDIUM: {by_sev['MEDIUM']}[/]",
        f"[blue]LOW: {by_sev['LOW']}[/]",
        f"[dim]INFO: {by_sev['INFO']}[/]",
    ]
    summary_lines = [
        f"[bold]Objetivo:[/]      {target_str}",
        f"[bold]Fecha:[/]         {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"[bold]Herramientas:[/]  {tools_ok} completadas, {tools_err} con error",
        f"[bold]Duración total:[/] {int(result.duration)}s",
        f"[bold]Hallazgos:[/]     {len(result.all_findings)} totales — " + " | ".join(sev_parts),
        f"[bold]Puntuación de riesgo:[/] [bold]{'red' if result.risk_score >= 70 else 'yellow' if result.risk_score >= 40 else 'green'}]{result.risk_score}/100[/]",
    ]
    console.print(Panel("\n".join(summary_lines),
                        title="[bold]Resumen Ejecutivo[/]",
                        border_style="red", padding=(1, 2)))
    console.print()

    # ── 2. CRITICAL y HIGH por separado ────────────────────────────────────
    for sev, style, border in [("CRITICAL", "bold red", "red"),
                                ("HIGH",     "bold yellow", "yellow")]:
        crits = [f for f in result.all_findings if f.get("severity") == sev]
        if not crits:
            continue
        lines = []
        for f in crits[:15]:
            tool = f.get("tool", "?")
            lines.append(
                f"  [{style}]●[/] [{style}]{f['id']}[/] [{border}]{f['title'][:70]}[/] "
                f"[dim]({tool})[/] — afectado: [italic]{f.get('affected','?')[:50]}[/]"
            )
        if len(crits) > 15:
            lines.append(f"  [dim]… y {len(crits)-15} hallazgos {sev} más[/]")
        console.print(Panel("\n".join(lines),
                            title=f"[{style}]Hallazgos {sev}[/]",
                            border_style=border, padding=(0, 1)))
        console.print()

    # ── 3. Tabla completa de hallazgos ──────────────────────────────────────
    if result.all_findings:
        tbl = Table(
            title="Todos los hallazgos",
            title_style="bold white",
            border_style="bright_black",
            header_style="bold",
            expand=True,
            show_lines=False,
        )
        tbl.add_column("ID",         no_wrap=True, width=12)
        tbl.add_column("Severidad",  justify="center", width=10)
        tbl.add_column("Herramienta", no_wrap=True, width=10)
        tbl.add_column("Título",     ratio=3)
        tbl.add_column("Afectado",   ratio=2)

        sorted_findings = sorted(
            result.all_findings,
            key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 99)
        )
        for f in sorted_findings:
            sev   = f.get("severity", "INFO")
            style = SEV_STYLE.get(sev, "white")
            tbl.add_row(
                f["id"],
                Text(sev, style=style),
                f.get("tool", "?"),
                f.get("title", "")[:80],
                f.get("affected", "—")[:60],
            )
        console.print(tbl)
        console.print()

    # ── 4. TOP-10 prioridades de remediación ────────────────────────────────
    actionable = [
        f for f in result.all_findings
        if f.get("remediation") and f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")
    ]
    top10 = sorted(actionable, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 99))[:10]
    if top10:
        console.print(Panel(
            "\n".join(
                f"  [bold]{i}.[/] [{SEV_STYLE.get(f['severity'],'white')}]{f['id']}[/] "
                f"— {f['title'][:55]}\n"
                f"     [dim]Remediación: {f['remediation'][:100]}[/]"
                for i, f in enumerate(top10, 1)
            ),
            title="[bold]TOP 10 — Prioridades de remediación[/]",
            border_style="bright_black",
            padding=(0, 1),
        ))


# ---------------------------------------------------------------------------
# Generación de informe HTML unificado dark-theme
# ---------------------------------------------------------------------------

def _risk_color(score: int) -> str:
    if score >= 70:
        return "#c0392b"
    if score >= 40:
        return "#d4ac0d"
    return "#27ae60"


def generate_html_report(result: OrchestratorResult, meta_args,
                         path: str) -> None:
    """
    Genera el informe HTML unificado dark-theme con tema VSL.

    Secciones:
      · Portada/resumen ejecutivo con score de riesgo
      · Tabla por severidad con barras
      · Sección por herramienta (colapsable)
      · Tabla completa de hallazgos
      · Hoja de ruta de remediación
    """
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    target_str = " / ".join(filter(None, [
        result.target_domain,
        result.target_url,
        result.target_host,
    ])) or "—"

    by_sev: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in result.all_findings:
        by_sev[f.get("severity", "INFO")] = by_sev.get(f.get("severity", "INFO"), 0) + 1

    total = len(result.all_findings)
    score = result.risk_score
    score_color = _risk_color(score)

    # KPI cards
    sev_card_colors = {
        "CRITICAL": "#c0392b", "HIGH": "#d35400",
        "MEDIUM": "#d4ac0d",   "LOW": "#2980b9", "INFO": "#7f8c8d",
    }
    kpi_html = "".join(
        f'<div class="kpi" style="border-top:3px solid {sev_card_colors[s]}">'
        f'<div class="kv" style="color:{sev_card_colors[s]}">{by_sev[s]}</div>'
        f'<div class="kl">{s}</div></div>'
        for s in SEVERITY_ORDER if by_sev[s] > 0
    )

    # Barras de distribución
    max_count = max(by_sev.values()) or 1
    bar_rows = ""
    for sev, count in by_sev.items():
        if count == 0:
            continue
        pct = round(count / max_count * 100)
        c   = sev_card_colors[sev]
        bar_rows += (
            f'<div class="bar-row">'
            f'<span class="badge" style="background:{c};width:100px;text-align:center">{sev}</span>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{c}"></div></div>'
            f'<span class="bar-count">{count}</span></div>\n'
        )

    # Herramientas ejecutadas
    tools_rows = ""
    for tr in result.tools_run:
        sev_counts = {s: 0 for s in SEVERITY_ORDER}
        for f in tr.findings:
            sev_counts[f.get("severity", "INFO")] = sev_counts.get(f.get("severity", "INFO"), 0) + 1
        icon = {"done": "✅", "error": "❌", "skipped": "⏭️"}.get(tr.status, "⏳")
        err_html = f'<div class="err">Error: {_he(tr.error_msg)}</div>' if tr.error_msg else ""
        find_html = ""
        for f in sorted(tr.findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity","INFO"), 99)):
            sev = f.get("severity", "INFO")
            c   = sev_card_colors.get(sev, "#555")
            find_html += (
                f'<div class="finding-row">'
                f'<span class="badge" style="background:{c}">{sev}</span> '
                f'<code>{_he(f.get("id","?"))}</code> '
                f'{_he(f.get("title","")[:80])}'
                f'<div class="find-aff">Afectado: <code>{_he(f.get("affected","?")[:80])}</code></div>'
                f'</div>\n'
            )
        tools_rows += (
            f'<details class="tool-section">'
            f'<summary>{icon} <strong>{_he(tr.name)}</strong>'
            f' &nbsp;<span class="dim">{tr.duration_str}</span>'
            f' &nbsp;{tr.findings_count} hallazgos</summary>'
            f'{err_html}{find_html}'
            f'</details>\n'
        )

    # Tabla completa de hallazgos
    sorted_all = sorted(
        result.all_findings,
        key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 99)
    )
    findings_rows = ""
    for i, f in enumerate(sorted_all, 1):
        sev = f.get("severity", "INFO")
        c   = sev_card_colors.get(sev, "#555")
        cve_s = f' <span class="cve">{_he(f.get("cve",""))}</span>' if f.get("cve") else ""
        cvss_s = f'{f["cvss"]:.1f}' if f.get("cvss") is not None else "—"
        findings_rows += (
            f'<tr>'
            f'<td class="mono">{i}</td>'
            f'<td class="mono">{_he(f.get("id","?"))}</td>'
            f'<td><span class="badge" style="background:{c}">{sev}</span></td>'
            f'<td>{_he(f.get("tool","?"))}</td>'
            f'<td>{_he(f.get("title","")[:80])}{cve_s}</td>'
            f'<td class="dim">{cvss_s}</td>'
            f'<td class="mono">{_he(f.get("affected","—")[:60])}</td>'
            f'</tr>\n'
        )

    # Hoja de ruta de remediación
    actionable = [
        f for f in sorted_all
        if f.get("remediation") and f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")
    ][:10]
    remediation_html = ""
    for i, f in enumerate(actionable, 1):
        sev = f.get("severity", "INFO")
        c   = sev_card_colors.get(sev, "#555")
        remediation_html += (
            f'<div class="remed-item">'
            f'<div class="remed-head">'
            f'<span class="num">{i}</span>'
            f'<span class="badge" style="background:{c}">{sev}</span>'
            f' <strong>{_he(f.get("id","?"))}</strong>'
            f' — {_he(f.get("title","")[:70])}'
            f'</div>'
            f'<div class="remed-body">{_he(f.get("remediation","")[:300])}</div>'
            f'</div>\n'
        )

    client     = getattr(meta_args, "client", "Confidencial") if meta_args else "Confidencial"
    engagement = getattr(meta_args, "engagement", "") if meta_args else ""

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Informe Unificado VSL — {_he(client)} — {now_str[:10]}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
     background:#0d0d14;color:#e0e0e8;line-height:1.6;font-size:14px}}
a{{color:#5dade2}}
code,.mono{{font-family:'Courier New',monospace;font-size:.85em;color:#a0c8e8}}
.dim{{opacity:.6}}
.cve{{font-size:.78em;color:#a0a0b0;font-style:italic}}
.wrap{{max-width:1100px;margin:0 auto;padding:0 0 60px}}

/* Cabecera */
.header{{background:linear-gradient(135deg,#1a1a2e 0%,#6e0000 50%,#c0392b 100%);
         padding:40px 48px;position:relative;overflow:hidden}}
.header::before{{content:"";position:absolute;top:-80px;right:-80px;
                 width:320px;height:320px;border-radius:50%;
                 background:rgba(255,255,255,.03)}}
.brand{{font-size:.72em;letter-spacing:3px;text-transform:uppercase;
        opacity:.55;margin-bottom:20px;color:#eee}}
.h-title{{font-size:1.8em;font-weight:700;color:#fff;margin-bottom:4px}}
.h-sub{{font-size:.9em;opacity:.65;color:#ddd;margin-bottom:24px}}
.h-meta{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;font-size:.82em}}
.h-item span{{display:block;opacity:.45;font-size:.78em;text-transform:uppercase;
              letter-spacing:.4px;margin-bottom:2px;color:#bbb}}
.h-item strong{{color:#eee}}
.conf{{position:absolute;top:16px;right:24px;font-size:.68em;
       letter-spacing:2px;border:1px solid rgba(255,255,255,.2);
       padding:3px 7px;border-radius:2px;opacity:.5;color:#eee;text-transform:uppercase}}

/* Score de riesgo */
.score-wrap{{position:absolute;top:32px;right:120px;text-align:center}}
.score-circle{{width:72px;height:72px;border-radius:50%;
               border:3px solid {score_color};display:flex;flex-direction:column;
               align-items:center;justify-content:center}}
.score-n{{font-size:1.4em;font-weight:700;color:{score_color}}}
.score-l{{font-size:.55em;color:#888;text-transform:uppercase;letter-spacing:1px}}

/* Secciones */
.sec{{padding:28px 48px;border-bottom:1px solid #1e1e2e}}
.sec:last-child{{border-bottom:none}}
.sec-title{{font-size:.88em;font-weight:700;color:#c0392b;text-transform:uppercase;
            letter-spacing:.6px;margin-bottom:18px;display:flex;
            align-items:center;gap:10px}}
.sec-title::after{{content:'';flex:1;height:1px;background:#2a2a3e}}

/* KPIs */
.kpis{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}}
.kpi{{background:#13131f;border:1px solid #2a2a3e;border-radius:6px;
      padding:14px 18px;min-width:110px;text-align:center}}
.kv{{font-size:2em;font-weight:700}}
.kl{{font-size:.68em;color:#888;text-transform:uppercase;letter-spacing:.4px;margin-top:2px}}

/* Barras */
.bar-row{{display:flex;align-items:center;gap:10px;margin-bottom:8px}}
.bar-track{{flex:1;background:#1e1e2e;border-radius:3px;height:14px;overflow:hidden}}
.bar-fill{{height:100%;border-radius:3px;transition:width .3s}}
.bar-count{{font-size:.8em;color:#666;width:24px;text-align:right}}

/* Badge */
.badge{{display:inline-block;padding:2px 8px;border-radius:3px;
        font-size:.72em;font-weight:700;letter-spacing:.3px;color:#fff}}

/* Herramientas */
.tool-section{{border:1px solid #1e1e2e;border-radius:6px;margin-bottom:10px;overflow:hidden}}
.tool-section summary{{padding:12px 16px;cursor:pointer;background:#13131f;
                       list-style:none;display:flex;align-items:center;gap:8px;
                       border-bottom:1px solid #1e1e2e}}
.tool-section summary:hover{{background:#1a1a2e}}
.tool-section[open] summary{{background:#1a1a2e}}
.finding-row{{padding:8px 16px;border-bottom:1px solid #1a1a2f;font-size:.85em}}
.finding-row:last-child{{border-bottom:none}}
.find-aff{{font-size:.78em;color:#666;margin-top:2px}}
.err{{padding:8px 16px;color:#e74c3c;font-size:.85em;background:#1a0a0a}}

/* Tabla */
table{{width:100%;border-collapse:collapse;font-size:.83em}}
th{{background:#13131f;color:#666;padding:8px 10px;text-align:left;
    border-bottom:2px solid #1e1e2e;font-size:.73em;text-transform:uppercase;
    letter-spacing:.4px;font-weight:700;position:sticky;top:0}}
td{{padding:7px 10px;border-bottom:1px solid #1a1a2e;vertical-align:top}}
tr:hover td{{background:#0f0f1e}}

/* Remediación */
.remed-item{{border:1px solid #1e1e2e;border-radius:6px;margin-bottom:10px;overflow:hidden}}
.remed-head{{padding:10px 16px;background:#13131f;display:flex;align-items:center;gap:8px}}
.num{{display:inline-flex;align-items:center;justify-content:center;
      width:22px;height:22px;border-radius:50%;background:#c0392b;
      color:#fff;font-size:.75em;font-weight:700;flex-shrink:0}}
.remed-body{{padding:10px 16px;font-size:.84em;color:#a0a0b8;background:#0e0e1a}}

/* Pie */
.footer{{background:#0a0a12;border-top:1px solid #1e1e2e;padding:14px 48px;
         font-size:.72em;color:#444;display:flex;
         justify-content:space-between;flex-wrap:wrap;gap:6px}}
</style>
</head>
<body>
<div class="wrap">

<!-- CABECERA -->
<div class="header">
  <div class="conf">Confidencial</div>
  <div class="score-wrap">
    <div class="score-circle">
      <div class="score-n">{score}</div>
      <div class="score-l">Riesgo</div>
    </div>
  </div>
  <div class="brand">&#9679; VampSecure Labs — Security Research Division</div>
  <div class="h-title">Informe de Auditoría Unificado</div>
  <div class="h-sub">{TOOL_NAME} v{VERSION} — Orquestación completa VSL</div>
  <div class="h-meta">
    <div class="h-item"><span>Objetivo</span><strong>{_he(target_str)}</strong></div>
    <div class="h-item"><span>Cliente</span><strong>{_he(client)}</strong></div>
    <div class="h-item"><span>Engagement</span><strong>{_he(engagement or '—')}</strong></div>
    <div class="h-item"><span>Generado</span><strong>{_he(now_str)}</strong></div>
    <div class="h-item"><span>Herramientas</span><strong>{len(result.tools_run)} ejecutadas</strong></div>
    <div class="h-item"><span>Total hallazgos</span><strong>{total}</strong></div>
  </div>
</div>

<!-- RESUMEN EJECUTIVO -->
<div class="sec">
  <div class="sec-title">Resumen Ejecutivo</div>
  <div class="kpis">
    <div class="kpi"><div class="kv">{total}</div><div class="kl">Total</div></div>
    {kpi_html}
  </div>
  <div>{bar_rows}</div>
</div>

<!-- POR HERRAMIENTA -->
<div class="sec">
  <div class="sec-title">Resultados por Herramienta</div>
  {tools_rows}
</div>

<!-- TABLA COMPLETA -->
<div class="sec" style="overflow-x:auto">
  <div class="sec-title">Tabla de Hallazgos</div>
  <table>
    <tr>
      <th>#</th><th>ID</th><th>Severidad</th><th>Herramienta</th>
      <th>Título</th><th>CVSS</th><th>Afectado</th>
    </tr>
    {findings_rows}
  </table>
</div>

<!-- REMEDIACIÓN -->
<div class="sec">
  <div class="sec-title">Hoja de Ruta de Remediación (TOP 10)</div>
  {remediation_html or '<p class="dim">Sin hallazgos accionables prioritarios.</p>'}
</div>

<!-- PIE -->
<div class="footer">
  <span>VampSecure Labs — Security Research Division &nbsp;·&nbsp; {AUTHOR}</span>
  <span>CONFIDENCIAL — Uso exclusivo del cliente destinatario</span>
</div>
</div>
</body>
</html>"""

    Path(path).write_text(html, encoding="utf-8")


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def print_banner(console: Console) -> None:
    """Imprime el banner de inicio del orquestador."""
    console.print(Panel(
        f"[bold red]{TOOL_NAME}[/] [dim]v{VERSION}[/]\n"
        "[dim]Meta-orquestador del toolkit VampSecure Labs[/]\n"
        f"[dim]{AUTHOR}[/]",
        border_style="red",
        padding=(0, 2),
    ))


# ---------------------------------------------------------------------------
# Argumentos CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Construye y devuelve el parser de argumentos del orquestador."""
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            f"VampSecure Labs Orchestrator v{VERSION} — "
            "Orquestación de herramientas VSL y generación de informe unificado"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            f"  {TOOL_NAME} -d ejemplo.com\n"
            f"  {TOOL_NAME} -u https://ejemplo.com -d ejemplo.com --parallel\n"
            f"  {TOOL_NAME} -d ejemplo.com --tools recon,ssl,mail --json out.json\n"
            f"  {TOOL_NAME} -p /path/al/proyecto --tools secrets\n"
        ),
    )

    # Objetivos
    tgt = p.add_argument_group("Especificación de objetivos")
    tgt.add_argument("-d", "--domain", metavar="DOMAIN",
                     help="Dominio objetivo (recon, ssl, http, wp, mail, cloud)")
    tgt.add_argument("-u", "--url", metavar="URL",
                     help="URL objetivo (http, wp; ssl y recon derivados)")
    tgt.add_argument("-H", "--host", metavar="HOST",
                     help="Host objetivo con puerto opcional HOST[:PUERTO] (ssl, fort)")
    tgt.add_argument("-p", "--path", metavar="PATH",
                     help="Ruta del directorio a escanear en busca de secretos")
    tgt.add_argument("--jwt", metavar="TOKEN",
                     help="Token JWT a auditar")
    tgt.add_argument("--log-dir", metavar="DIR",
                     help="Directorio de logs a analizar")
    tgt.add_argument("--cve", metavar="CVE-ID", nargs="+",
                     help="CVE IDs a analizar con vamp-cve-oracle")

    # Selección de herramientas
    sel = p.add_argument_group("Selección de herramientas")
    tool_names = ",".join(VSL_TOOLS.keys())
    sel.add_argument("--tools", metavar="LISTA",
                     help=(
                         f"Herramientas a ejecutar separadas por coma: {tool_names} | all "
                         "(por defecto: selección automática según objetivos)"
                     ))
    sel.add_argument("--skip", metavar="LISTA",
                     help="Herramientas a omitir (separadas por coma)")

    # Ejecución
    exc = p.add_argument_group("Opciones de ejecución")
    exc.add_argument("--parallel", action="store_true",
                     help="Ejecutar herramientas en paralelo (por defecto: secuencial)")
    exc.add_argument("--max-parallel", metavar="N", type=int, default=3,
                     help="Máximo de herramientas simultáneas en modo paralelo (por defecto: 3)")
    exc.add_argument("--timeout", metavar="SEG", type=int, default=300,
                     help="Tiempo máximo por herramienta en segundos (por defecto: 300)")
    exc.add_argument("--tool-dir", metavar="DIR",
                     help="Directorio raíz de los scripts VSL (por defecto: directorio de este script)")
    exc.add_argument("--python", metavar="PATH", default=sys.executable,
                     help="Intérprete Python a usar (por defecto: el actual)")

    # Salida
    out = p.add_argument_group("Exportación de resultados")
    out.add_argument("--json", metavar="FICHERO",
                     help="Guardar informe JSON unificado")
    out.add_argument("--html", metavar="FICHERO",
                     help="Guardar informe HTML unificado dark-theme")

    add_report_args(p)
    return p


# ---------------------------------------------------------------------------
# Orquestación principal
# ---------------------------------------------------------------------------

def orchestrate(args: argparse.Namespace, console: Console) -> OrchestratorResult:
    """
    Función principal de orquestación.

    Descubre herramientas, selecciona las relevantes, las ejecuta (secuencial o
    en paralelo) y devuelve el OrchestratorResult consolidado.
    """
    tool_dir = Path(getattr(args, "tool_dir", None) or Path(__file__).parent)
    python   = args.python
    timeout  = args.timeout

    # ── Descubrimiento ─────────────────────────────────────────────────────
    availability = discover_tools(tool_dir)
    unavailable  = [n for n, ok in availability.items() if not ok]
    if unavailable:
        console.print(f"[dim]Herramientas no disponibles en {tool_dir}: {', '.join(unavailable)}[/]")

    # ── Selección de herramientas ──────────────────────────────────────────
    skip_set: set = set()
    if getattr(args, "skip", None):
        skip_set = {s.strip() for s in args.skip.split(",") if s.strip()}

    if getattr(args, "tools", None):
        raw = args.tools.strip().lower()
        if raw == "all":
            selected = [t for t in VSL_TOOLS if availability.get(t, False)]
        else:
            selected = [
                t.strip() for t in raw.split(",")
                if t.strip() in VSL_TOOLS and availability.get(t.strip(), False)
            ]
    else:
        selected = auto_select_tools(args, availability)

    selected = [t for t in selected if t not in skip_set]

    if not selected:
        console.print("[bold red]No hay herramientas seleccionadas o disponibles para ejecutar.[/]")
        console.print("[dim]Use --tools all para forzar, o compruebe que los scripts están en --tool-dir.[/]")
        sys.exit(1)

    console.print(f"\n[bold]Herramientas seleccionadas:[/] {', '.join(selected)}\n")

    # ── Preparar ToolRun y comandos ────────────────────────────────────────
    tmpdir   = tempfile.mkdtemp(prefix="vamp_orch_")
    tool_runs: List[ToolRun] = []
    commands: Dict[str, Optional[List[str]]] = {}

    for name in selected:
        info     = VSL_TOOLS[name]
        json_out = os.path.join(tmpdir, f"{name}_out.json")
        cmd      = build_command(name, info, args, python, tool_dir, json_out)
        tr = ToolRun(name=name, script=info["script"])
        if cmd is None:
            tr.status    = "skipped"
            tr.error_msg = "Argumentos de objetivo insuficientes"
        tool_runs.append(tr)
        commands[name] = cmd

    # ── Ejecución con progreso Rich ────────────────────────────────────────
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    )
    task_id  = progress.add_task("[cyan]Progreso global", total=len(tool_runs))
    start_ts = time.monotonic()

    def _update_progress() -> None:
        done = sum(1 for tr in tool_runs if tr.status in ("done", "error", "skipped"))
        progress.update(task_id, completed=done)

    def _run_one(tr: ToolRun) -> None:
        cmd = commands.get(tr.name)
        if cmd is None or tr.status == "skipped":
            if tr.status != "skipped":
                tr.status    = "skipped"
                tr.error_msg = "Sin comando (objetivo insuficiente)"
            return
        run_tool(tr, cmd, timeout, console)
        _update_progress()

    with Live(
        _build_status_table(tool_runs),
        console=console,
        refresh_per_second=4,
    ) as live:
        if args.parallel:
            max_workers = min(args.max_parallel, len(tool_runs))
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(_run_one, tr): tr for tr in tool_runs if commands.get(tr.name)}
                # Herramientas skipped inmediatas
                for tr in tool_runs:
                    if tr.status == "skipped":
                        _update_progress()
                for fut in concurrent.futures.as_completed(futures):
                    live.update(_build_status_table(tool_runs))
                    try:
                        fut.result()
                    except Exception as exc:
                        tr = futures[fut]
                        tr.status    = "error"
                        tr.error_msg = str(exc)[:200]
        else:
            for tr in tool_runs:
                live.update(_build_status_table(tool_runs))
                _run_one(tr)
                live.update(_build_status_table(tool_runs))

    total_duration = time.monotonic() - start_ts

    # ── Fusión y deduplicación de hallazgos ───────────────────────────────
    all_raw: List[dict] = []
    for tr in tool_runs:
        all_raw.extend(tr.findings)

    all_findings = deduplicate_findings(
        sorted(all_raw, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 99))
    )

    risk_score = compute_risk_score(all_findings)

    # Limpiar temporales
    import shutil as _shutil
    try:
        _shutil.rmtree(tmpdir, ignore_errors=True)
    except Exception:
        pass

    return OrchestratorResult(
        target_domain = getattr(args, "domain", None),
        target_url    = getattr(args, "url", None),
        target_host   = getattr(args, "host", None),
        tools_run     = tool_runs,
        all_findings  = all_findings,
        risk_score    = risk_score,
        duration      = total_duration,
    )


# ---------------------------------------------------------------------------
# Exportación JSON unificado
# ---------------------------------------------------------------------------

def save_json(result: OrchestratorResult, path: str) -> None:
    """
    Guarda el informe JSON consolidado con esquema VSL estándar.

    Estructura:
      meta · summary.by_severity · summary.by_tool · findings[]
    """
    by_sev: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in result.all_findings:
        sev = f.get("severity", "INFO")
        by_sev[sev] = by_sev.get(sev, 0) + 1

    by_tool: Dict[str, int] = {}
    for tr in result.tools_run:
        by_tool[tr.name] = tr.findings_count

    target_str = " / ".join(filter(None, [
        result.target_domain,
        result.target_url,
        result.target_host,
    ])) or "—"

    payload = {
        "schema_version": "1.0",
        "tool":           TOOL_NAME,
        "tool_version":   VERSION,
        "generated":      datetime.now(timezone.utc).isoformat(),
        "meta": {
            "target":         target_str,
            "target_domain":  result.target_domain,
            "target_url":     result.target_url,
            "target_host":    result.target_host,
            "duration_total": round(result.duration, 2),
            "risk_score":     result.risk_score,
            "tools_run": [
                {
                    "name":     tr.name,
                    "status":   tr.status,
                    "duration": round(tr.duration, 2),
                    "findings": tr.findings_count,
                    "error":    tr.error_msg,
                }
                for tr in result.tools_run
            ],
        },
        "summary": {
            "total_findings": len(result.all_findings),
            "by_severity":    by_sev,
            "by_tool":        by_tool,
        },
        "findings": result.all_findings,
    }
    Path(path).write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Punto de entrada
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Punto de entrada principal del orquestador.

    Flujo:
      1. Parseo de argumentos
      2. Orquestación (descubrimiento → selección → ejecución → fusión)
      3. Salida en consola (informe unificado)
      4. Exportación a JSON/HTML si se solicita
      5. Código de salida: 2=CRITICAL, 1=HIGH, 0=limpio
    """
    parser = build_parser()
    args   = parser.parse_args()

    console = Console()
    print_banner(console)

    # Validar que se ha proporcionado al menos un objetivo
    has_target = any([
        getattr(args, "domain", None),
        getattr(args, "url", None),
        getattr(args, "host", None),
        getattr(args, "path", None),
        getattr(args, "jwt", None),
        getattr(args, "log_dir", None),
        getattr(args, "cve", None),
        getattr(args, "tools", None),  # --tools docker no necesita objetivo
    ])
    if not has_target:
        console.print("[bold red]Error:[/] Proporciona al menos un objetivo (-d, -u, -H, -p, --jwt, --log-dir, --cve).")
        parser.print_help()
        sys.exit(1)

    # Ejecutar orquestación
    result = orchestrate(args, console)

    # Imprimir informe en consola
    print_unified_report(result, console)

    # Exportar JSON
    json_path = getattr(args, "json", None)
    if json_path:
        save_json(result, json_path)
        console.print(f"\n[green]✔[/] Informe JSON guardado en [bold]{json_path}[/]")

    # Exportar HTML unificado (--html del orquestador)
    html_path = getattr(args, "html", None)
    if html_path:
        generate_html_report(result, args, html_path)
        console.print(f"[green]✔[/] Informe HTML unificado guardado en [bold]{html_path}[/]")

    # Exportar HTML/PDF cliente VSL (--report-html / --report-pdf de add_report_args)
    report_html = getattr(args, "report_html", None)
    report_pdf  = getattr(args, "report_pdf",  None)
    if report_html or report_pdf:
        meta = meta_from_args(args, tool=TOOL_NAME, version=VERSION)
        vsl_findings: List[VSLFinding] = []
        for i, f in enumerate(result.all_findings, 1):
            try:
                cvss_val = f.get("cvss")
                vsl_findings.append(VSLFinding(
                    id          = f.get("id", f"ORC-{i:03d}"),
                    title       = f.get("title", "Hallazgo"),
                    severity    = f.get("severity", "INFO"),
                    description = f.get("description", ""),
                    evidence    = f.get("evidence", ""),
                    affected    = f.get("affected", "—"),
                    remediation = f.get("remediation", ""),
                    cvss        = float(cvss_val) if cvss_val is not None else None,
                    cve         = f.get("cve"),
                    references  = f.get("references", []),
                    tags        = f.get("tags", []),
                ))
            except Exception:
                continue
        vsl_report = VampSecReport(meta, vsl_findings)
        if report_html:
            vsl_report.to_html_client(report_html)
            console.print(f"[green]✔[/] Informe cliente HTML guardado en [bold]{report_html}[/]")
        if report_pdf:
            try:
                vsl_report.to_pdf(report_pdf)
                console.print(f"[green]✔[/] Informe cliente PDF guardado en [bold]{report_pdf}[/]")
            except RuntimeError as e:
                console.print(f"[yellow]⚠[/] PDF no generado: {e}")

    # ── Código de salida ───────────────────────────────────────────────────
    has_critical = any(f.get("severity") == "CRITICAL" for f in result.all_findings)
    has_high     = any(f.get("severity") == "HIGH"     for f in result.all_findings)

    console.print()
    if has_critical:
        console.print("[bold red]Salida con código 2: se encontraron hallazgos CRITICAL.[/]")
        sys.exit(2)
    if has_high:
        console.print("[bold yellow]Salida con código 1: se encontraron hallazgos HIGH.[/]")
        sys.exit(1)
    console.print("[bold green]Salida con código 0: sin hallazgos CRITICAL ni HIGH.[/]")
    sys.exit(0)


if __name__ == "__main__":
    main()
