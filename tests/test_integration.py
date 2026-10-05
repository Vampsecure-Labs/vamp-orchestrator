# © VampSecure Studios — VampSecure Labs Security Research Division
"""
Tests de integración para vamp-orchestrator.
Todos los subprocess se mockean — no se necesita red ni herramientas reales.
Marcados con @pytest.mark.integration.
"""

import argparse
import json
import os
import sys
import tempfile
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── Mock rich + vampsec_report (misma estrategia que test_unit) ──────────────

def _mock_rich():
    for mod_name in [
        "rich", "rich.console", "rich.table", "rich.panel", "rich.text",
        "rich.progress", "rich.box", "rich.live", "rich.columns", "rich.rule",
    ]:
        if mod_name not in sys.modules:
            sys.modules[mod_name] = types.ModuleType(mod_name)

    class _Console:
        def __init__(self, *a, **k): pass
        def print(self, *a, **k): pass
        def rule(self, *a, **k): pass

    class _Table:
        def __init__(self, *a, **k): pass
        def add_column(self, *a, **k): pass
        def add_row(self, *a, **k): pass

    class _Live:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def update(self, *a, **k): pass

    sys.modules["rich.console"].Console = _Console
    sys.modules["rich.table"].Table = _Table
    sys.modules["rich.live"].Live = _Live
    for mod, name in [
        ("rich.panel", "Panel"), ("rich.text", "Text"),
        ("rich.rule", "Rule"), ("rich.columns", "Columns"),
    ]:
        setattr(sys.modules[mod], name,
                type(name, (), {"__init__": lambda s, *a, **k: None}))
    for cls_name in ["Progress", "SpinnerColumn", "TextColumn", "BarColumn",
                     "MofNCompleteColumn", "TimeElapsedColumn"]:
        setattr(sys.modules["rich.progress"], cls_name,
                type(cls_name, (), {
                    "__init__": lambda s, *a, **k: None,
                    "__enter__": lambda s: s,
                    "__exit__": lambda s, *a: None,
                    "add_task": lambda s, *a, **k: 0,
                    "advance": lambda s, *a, **k: None,
                    "update": lambda s, *a, **k: None,
                }))


if "rich" not in sys.modules:
    _mock_rich()

if "vampsec_report" not in sys.modules:
    mod = types.ModuleType("vampsec_report")
    mod.SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    class _VampSecReport:
        def __init__(self, *a, **k): pass
        def generate_html(self, *a, **k): return "<html></html>"

    class _Finding:
        def __init__(self, *a, **k):
            for k_, v in k.items():
                setattr(self, k_, v)

    mod.VampSecReport = _VampSecReport
    mod.Finding = _Finding
    mod.add_report_args = lambda p: None
    mod.meta_from_args = lambda a: None
    sys.modules["vampsec_report"] = mod

sys.path.insert(0, str(Path(__file__).parent.parent))
import vamp_orchestrator as orch


# =============================================================================
# Helpers de integración
# =============================================================================

def _ssl_json(host="target.local"):
    """Devuelve un JSON típico de vamp-ssl-audit."""
    return {
        "tool": "vamp-ssl-audit",
        "version": "1.0",
        "target": host,
        "results": [{
            "host": host,
            "port": 443,
            "findings": [
                {
                    "severity": "HIGH",
                    "name": "TLS 1.0 habilitado",
                    "detail": "El servidor acepta negociaciones TLS 1.0",
                    "remediation": "Desactivar TLS 1.0 en el servidor",
                },
                {
                    "severity": "MEDIUM",
                    "name": "HSTS no configurado",
                    "detail": "Falta la cabecera Strict-Transport-Security",
                    "remediation": "Añadir HSTS con max-age mínimo de 1 año",
                },
            ],
        }],
    }


def _http_json(url="http://target.local"):
    """Devuelve un JSON típico de vamp-http-audit."""
    return {
        "tool": "vamp-http-audit",
        "version": "1.0",
        "target": url,
        "findings": [
            {
                "severity": "HIGH",
                "title": "X-Content-Type-Options ausente",
                "description": "Falta la cabecera de seguridad",
                "affected": url,
                "remediation": "Añadir X-Content-Type-Options: nosniff",
            }
        ],
    }


def _make_subprocess_mock(output_data, returncode=0):
    """Mock de subprocess.run que escribe un JSON en el fichero indicado."""

    def _side_effect(cmd, *args, **kwargs):
        # Busca el último arg que parece un path de JSON de salida
        out_path = cmd[-1] if isinstance(cmd, list) and cmd[-1].endswith(".json") else None
        if out_path:
            Path(out_path).write_text(json.dumps(output_data))
        proc = MagicMock()
        proc.returncode = returncode
        proc.stdout = ""
        proc.stderr = ""
        return proc

    return _side_effect


# =============================================================================
# Tests de integración
# =============================================================================

@pytest.mark.integration
class TestOrchestrationFlow:
    """Prueba flujos de orquestación completos con subprocess mockeado."""

    def test_run_ssl_produce_hallazgos(self):
        """Lanzar ssl contra un dominio genera hallazgos en el resultado."""
        ssl_data = _ssl_json()

        with tempfile.TemporaryDirectory() as tmpdir:
            args = argparse.Namespace(
                domain="target.local", url=None, host="target.local",
                path=None, jwt=None, log_dir=tmpdir, cve=None,
                llm_endpoint=None, k8s_context=None,
                client="TestClient", engagement="test-001",
                tool_dir=None, tools="ssl", json=None, html=None,
                python=sys.executable, timeout=30,
                parallel=False, max_parallel=1, skip=None,
            )
            with patch("vamp_orchestrator.subprocess.run",
                       side_effect=_make_subprocess_mock(ssl_data)):
                with patch("vamp_orchestrator.discover_tools",
                           return_value={"ssl": True}):
                    result = orch.orchestrate(args, orch.Console())

        assert result is not None
        assert len(result.all_findings) >= 2
        assert any(f["severity"] == "HIGH" for f in result.all_findings)

    def test_deduplicacion_entre_herramientas(self):
        """El mismo hallazgo de dos tools distintas debe deduplicarse."""
        finding_duplicado = {
            "severity": "HIGH",
            "title": "TLS 1.0 habilitado",
            "description": "...",
            "affected": "target.local",
            "remediation": "Deshabilitar TLS 1.0",
        }
        json_tool1 = {"tool": "ssl", "findings": [finding_duplicado]}
        json_tool2 = {"tool": "ssl-deep", "findings": [dict(finding_duplicado)]}

        findings = json_tool1["findings"] + json_tool2["findings"]
        deduped = orch.deduplicate_findings(findings)
        assert len(deduped) == 1

    def test_aggregation_multitool_json_export(self):
        """save_json sobre un resultado multi-tool genera JSON con schema 2.0."""
        findings_ssl = orch.extract_findings("ssl", _ssl_json())
        findings_http = orch.extract_findings("http", _http_json())

        tr_ssl = orch.ToolRun(name="ssl", script="vamp_ssl_audit.py",
                              status="done",
                              findings_count=len(findings_ssl),
                              findings=findings_ssl)
        tr_http = orch.ToolRun(name="http", script="vamp_http_audit.py",
                               status="done",
                               findings_count=len(findings_http),
                               findings=findings_http)
        all_f = findings_ssl + findings_http
        result = orch.OrchestratorResult(
            target_domain="target.local",
            target_url="http://target.local",
            target_host="target.local",
            target_k8s_context=None,
            target_llm_endpoint=None,
            tools_run=[tr_ssl, tr_http],
            all_findings=all_f,
            risk_score=orch.compute_risk_score(all_f),
            duration=5.0,
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                        delete=False) as fh:
            path = fh.name
        try:
            orch.save_json(result, path)
            data = json.loads(Path(path).read_text())
            assert data["schema_version"] == "2.0"
            assert len(data["findings"]) == len(all_f)
            assert "by_severity" in data["summary"]
        finally:
            os.unlink(path)

    def test_risk_score_en_resultado_final(self):
        """El risk score exportado refleja los hallazgos reales."""
        findings = [{"severity": "CRITICAL"}] * 5
        score = orch.compute_risk_score(findings)
        assert 50 < score <= 100, "5 criticals deben suponer score >50"

    def test_cmd_diff_detecta_nuevos_y_resueltos(self):
        """_cmd_diff encuentra hallazgos nuevos y resueltos entre dos JSONs."""
        json_anterior = {
            "schema_version": "2.0",
            "findings": [
                {"id": "SSL-001", "severity": "HIGH",
                 "title": "TLS 1.0", "affected": "host.local"},
                {"id": "SSL-002", "severity": "MEDIUM",
                 "title": "HSTS ausente", "affected": "host.local"},
            ],
        }
        json_nuevo = {
            "schema_version": "2.0",
            "findings": [
                {"id": "SSL-002", "severity": "MEDIUM",
                 "title": "HSTS ausente", "affected": "host.local"},
                {"id": "SSL-003", "severity": "CRITICAL",
                 "title": "Certificado expirado", "affected": "host.local"},
            ],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                        delete=False) as f1:
            json.dump(json_anterior, f1)
            path1 = f1.name
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                        delete=False) as f2:
            json.dump(json_nuevo, f2)
            path2 = f2.name
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html",
                                        delete=False) as fh:
            html_out = fh.name

        try:
            orch._cmd_diff(["--scan1", path1, "--scan2", path2, "--html", html_out])
            contenido = Path(html_out).read_text()
            # El HTML debe mencionar el hallazgo nuevo y el resuelto
            assert "Certificado expirado" in contenido or "SSL-003" in contenido
            assert "TLS 1.0" in contenido or "SSL-001" in contenido
        finally:
            for p in (path1, path2, html_out):
                if os.path.exists(p):
                    os.unlink(p)
