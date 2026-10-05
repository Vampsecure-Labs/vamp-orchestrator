# © VampSecure Studios — VampSecure Labs Security Research Division
"""
Tests unitarios para vamp-orchestrator.
Cobertura: dispatch de tools, aggregación JSON, deduplicación, risk score
logarítmico, _cmd_diff, auto_select_tools, build_command, notificaciones
Telegram (mock), schema_version en output.
"""

import argparse
import json
import os
import sys
import tempfile
import types
from pathlib import Path
from unittest.mock import MagicMock, patch


# ── Mock de dependencias rich antes del import ──────────────────────────────

def _mock_rich():
    """Inyecta mocks mínimos de rich en sys.modules."""
    for mod_name in [
        "rich", "rich.console", "rich.table", "rich.panel", "rich.text",
        "rich.progress", "rich.box", "rich.live", "rich.columns", "rich.rule",
    ]:
        if mod_name not in sys.modules:
            sys.modules[mod_name] = types.ModuleType(mod_name)

    # Clases mínimas para que el import no falle
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

    for cls, mod in [
        (_Console, "rich.console"),
        (_Table, "rich.table"),
        (_Live, "rich.live"),
    ]:
        for attr_name in dir(cls):
            if not attr_name.startswith("_"):
                setattr(sys.modules[mod], attr_name, cls)

    sys.modules["rich.console"].Console = _Console
    sys.modules["rich.table"].Table = _Table
    sys.modules["rich.live"].Live = _Live

    for mod, name in [
        ("rich.panel", "Panel"),
        ("rich.text", "Text"),
        ("rich.rule", "Rule"),
        ("rich.columns", "Columns"),
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
                }))


_mock_rich()

# ── Mock de vampsec_report ────────────────────────────────────────────────────

def _mock_vampsec_report():
    mod = types.ModuleType("vampsec_report")
    mod.SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    class _Finding:
        def __init__(self, **kw):
            for k, v in kw.items():
                setattr(self, k, v)

    class _VampSecReport:
        def __init__(self, *a, **k): pass
        def generate_html(self, *a, **k): return "<html></html>"

    mod.VampSecReport = _VampSecReport
    mod.Finding = _Finding
    mod.add_report_args = lambda p: None
    mod.meta_from_args = lambda a: None
    sys.modules["vampsec_report"] = mod


_mock_vampsec_report()

# ── Import del módulo bajo test ───────────────────────────────────────────────

sys.path.insert(0, str(Path(__file__).parent.parent))
import vamp_orchestrator as orch


# =============================================================================
# Fixtures
# =============================================================================

def _make_args(**kwargs):
    """Crea un Namespace de argparse con valores por defecto para tests."""
    defaults = dict(
        domain=None, url=None, host=None, path=None,
        jwt=None, log_dir=None, cve=None, llm_endpoint=None,
        k8s_context=None, client="TestClient", engagement="test-001",
        tool_dir=None, tools=None, json=None, html=None,
    )
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# =============================================================================
# Grupo 1 — Normalización de severidad
# =============================================================================

class TestNormSev:
    """Prueba _norm_sev para todos los valores canónicos y casos borde."""

    def test_critical_mayus(self):
        # CRITICAL en mayúsculas devuelve CRITICAL
        assert orch._norm_sev("CRITICAL") == "CRITICAL"

    def test_high_minusc(self):
        # 'high' en minúsculas se normaliza a HIGH
        assert orch._norm_sev("high") == "HIGH"

    def test_medium(self):
        assert orch._norm_sev("MEDIUM") == "MEDIUM"

    def test_low(self):
        assert orch._norm_sev("low") == "LOW"

    def test_info(self):
        assert orch._norm_sev("INFO") == "INFO"

    def test_desconocido_devuelve_info(self):
        # Un valor no reconocido se degrada silenciosamente a INFO
        assert orch._norm_sev("UNKNOWN") == "INFO"

    def test_none_devuelve_info(self):
        # None también se maneja como INFO
        assert orch._norm_sev(None) == "INFO"


# =============================================================================
# Grupo 2 — _make_finding
# =============================================================================

class TestMakeFinding:
    """Verifica que _make_finding genera hallazgos con el esquema VSL correcto."""

    def test_campos_obligatorios_presentes(self):
        f = orch._make_finding("TST", 1, "HIGH", "Título test")
        for campo in ("id", "severity", "title", "description", "evidence",
                      "affected", "remediation", "cvss", "cve", "tags", "references"):
            assert campo in f, f"Campo '{campo}' ausente en el hallazgo"

    def test_id_formato_prefijo_idx(self):
        f = orch._make_finding("RECON", 42, "HIGH", "Test")
        assert f["id"] == "RECON-042"

    def test_severidad_normalizada(self):
        # Severidades no estándar se normalizan a INFO
        f = orch._make_finding("TST", 1, "SUPER_CRITICAL", "Test")
        assert f["severity"] == "INFO"

    def test_titulo_truncado_a_200(self):
        titulo_largo = "A" * 300
        f = orch._make_finding("TST", 1, "LOW", titulo_largo)
        assert len(f["title"]) <= 200

    def test_tags_lista_vacia_por_defecto(self):
        f = orch._make_finding("TST", 1, "INFO", "Test")
        assert f["tags"] == []

    def test_cvss_ninguno_por_defecto(self):
        f = orch._make_finding("TST", 1, "HIGH", "Test")
        assert f["cvss"] is None


# =============================================================================
# Grupo 3 — Deduplicación
# =============================================================================

class TestDeduplicateFindigns:
    """Prueba que deduplicate_findings elimina correctamente los duplicados."""

    def _finding(self, sev, title, affected, idx=1):
        return {"id": f"T-{idx:03d}", "severity": sev,
                "title": title, "affected": affected}

    def test_mismo_titulo_sev_affected_duplicado(self):
        # Dos hallazgos con la misma clave → solo queda 1
        f1 = self._finding("HIGH", "TLS 1.0", "target.local", 1)
        f2 = self._finding("HIGH", "TLS 1.0", "target.local", 2)
        resultado = orch.deduplicate_findings([f1, f2])
        assert len(resultado) == 1

    def test_diferente_affected_se_conserva(self):
        # El mismo tipo de hallazgo en hosts distintos NO es duplicado
        f1 = self._finding("HIGH", "TLS 1.0", "host1.local", 1)
        f2 = self._finding("HIGH", "TLS 1.0", "host2.local", 2)
        resultado = orch.deduplicate_findings([f1, f2])
        assert len(resultado) == 2

    def test_diferente_severidad_se_conserva(self):
        # Mismo título pero distinta severidad → son distintos hallazgos
        f1 = self._finding("HIGH", "Config error", "host.local", 1)
        f2 = self._finding("LOW",  "Config error", "host.local", 2)
        resultado = orch.deduplicate_findings([f1, f2])
        assert len(resultado) == 2

    def test_titulo_duplicado_anota_conteo(self):
        # Al deduplicar 3 iguales → el título canónico lleva "(+2 duplicados)"
        f1 = self._finding("HIGH", "Repeated", "target.local", 1)
        f2 = self._finding("HIGH", "Repeated", "target.local", 2)
        f3 = self._finding("HIGH", "Repeated", "target.local", 3)
        resultado = orch.deduplicate_findings([f1, f2, f3])
        assert len(resultado) == 1
        assert "+2 duplicado" in resultado[0]["title"]

    def test_lista_vacia_devuelve_vacia(self):
        assert orch.deduplicate_findings([]) == []

    def test_un_elemento_se_conserva(self):
        f = self._finding("MEDIUM", "Solo", "host.local", 1)
        resultado = orch.deduplicate_findings([f])
        assert len(resultado) == 1


# =============================================================================
# Grupo 4 — Risk score logarítmico
# =============================================================================

class TestComputeRiskScore:
    """Prueba la fórmula logarítmica: score = 100 × (1 − e^(−raw/75))."""

    def _findings(self, sev, count):
        return [{"severity": sev} for _ in range(count)]

    def test_sin_hallazgos_es_cero(self):
        assert orch.compute_risk_score([]) == 0

    def test_un_critical(self):
        # 1 CRITICAL → raw=25 → score ≈ 28
        score = orch.compute_risk_score(self._findings("CRITICAL", 1))
        assert 20 < score < 40

    def test_cuatro_vs_veinte_criticals_son_distintos(self):
        # La escala logarítmica satura: 4 críticos < 20 críticos pero ambos < 100
        s4  = orch.compute_risk_score(self._findings("CRITICAL", 4))
        s20 = orch.compute_risk_score(self._findings("CRITICAL", 20))
        assert s4 < s20, "4 críticos debe dar score menor que 20 críticos"
        assert s4 > 0
        assert s20 <= 100

    def test_saturacion_en_100(self):
        # Muchos hallazgos no pueden superar 100
        score = orch.compute_risk_score(self._findings("CRITICAL", 1000))
        assert score == 100

    def test_solo_info_es_cero(self):
        # INFO tiene peso 0
        score = orch.compute_risk_score(self._findings("INFO", 100))
        assert score == 0

    def test_mix_severidades(self):
        # Mezcla: el score debe ser positivo y razonable
        findings = (self._findings("CRITICAL", 2) +
                    self._findings("HIGH", 3) +
                    self._findings("MEDIUM", 5))
        score = orch.compute_risk_score(findings)
        assert 0 < score <= 100


# =============================================================================
# Grupo 5 — auto_select_tools
# =============================================================================

class TestAutoSelectTools:
    """Prueba la selección automática de herramientas según los objetivos."""

    def _availability(self, *names):
        """Crea un dict de disponibilidad con las herramientas indicadas como True."""
        avail = {k: False for k in orch.VSL_TOOLS}
        for n in names:
            avail[n] = True
        return avail

    def test_domain_incluye_takeover(self):
        # Con --domain, la herramienta de subdomain-takeover debe incluirse
        args = _make_args(domain="example.com")
        avail = self._availability(*orch.VSL_TOOLS.keys())
        # Parchear llamadas a subprocess para que no accedan al sistema
        with patch("vamp_orchestrator.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            with patch("vamp_orchestrator.shutil.which", return_value=None):
                seleccionadas = orch.auto_select_tools(args, avail)
        assert "takeover" in seleccionadas, "takeover debe seleccionarse con --domain"

    def test_domain_incluye_recon_ssl_http_mail(self):
        args = _make_args(domain="example.com")
        avail = self._availability(*orch.VSL_TOOLS.keys())
        with patch("vamp_orchestrator.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            with patch("vamp_orchestrator.shutil.which", return_value=None):
                seleccionadas = orch.auto_select_tools(args, avail)
        for t in ("recon", "ssl", "http", "mail"):
            assert t in seleccionadas, f"'{t}' debe incluirse con --domain"

    def test_kubectl_accesible_incluye_k8s(self):
        # kubectl disponible y responde → k8s debe seleccionarse
        args = _make_args(domain="example.com")
        avail = self._availability(*orch.VSL_TOOLS.keys())
        with patch("vamp_orchestrator.shutil.which") as mock_which:
            mock_which.side_effect = lambda cmd: "/usr/bin/kubectl" if cmd == "kubectl" else None
            with patch("vamp_orchestrator.subprocess.run") as mock_run:
                # kubectl cluster-info → returncode 0
                mock_run.return_value = MagicMock(returncode=0)
                seleccionadas = orch.auto_select_tools(args, avail)
        assert "k8s" in seleccionadas, "k8s debe seleccionarse cuando kubectl responde"

    def test_kubectl_no_disponible_no_incluye_k8s(self):
        # Sin kubectl, k8s no debe aparecer
        args = _make_args(domain="example.com")
        avail = self._availability(*orch.VSL_TOOLS.keys())
        with patch("vamp_orchestrator.shutil.which", return_value=None):
            with patch("vamp_orchestrator.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1)
                seleccionadas = orch.auto_select_tools(args, avail)
        assert "k8s" not in seleccionadas

    def test_k8s_context_explicito_incluye_k8s(self):
        # --k8s-context explícito siempre incluye k8s aunque kubectl no responda
        args = _make_args(k8s_context="prod-cluster")
        avail = self._availability(*orch.VSL_TOOLS.keys())
        with patch("vamp_orchestrator.shutil.which", return_value=None):
            with patch("vamp_orchestrator.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1)
                seleccionadas = orch.auto_select_tools(args, avail)
        assert "k8s" in seleccionadas

    def test_path_incluye_secrets_entropy(self):
        args = _make_args(path="/repo/src")
        avail = self._availability("secrets", "entropy")
        with patch("vamp_orchestrator.shutil.which", return_value=None):
            with patch("vamp_orchestrator.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1)
                seleccionadas = orch.auto_select_tools(args, avail)
        assert "secrets" in seleccionadas
        assert "entropy" in seleccionadas


# =============================================================================
# Grupo 6 — build_command
# =============================================================================

class TestBuildCommand:
    """Prueba que build_command genera los flags correctos por herramienta."""

    def test_ssl_usa_flag_H(self):
        info = orch.VSL_TOOLS["ssl"]
        args = _make_args(host="target.local")
        cmd = orch.build_command("ssl", info, args, "python3",
                                 Path("/tools"), "/tmp/out.json")
        assert cmd is not None
        assert "-H" in cmd
        assert "target.local" in cmd

    def test_secrets_usa_path_posicional(self):
        info = orch.VSL_TOOLS["secrets"]
        args = _make_args(path="/repo/src")
        cmd = orch.build_command("secrets", info, args, "python3",
                                 Path("/tools"), "/tmp/out.json")
        assert cmd is not None
        # El path se pasa posicional, no como flag
        assert "/repo/src" in cmd

    def test_jwt_usa_flag_token(self):
        info = orch.VSL_TOOLS["jwt"]
        args = _make_args(jwt="eyJ0eXAiOiJKV1Q...")
        cmd = orch.build_command("jwt", info, args, "python3",
                                 Path("/tools"), "/tmp/out.json")
        assert cmd is not None
        assert "--token" in cmd

    def test_domain_faltante_devuelve_none(self):
        # Si la herramienta necesita domain y no hay ninguno → None
        info = orch.VSL_TOOLS["recon"]
        args = _make_args()  # sin domain ni url ni host
        cmd = orch.build_command("recon", info, args, "python3",
                                 Path("/tools"), "/tmp/out.json")
        assert cmd is None, "build_command debe devolver None si falta el target obligatorio"

    def test_entropy_usa_flag_path(self):
        info = orch.VSL_TOOLS["entropy"]
        args = _make_args(path="/datos")
        cmd = orch.build_command("entropy", info, args, "python3",
                                 Path("/tools"), "/tmp/out.json")
        assert cmd is not None
        assert "--path" in cmd
        assert "/datos" in cmd

    def test_output_json_es_ultimo_argumento(self):
        # El último argumento del comando siempre es el fichero de salida JSON
        info = orch.VSL_TOOLS["ssl"]
        args = _make_args(host="h.local")
        out = "/tmp/ssl_out.json"
        cmd = orch.build_command("ssl", info, args, "python3",
                                 Path("/tools"), out)
        assert cmd is not None
        assert cmd[-1] == out


# =============================================================================
# Grupo 7 — extract_findings / dispatch de extractores
# =============================================================================

class TestExtractFindings:
    """Prueba que extract_findings invoca el extractor correcto y normaliza."""

    def test_ssl_extrae_hallazgos(self):
        data = {
            "results": [{
                "host": "target.local",
                "port": 443,
                "findings": [{
                    "severity": "HIGH",
                    "name": "TLS 1.0 habilitado",
                    "detail": "El servidor acepta TLS 1.0",
                    "remediation": "Deshabilitar TLS 1.0",
                }],
            }]
        }
        findings = orch.extract_findings("ssl", data)
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert "target.local" in findings[0]["affected"]

    def test_ssl_hallazgo_lleva_tool_name(self):
        data = {"results": [{"host": "h.local", "findings": [
            {"severity": "MEDIUM", "name": "Cipher débil", "detail": ""}
        ]}]}
        findings = orch.extract_findings("ssl", data)
        assert findings[0].get("tool") == "ssl"

    def test_herramienta_desconocida_usa_extractor_generico(self):
        # Una herramienta sin extractor específico usa _extract_generic
        data = {"findings": [{"severity": "LOW", "title": "Hallazgo genérico",
                               "description": "desc"}]}
        findings = orch.extract_findings("tool_inexistente", data)
        assert len(findings) == 1

    def test_extractor_no_aborta_con_datos_invalidos(self):
        # Si el JSON está mal formado, extract_findings no debe lanzar excepción
        findings = orch.extract_findings("ssl", {"unexpected_key": []})
        assert isinstance(findings, list)

    def test_secrets_extrae_categoria(self):
        data = {"findings": [{
            "severity": "CRITICAL",
            "pattern": "sk_live_",
            "category": "api_key",
            "file": "config.py",
            "line_no": 42,
            "preview": "sk_live_xxxx",
        }]}
        findings = orch.extract_findings("secrets", data)
        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"


# =============================================================================
# Grupo 8 — _finding_key y _load_scan_findings
# =============================================================================

class TestDiffHelpers:
    """Prueba las funciones auxiliares del subcomando diff."""

    def test_finding_key_con_check_id(self):
        f = {"check_id": "AUTH-001", "affected": "host.local", "title": "Root login"}
        key = orch._finding_key(f)
        assert key.startswith("__id__")
        assert "AUTH-001" in key

    def test_finding_key_sin_check_id_usa_titulo(self):
        f = {"title": "TLS 1.0", "affected": "host.local"}
        key = orch._finding_key(f)
        assert key.startswith("__title__")
        assert "tls 1.0" in key.lower()

    def test_finding_key_mismo_hallazgo_misma_clave(self):
        f1 = {"title": "TLS 1.0", "affected": "host.local"}
        f2 = {"title": "TLS 1.0", "affected": "host.local"}
        assert orch._finding_key(f1) == orch._finding_key(f2)

    def test_load_scan_findings_desde_key_findings(self):
        data = {"schema_version": "2.0",
                "findings": [{"id": "T-001", "severity": "HIGH"}]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                        delete=False) as fh:
            json.dump(data, fh)
            fh_path = fh.name
        try:
            findings = orch._load_scan_findings(fh_path)
            assert len(findings) == 1
            assert findings[0]["id"] == "T-001"
        finally:
            os.unlink(fh_path)

    def test_load_scan_findings_desde_key_results(self):
        # También debe funcionar con 'results' como clave principal
        data = {"results": [{"id": "R-001", "severity": "MEDIUM"}]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                        delete=False) as fh:
            json.dump(data, fh)
            fh_path = fh.name
        try:
            findings = orch._load_scan_findings(fh_path)
            assert len(findings) == 1
        finally:
            os.unlink(fh_path)


# =============================================================================
# Grupo 9 — save_json → schema_version 2.0
# =============================================================================

class TestSaveJson:
    """Prueba que save_json genera JSON con schema_version 2.0 y estructura correcta."""

    def _make_result(self, findings=None, tools=None):
        tr = orch.ToolRun(name="ssl", script="vamp_ssl_audit.py",
                          status="done", findings_count=len(findings or []),
                          findings=findings or [])
        return orch.OrchestratorResult(
            target_domain="test.local", target_url=None,
            target_host=None, target_k8s_context=None,
            target_llm_endpoint=None,
            tools_run=[tr],
            all_findings=findings or [],
            risk_score=42,
            duration=3.14,
        )

    def test_schema_version_es_2_0(self):
        result = self._make_result()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                        delete=False) as fh:
            path = fh.name
        try:
            orch.save_json(result, path)
            data = json.loads(Path(path).read_text())
            assert data["schema_version"] == "2.0"
        finally:
            os.unlink(path)

    def test_output_contiene_findings(self):
        findings = [{"id": "T-001", "severity": "HIGH", "title": "Test",
                     "description": "", "affected": "h.local",
                     "remediation": "", "tool": "ssl"}]
        result = self._make_result(findings=findings)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                        delete=False) as fh:
            path = fh.name
        try:
            orch.save_json(result, path)
            data = json.loads(Path(path).read_text())
            assert len(data["findings"]) == 1
            assert data["findings"][0]["id"] == "T-001"
        finally:
            os.unlink(path)

    def test_output_contiene_risk_score(self):
        result = self._make_result()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                        delete=False) as fh:
            path = fh.name
        try:
            orch.save_json(result, path)
            data = json.loads(Path(path).read_text())
            assert "risk_score" in data["meta"]
            assert data["meta"]["risk_score"] == 42
        finally:
            os.unlink(path)

    def test_output_tiene_summary_by_severity(self):
        result = self._make_result()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                        delete=False) as fh:
            path = fh.name
        try:
            orch.save_json(result, path)
            data = json.loads(Path(path).read_text())
            assert "by_severity" in data["summary"]
            assert "CRITICAL" in data["summary"]["by_severity"]
        finally:
            os.unlink(path)


# =============================================================================
# Grupo 10 — Notificaciones Telegram (mock)
# =============================================================================

class TestTelegramNotification:
    """Prueba la notificación Telegram con urlopen mockeado."""

    def test_notificar_telegram_llama_urlopen(self):
        # Debe llamar a urllib.request.urlopen cuando hay token/chat_id
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.status = 200

        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
            result = orch._notificar_telegram("bot_token_test",
                                              "chat_id_test",
                                              "Mensaje de prueba VSL")
        mock_urlopen.assert_called_once()
        assert result is True

    def test_notificar_telegram_devuelve_false_en_error(self):
        # Si urlopen lanza excepción, la función devuelve False sin propagar
        with patch("urllib.request.urlopen", side_effect=Exception("network error")):
            result = orch._notificar_telegram("tok", "chat", "msg")
        assert result is False

    def test_leer_config_telegram_sin_fichero(self):
        # Si no existe el fichero de configuración, devuelve cadenas vacías
        with patch("pathlib.Path.exists", return_value=False):
            token, chat_id = orch._leer_config_telegram()
        assert token == ""
        assert chat_id == ""
