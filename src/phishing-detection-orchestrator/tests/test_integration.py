"""Tests de integracion del cliente orquestador.

Requisitos de entorno por prueba (ver README.md, seccion "Configuracion"):

- test_mcp_client_conecta_con_knowledge: necesita KNOWLEDGE_MCP_PATH apuntando
  a una copia local de knowledge-based-MCP con `uv sync` ya corrido ahi. No
  necesita ninguna API key.

- test_loop_orquestador_con_cliente_anthropic_simulado: mismos requisitos que
  la anterior (KNOWLEDGE_MCP_PATH). Tampoco necesita ninguna API key: usa un
  cliente de Anthropic simulado (respuestas guionizadas) para no depender de
  una key real ni gastar tokens, mientras ejercita de verdad la conexion MCP,
  la ejecucion de herramientas y la validacion Pydantic del resultado.

- test_analisis_completo_en_vivo: la unica prueba que golpea la API real de
  Anthropic. Necesita ANTHROPIC_API_KEY (una key valida y con saldo) ademas
  de KNOWLEDGE_MCP_PATH. Se salta automaticamente si ANTHROPIC_API_KEY no
  esta definida, para poder correr el resto de la suite sin ella.

- test_tool_terminal_acepta_resultado_envuelto: no necesita variables de
  entorno, servidores MCP ni API keys. Valida solo el desempaquetado del
  resultado final cuando el modelo lo entrega como {"resultado": {...}}.

Todas las pruebas usan COHERENCE_LLM_PROVIDER=mock si no se especifica lo
contrario, y ninguna requiere VIRUSTOTAL_API_KEY ni pattern-archetype-MCP
(que ademas requiere artefactos pregenerados fuera de este repo).
"""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from phishing_orchestrator import config, orchestrator
from phishing_orchestrator.mcp_client import MCPClientManager
from phishing_orchestrator.schemas import VeredictoOutput


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        pytest.skip(f"Se requiere la variable de entorno {name} para esta prueba (ver README.md).")
    return value


def _make_tool_use_block(name: str, arguments: dict, block_id: str = "toolu_1") -> SimpleNamespace:
    return SimpleNamespace(type="tool_use", id=block_id, name=name, input=arguments)


class _FakeMessages:
    """Cliente de mensajes de Anthropic simulado, con una respuesta guionizada."""

    def __init__(self, responses: list[SimpleNamespace]) -> None:
        self._responses = list(responses)
        self.calls: list[dict] = []

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        return self._responses.pop(0)


class _FakeAnthropicClient:
    def __init__(self, responses: list[SimpleNamespace]) -> None:
        self.messages = _FakeMessages(responses)


@pytest.fixture()
def knowledge_server_config() -> config.ServerConfig:
    knowledge_path = _require_env("KNOWLEDGE_MCP_PATH")
    config.load_environment()
    os.environ.setdefault("COHERENCE_LLM_PROVIDER", "mock")
    servers, _ = config.load_server_configs()
    subset = {"knowledge": servers["knowledge"]}
    config.validate_selected_servers(subset)
    assert knowledge_path  # ya validado por _require_env, solo para dejar claro el uso
    return subset["knowledge"]


async def test_mcp_client_conecta_con_knowledge(knowledge_server_config):
    """El cliente MCP debe poder conectarse a knowledge-based-MCP y listar sus tools."""
    async with MCPClientManager({"knowledge": knowledge_server_config}) as client:
        statuses = await client.connect_all()
        assert statuses["knowledge"] == "ok"

        tools = client.get_anthropic_tools()
        tool_names = {t["name"] for t in tools}
        assert "knowledge__get_analysis_policy" in tool_names

        result = await client.call_tool("knowledge__get_analysis_policy", {})
        assert result.ok is True
        assert isinstance(result.data, dict)


async def test_loop_orquestador_con_cliente_anthropic_simulado(knowledge_server_config):
    """Ejercita el loop completo (conexion real + tool_use real + validacion Pydantic)
    sin gastar tokens reales: el modelo de Anthropic esta simulado.
    """
    settings = config.OrchestratorSettings(
        anthropic_api_key="clave-simulada",
        orchestrator_model="claude-haiku-4-5",
        orchestrator_temperature=0.0,
    )

    turno_1 = SimpleNamespace(
        stop_reason="tool_use",
        stop_details=None,
        content=[_make_tool_use_block("knowledge__get_analysis_policy", {}, "toolu_1")],
    )
    turno_2 = SimpleNamespace(
        stop_reason="tool_use",
        stop_details=None,
        content=[
            _make_tool_use_block(
                orchestrator.TERMINAL_TOOL_NAME,
                {"clasificacion": "phishing", "puntaje_riesgo": 0.9},
                "toolu_2",
            )
        ],
    )
    fake_client = _FakeAnthropicClient([turno_1, turno_2])

    async with MCPClientManager({"knowledge": knowledge_server_config}) as mcp_client:
        statuses = await mcp_client.connect_all()

        resultado = await orchestrator.run_analysis(
            email_text="Su cuenta sera bloqueada, verifique en http://banco-falso.example.com",
            mode="veredicto",
            mcp_client=mcp_client,
            anthropic_client=fake_client,
            settings=settings,
            connection_statuses=statuses,
        )

    assert isinstance(resultado.resultado, VeredictoOutput)
    assert resultado.resultado.clasificacion.value == "phishing"
    assert resultado.resultado.puntaje_riesgo == 0.9
    assert len(resultado.herramientas_invocadas) == 1
    assert resultado.herramientas_invocadas[0].servidor == "knowledge"
    assert resultado.herramientas_invocadas[0].ok is True


async def test_analisis_completo_en_vivo(knowledge_server_config):
    """Unica prueba que llama a la API real de Anthropic. Requiere ANTHROPIC_API_KEY."""
    from anthropic import AsyncAnthropic

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        pytest.skip(
            "Se requiere ANTHROPIC_API_KEY (una key real, con saldo) para esta prueba. "
            "El resto de la suite no depende de ella."
        )

    settings = config.load_orchestrator_settings()
    anthropic_client = AsyncAnthropic(api_key=settings.anthropic_api_key)

    async with MCPClientManager({"knowledge": knowledge_server_config}) as mcp_client:
        statuses = await mcp_client.connect_all()

        resultado = await orchestrator.run_analysis(
            email_text=(
                "Estimado usuario, su cuenta de banco sera suspendida en 24 horas. "
                "Verifique sus datos de inmediato en http://banco-seguro-verificacion.example.com "
                "o perdera el acceso permanentemente."
            ),
            mode="veredicto",
            mcp_client=mcp_client,
            anthropic_client=anthropic_client,
            settings=settings,
            connection_statuses=statuses,
        )

    assert isinstance(resultado.resultado, VeredictoOutput)
    assert 0.0 <= resultado.resultado.puntaje_riesgo <= 1.0


def test_tool_terminal_acepta_resultado_envuelto():
    """El modelo a veces envuelve el JSON final en {"resultado": {...}}; debe validarse igual."""
    from phishing_orchestrator.schemas import ExplicacionOutput

    plano = {"clasificacion": "phishing", "puntaje_riesgo": 0.9, "explicacion": "Suplanta a un banco."}

    directo = orchestrator._validate_terminal_input(ExplicacionOutput, plano)
    envuelto = orchestrator._validate_terminal_input(ExplicacionOutput, {"resultado": plano})
    assert envuelto == directo
    assert envuelto.explicacion == "Suplanta a un banco."

    with pytest.raises(ValueError):
        orchestrator._validate_terminal_input(ExplicacionOutput, {"resultado": {"clasificacion": "phishing"}})
