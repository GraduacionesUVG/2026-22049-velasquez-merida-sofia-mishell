"""Loop agentico del orquestador.

Coordina llamadas a los servidores MCP conectados y usa un modelo de Anthropic
para decidir que herramientas invocar, hasta producir un veredicto final
estructurado y validado con Pydantic. El veredicto es siempre del orquestador:
los servidores MCP consultados no clasifican, solo aportan evidencia.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, Literal

import anthropic
from anthropic import AsyncAnthropic
from pydantic import ValidationError

from phishing_orchestrator.config import OrchestratorSettings
from phishing_orchestrator.extraction import extract_network_indicators
from phishing_orchestrator.mcp_client import MCPClientManager
from phishing_orchestrator.prompts import build_system_prompt, build_user_message
from phishing_orchestrator.schemas import (
    ExplicacionOutput,
    OrchestratorRunResult,
    ServerCallStatus,
    ToolInvocation,
    VeredictoOutput,
)

logger = logging.getLogger(__name__)

Modo = Literal["veredicto", "explicacion"]

TERMINAL_TOOL_NAME = "emit_resultado"
DEFAULT_MAX_ITERATIONS = 6

_MAX_TOKENS_BY_MODE: dict[str, int] = {
    "veredicto": 1024,
    "explicacion": 4096,
}

# Modo veredicto (clasificacion binaria, sin explicacion): de las 11
# herramientas de VirusTotal solo se ofrecen estas 3. Las otras 8
# (relaciones, busqueda, archivos/hashes, colecciones) aportan poco a una
# clasificacion binaria y su definicion completa cuesta ~2,200 tokens extra
# por turno que se reenvian en cada iteracion del loop. Se mantiene
# get_ip_report (no solo url+domain) porque el propio corpus de la tesis
# trata "URL con IP literal" como senal de riesgo elevado (tiene_url_ip en
# 01_preparacion_corpus.ipynb); sin ella se pierde cobertura justo en esos
# casos. No aplica a modo explicacion, que mantiene las 11.
_VIRUSTOTAL_TOOLS_MODO_VEREDICTO = frozenset({"get_url_report", "get_domain_report", "get_ip_report"})

# Modelos de la generacion Claude 5 (opus-5, sonnet-5, fable-5, fable-5-1,
# mythos-5-1) ya no aceptan 'temperature' (error 400) pero si soportan
# 'output_config.effort'. Los modelos anteriores (ej. claude-haiku-4-5) es al
# reves: aceptan 'temperature' pero 'effort' les da error. Este patron separa
# ambos grupos para no enviar un parametro que el modelo actual no soporta.
_GENERACION_SIN_TEMPERATURA = re.compile(r"^claude-(opus|sonnet|fable|mythos)-5(-1)?$")

# La familia Fable/Mythos 5.1 no soporta tool_choice forzado (type "tool" o
# "any"): devuelve 400. Todo el diseño de salida estructurada de este
# orquestador depende de forzar la tool terminal, asi que esos modelos no son
# compatibles como modelo orquestador.
_MODELOS_SIN_TOOL_CHOICE_FORZADO = re.compile(r"^claude-(fable|mythos)-5-1$")


class OrchestratorError(RuntimeError):
    """Error irrecuperable durante el analisis de un correo con el orquestador.

    raw_output guarda, cuando existe, el JSON que el modelo entrego en la tool
    terminal y que no paso la validacion, para que el llamador pueda
    conservar el contenido aunque el analisis cuente como fallido.
    """

    def __init__(self, message: str, raw_output: Any = None) -> None:
        super().__init__(message)
        self.raw_output = raw_output


def _output_model_for(mode: Modo) -> type[VeredictoOutput] | type[ExplicacionOutput]:
    return ExplicacionOutput if mode == "explicacion" else VeredictoOutput


def _model_supports_temperature(model: str) -> bool:
    return not _GENERACION_SIN_TEMPERATURA.match(model)


def _model_supports_effort(model: str) -> bool:
    return bool(_GENERACION_SIN_TEMPERATURA.match(model))


def _is_virustotal_tool_excluded_in_veredicto(qualified_tool_name: str) -> bool:
    """True si esta herramienta debe quitarse de la lista en modo veredicto.

    qualified_tool_name viene con el prefijo "<server_id>__" (ver
    MCPClientManager._qualify); solo se filtra "virustotal__*".
    """
    if not qualified_tool_name.startswith("virustotal__"):
        return False
    tool_name = qualified_tool_name.split("__", 1)[1]
    return tool_name not in _VIRUSTOTAL_TOOLS_MODO_VEREDICTO


def _validate_terminal_input(
    output_model: type[VeredictoOutput] | type[ExplicacionOutput], payload: Any
) -> VeredictoOutput | ExplicacionOutput:
    """Valida el input de la tool terminal contra el schema del modo.

    El schema es plano (clasificacion, puntaje_riesgo, ... a nivel raiz), pero
    a veces el modelo lo envuelve en una unica clave, tipicamente
    {"resultado": {...}} por el nombre de la tool 'emit_resultado'. Si la
    validacion directa falla y el payload tiene esa forma, se valida el
    contenido de la clave envoltorio; si tampoco cumple, se propaga el error
    de la validacion directa.
    """
    try:
        return output_model.model_validate(payload)
    except ValidationError:
        if isinstance(payload, dict) and len(payload) == 1:
            (inner,) = payload.values()
            if isinstance(inner, dict):
                try:
                    return output_model.model_validate(inner)
                except ValidationError:
                    pass
        raise


def _terminal_tool(mode: Modo) -> dict[str, Any]:
    output_model = _output_model_for(mode)
    return {
        "name": TERMINAL_TOOL_NAME,
        "description": (
            "Entrega el resultado final y estructurado del analisis. Invocala "
            "exactamente una vez, al terminar tu investigacion, con un JSON que "
            "cumpla el schema. La clasificacion final es tuya: los servidores "
            "MCP consultados no clasifican, solo aportan evidencia."
        ),
        "input_schema": output_model.model_json_schema(),
    }


async def run_analysis(
    email_text: str,
    mode: Modo,
    mcp_client: MCPClientManager,
    anthropic_client: AsyncAnthropic,
    settings: OrchestratorSettings,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    connection_statuses: dict[str, str] | None = None,
    force_exclude_server_ids: set[str] | None = None,
) -> OrchestratorRunResult:
    """Ejecuta el loop agentico sobre un correo y devuelve el resultado validado.

    mcp_client debe tener ya conectados (via connect_all) solo los servidores
    que se quieren habilitar para esta corrida; el gate de VirusTotal por
    ausencia de URLs se aplica aqui, encima de eso.

    force_exclude_server_ids permite que el llamador (por ejemplo el runner
    de lote de la Fase 5) oculte un servidor ya conectado para esta llamada
    puntual sin desconectarlo, por ejemplo VirusTotal despues de detectar que
    su cuota diaria se agoto, para no seguir ofreciendo una herramienta que
    se sabe va a fallar en el resto del lote.
    """
    if _MODELOS_SIN_TOOL_CHOICE_FORZADO.match(settings.orchestrator_model):
        raise OrchestratorError(
            f"El modelo '{settings.orchestrator_model}' no soporta tool_choice "
            "forzado, requerido por el diseno de este orquestador. Usa "
            "claude-haiku-4-5 o claude-sonnet-5."
        )

    indicators = extract_network_indicators(email_text)
    exclude_server_ids: set[str] = set(force_exclude_server_ids or set())
    if not indicators.has_any() and mcp_client.is_connected("virustotal"):
        exclude_server_ids.add("virustotal")

    output_model = _output_model_for(mode)
    terminal_tool = _terminal_tool(mode)
    system_prompt = build_system_prompt(mode, indicators)
    messages: list[dict[str, Any]] = [{"role": "user", "content": build_user_message(email_text)}]

    tool_invocations: list[ToolInvocation] = []
    # Cache de tool calls (nombre calificado + argumentos) ya ejecutados en
    # ESTE analisis. Se crea nuevo en cada llamada a run_analysis, es decir
    # una vez por correo -- no persiste entre correos aunque mcp_client si
    # se reutilice a lo largo de un lote (ver batch.py). Complementa la
    # instruccion del system prompt de no repetir herramientas ya invocadas:
    # si el modelo lo hace de todas formas, esto evita el request repetido.
    tool_call_cache: dict[tuple[str, str], Any] = {}
    final_result: VeredictoOutput | ExplicacionOutput | None = None

    for iteration in range(max_iterations):
        is_last_iteration = iteration == max_iterations - 1
        tools = mcp_client.get_anthropic_tools(exclude_server_ids=exclude_server_ids)
        if mode == "veredicto":
            tools = [t for t in tools if not _is_virustotal_tool_excluded_in_veredicto(t["name"])]
        tools.append(terminal_tool)
        tool_choice: dict[str, Any] = (
            {"type": "tool", "name": TERMINAL_TOOL_NAME} if is_last_iteration else {"type": "auto"}
        )

        response = await _call_model(
            anthropic_client=anthropic_client,
            settings=settings,
            mode=mode,
            system_prompt=system_prompt,
            messages=messages,
            tools=tools,
            tool_choice=tool_choice,
        )

        if response.stop_reason == "refusal":
            detail = getattr(response.stop_details, "explanation", None) if response.stop_details else None
            raise OrchestratorError(f"El modelo orquestador rehuso responder: {detail or 'sin detalle'}")

        messages.append({"role": "assistant", "content": response.content})

        tool_use_blocks = [block for block in response.content if block.type == "tool_use"]
        terminal_block = next((b for b in tool_use_blocks if b.name == TERMINAL_TOOL_NAME), None)

        if terminal_block is not None:
            try:
                final_result = _validate_terminal_input(output_model, terminal_block.input)
            except Exception as exc:
                raise OrchestratorError(
                    f"El modelo devolvio un resultado que no cumple el schema esperado: {exc}",
                    raw_output=terminal_block.input,
                ) from exc
            break

        if not tool_use_blocks:
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "No invocaste ninguna herramienta en tu respuesta anterior. "
                        f"Si ya terminaste tu analisis, responde unicamente invocando "
                        f"'{TERMINAL_TOOL_NAME}'."
                    ),
                }
            )
            continue

        messages.append(
            {
                "role": "user",
                "content": await _execute_tool_calls(
                    mcp_client, tool_use_blocks, tool_invocations, tool_call_cache
                ),
            }
        )

    if final_result is None:
        raise OrchestratorError(
            "No se obtuvo un resultado estructurado del modelo tras el maximo de iteraciones"
        )

    server_statuses = [
        ServerCallStatus(server_id=sid, connected=(status == "ok"), detail=None if status == "ok" else status)
        for sid, status in (connection_statuses or {}).items()
    ]

    return OrchestratorRunResult(
        modo=mode,
        modelo_orquestador=settings.orchestrator_model,
        servidores_habilitados=list((connection_statuses or {}).keys()) or mcp_client.connected_server_ids(),
        servidores_conectados=server_statuses,
        herramientas_invocadas=tool_invocations,
        resultado=final_result,
    )


async def _call_model(
    anthropic_client: AsyncAnthropic,
    settings: OrchestratorSettings,
    mode: Modo,
    system_prompt: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    tool_choice: dict[str, Any],
) -> Any:
    model = settings.orchestrator_model
    kwargs: dict[str, Any] = {
        "model": model,
        "max_tokens": _MAX_TOKENS_BY_MODE.get(mode, 2048),
        "system": system_prompt,
        "messages": messages,
        "tools": tools,
        "tool_choice": tool_choice,
    }

    if _model_supports_temperature(model):
        # El SDK 1.6.0 ya no tipa 'temperature' como parametro de
        # messages.create (TypeError si se pasa directo) aunque el modelo si
        # la soporte a nivel de API; extra_body es el mecanismo del SDK para
        # pasar parametros no tipados tal cual al cuerpo de la peticion.
        kwargs["extra_body"] = {"temperature": settings.orchestrator_temperature}
    elif _model_supports_effort(model) and mode == "veredicto":
        # En modo veredicto se prioriza costo/latencia; en modelos que
        # soportan 'effort' (y ya no 'temperature'), effort bajo es el
        # control de costo disponible. En modo explicacion se deja el
        # default del modelo (mayor calidad de razonamiento).
        kwargs["output_config"] = {"effort": "low"}

    try:
        return await anthropic_client.messages.create(**kwargs)
    except anthropic.RateLimitError as exc:
        raise OrchestratorError(f"Limite de tasa de la API de Anthropic alcanzado: {exc}") from exc
    except anthropic.APIConnectionError as exc:
        raise OrchestratorError(f"Fallo de conexion con la API de Anthropic: {exc}") from exc
    except anthropic.APIStatusError as exc:
        raise OrchestratorError(f"Error de la API de Anthropic ({exc.status_code}): {exc.message}") from exc
    except Exception as exc:
        raise OrchestratorError(f"Fallo inesperado al llamar al modelo orquestador: {exc}") from exc


async def _execute_tool_calls(
    mcp_client: MCPClientManager,
    tool_use_blocks: list[Any],
    tool_invocations: list[ToolInvocation],
    tool_call_cache: dict[tuple[str, str], Any],
) -> list[dict[str, Any]]:
    """Ejecuta cada tool_use pedido por el modelo y arma los tool_result correspondientes.

    Todas las llamadas de un mismo turno se devuelven en un solo mensaje de
    usuario, como exige la API para tool use paralelo. Se ejecutan de forma
    concurrente (asyncio.gather), no secuencial: si una de ellas es
    virustotal y tiene que esperar su rate limit (ver
    MCPClientManager._virustotal_rate_limiter), eso no retrasa a las demas
    herramientas pedidas en el mismo turno (por ejemplo archetype).

    tool_call_cache se comparte entre TODOS los turnos de este mismo correo
    (se crea una vez en run_analysis): si el modelo pide la misma
    herramienta con los mismos argumentos en una iteracion posterior, se
    reutiliza el resultado en vez de repetir el request.
    """
    call_results = await asyncio.gather(
        *(
            mcp_client.call_tool(block.name, block.input, call_cache=tool_call_cache)
            for block in tool_use_blocks
        )
    )

    tool_result_blocks: list[dict[str, Any]] = []
    for block, call_result in zip(tool_use_blocks, call_results):
        tool_invocations.append(
            ToolInvocation(
                servidor=call_result.server_id,
                herramienta=call_result.tool_name,
                ok=call_result.ok,
                error=call_result.error,
            )
        )
        payload = (
            {"ok": True, "data": call_result.data}
            if call_result.ok
            else {"ok": False, "error": call_result.error}
        )
        tool_result_blocks.append(
            {
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": json.dumps(payload, ensure_ascii=False, default=str),
                "is_error": not call_result.ok,
            }
        )
    return tool_result_blocks
