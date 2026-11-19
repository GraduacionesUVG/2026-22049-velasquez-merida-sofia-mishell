"""Capa de cliente MCP: conecta con varios servidores por stdio a la vez.

Responsable de arrancar los servidores configurados, exponer sus herramientas
en el formato que espera la API de Anthropic (tool use) y ejecutar llamadas a
herramientas resolviendo a que servidor pertenece cada una. Un servidor que
falla al conectarse o al responder una llamada no debe tumbar a los demas: se
registra el fallo y la ejecucion continua con el resto.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import deque
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession, types
from mcp.client.stdio import StdioServerParameters, stdio_client

from phishing_orchestrator.config import ServerConfig

logger = logging.getLogger(__name__)

# Separador usado para namespacing de herramientas: "<server_id>__<tool_name>".
# Doble guion bajo para minimizar choques con nombres de tools reales.
_TOOL_SEPARATOR = "__"

# Timeout por defecto para llamadas a herramientas. Generoso porque
# coherence-analysis-MCP hace una llamada LLM real internamente.
_DEFAULT_TOOL_TIMEOUT_SECONDS = 90.0

# Limite del plan gratuito de VirusTotal: 4 requests por minuto. Este limiter
# es proactivo (espera antes de exceder el limite); la deteccion de cuota
# diaria agotada (500/dia) sigue siendo reactiva, por palabras clave en el
# error, en batch.py -- son mecanismos complementarios, no redundantes.
_VIRUSTOTAL_RATE_LIMIT_MAX_CALLS = 4
_VIRUSTOTAL_RATE_LIMIT_PERIOD_SECONDS = 60.0


class SlidingWindowRateLimiter:
    """Limita a `max_calls` llamadas por cada `period_seconds`, ventana deslizante.

    `acquire()` bloquea (con `asyncio.sleep`) solo a quien la invoca; no
    afecta corutinas concurrentes que no pasen por este limiter (por eso las
    llamadas a archetype/otras herramientas del mismo turno, ejecutadas con
    asyncio.gather en orchestrator._execute_tool_calls, no esperan a VT).
    """

    def __init__(self, max_calls: int, period_seconds: float) -> None:
        self._max_calls = max_calls
        self._period_seconds = period_seconds
        self._timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            self._evict_expired()
            if len(self._timestamps) >= self._max_calls:
                espera = self._period_seconds - (time.monotonic() - self._timestamps[0])
                if espera > 0:
                    logger.info("VT rate limit: esperando %.1fs...", espera)
                    await asyncio.sleep(espera)
                self._evict_expired()
            self._timestamps.append(time.monotonic())

    def _evict_expired(self) -> None:
        limite = time.monotonic() - self._period_seconds
        while self._timestamps and self._timestamps[0] < limite:
            self._timestamps.popleft()


@dataclass
class ToolCallResult:
    """Resultado de invocar una herramienta MCP, exito o fallo."""

    server_id: str
    tool_name: str
    ok: bool
    data: Any = None
    error: str | None = None


@dataclass
class _ConnectedServer:
    session: ClientSession
    tools: list[types.Tool] = field(default_factory=list)


class MCPClientManager:
    """Administra conexiones stdio a un conjunto de servidores MCP.

    Se construye con el subconjunto de ServerConfig que se quiere levantar
    para una corrida dada (el llamador decide que servidores incluir segun
    el modo y las banderas de ablation). Servidores no incluidos aqui
    simplemente nunca se arrancan, lo que ahorra costo y latencia.
    """

    def __init__(
        self,
        server_configs: dict[str, ServerConfig],
        tool_timeout_seconds: float = _DEFAULT_TOOL_TIMEOUT_SECONDS,
    ) -> None:
        self._configs = server_configs
        self._tool_timeout_seconds = tool_timeout_seconds
        self._exit_stack = AsyncExitStack()
        self._connected: dict[str, _ConnectedServer] = {}
        self._qualified_to_server: dict[str, tuple[str, str]] = {}
        # Una sola instancia por MCPClientManager: en modo lote se crea un
        # solo manager para las 1,000 filas (ver batch.py), asi que la
        # ventana deslizante persiste correctamente a lo largo de toda la
        # corrida, no solo por correo.
        self._virustotal_rate_limiter = SlidingWindowRateLimiter(
            max_calls=_VIRUSTOTAL_RATE_LIMIT_MAX_CALLS,
            period_seconds=_VIRUSTOTAL_RATE_LIMIT_PERIOD_SECONDS,
        )

    async def __aenter__(self) -> "MCPClientManager":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Cierra todas las sesiones y subprocesos abiertos."""
        await self._exit_stack.aclose()

    async def connect_all(self) -> dict[str, str]:
        """Conecta a cada servidor configurado.

        Devuelve un diccionario {id_servidor: estado}, donde estado es "ok"
        o un mensaje de error. Un fallo en un servidor no interrumpe la
        conexion a los demas.
        """
        statuses: dict[str, str] = {}
        for server_id, cfg in self._configs.items():
            statuses[server_id] = await self._connect_one(server_id, cfg)
        return statuses

    async def _connect_one(self, server_id: str, cfg: ServerConfig) -> str:
        local_stack = AsyncExitStack()
        try:
            params = StdioServerParameters(
                command=cfg.command,
                args=cfg.args,
                cwd=cfg.cwd,
                env=cfg.env,
            )
            read_stream, write_stream = await local_stack.enter_async_context(
                stdio_client(params)
            )
            session = await local_stack.enter_async_context(
                ClientSession(read_stream, write_stream)
            )
            await session.initialize()
            tools_result = await session.list_tools()
        except Exception as exc:
            await local_stack.aclose()
            message = f"error al conectar: {exc}"
            logger.warning("Servidor MCP '%s' no disponible: %s", server_id, exc)
            return message

        # El servidor conecto bien: transferimos su ciclo de vida al stack
        # principal para que se cierre junto con los demas al terminar.
        await self._exit_stack.enter_async_context(local_stack)
        self._connected[server_id] = _ConnectedServer(session=session, tools=tools_result.tools)
        for tool in tools_result.tools:
            qualified_name = self._qualify(server_id, tool.name)
            self._qualified_to_server[qualified_name] = (server_id, tool.name)
        logger.info(
            "Servidor MCP '%s' conectado con %d herramientas", server_id, len(tools_result.tools)
        )
        return "ok"

    def is_connected(self, server_id: str) -> bool:
        return server_id in self._connected

    def connected_server_ids(self) -> list[str]:
        return list(self._connected.keys())

    def get_anthropic_tools(self, exclude_server_ids: set[str] | None = None) -> list[dict[str, Any]]:
        """Arma la lista de tools en el formato que espera la API de Anthropic.

        exclude_server_ids permite ocultar temporalmente las herramientas de
        un servidor conectado sin desconectarlo, por ejemplo VirusTotal
        cuando el correo actual no contiene URLs.
        """
        excluded = exclude_server_ids or set()
        tools: list[dict[str, Any]] = []
        for server_id, connected in self._connected.items():
            if server_id in excluded:
                continue
            for tool in connected.tools:
                tools.append(
                    {
                        "name": self._qualify(server_id, tool.name),
                        "description": tool.description or "",
                        "input_schema": tool.input_schema,
                    }
                )
        return tools

    async def call_tool(
        self,
        qualified_name: str,
        arguments: dict[str, Any],
        call_cache: dict[tuple[str, str], ToolCallResult] | None = None,
    ) -> ToolCallResult:
        """Ejecuta una herramienta MCP por su nombre calificado.

        Nunca lanza excepciones hacia el llamador: cualquier fallo (servidor
        caido, timeout, error de la herramienta) se devuelve como
        ToolCallResult con ok=False, para que el loop del orquestador pueda
        continuar con las demas herramientas.

        call_cache es opcional y lo administra el llamador (orchestrator.py
        crea uno nuevo por correo, ver run_analysis): si se pasa, una llamada
        con el mismo nombre calificado y los mismos argumentos que ya se
        ejecuto en ese diccionario devuelve el resultado guardado sin volver
        a golpear el servidor MCP (ni, para VirusTotal, consumir cupo de
        rate limit) -- pensado para el caso en que el modelo pide la misma
        herramienta mas de una vez en distintas iteraciones del mismo
        analisis.
        """
        mapping = self._qualified_to_server.get(qualified_name)
        if mapping is None:
            return ToolCallResult(
                server_id="desconocido",
                tool_name=qualified_name,
                ok=False,
                error=f"Herramienta no reconocida: '{qualified_name}'",
            )

        server_id, tool_name = mapping
        connected = self._connected.get(server_id)
        if connected is None:
            return ToolCallResult(
                server_id=server_id,
                tool_name=tool_name,
                ok=False,
                error=f"El servidor '{server_id}' no esta conectado",
            )

        cache_key: tuple[str, str] | None = None
        if call_cache is not None:
            cache_key = (qualified_name, json.dumps(arguments, sort_keys=True, default=str))
            cached = call_cache.get(cache_key)
            if cached is not None:
                logger.info(
                    "Tool call repetido: '%s' ya se invoco con los mismos argumentos en "
                    "este correo, reutilizando resultado cacheado (sin nuevo request)",
                    qualified_name,
                )
                return cached

        if server_id == "virustotal":
            await self._virustotal_rate_limiter.acquire()

        try:
            result = await connected.session.call_tool(
                tool_name,
                arguments,
                read_timeout_seconds=self._tool_timeout_seconds,
            )
        except Exception as exc:
            logger.warning(
                "Fallo al invocar '%s' en servidor '%s': %s", tool_name, server_id, exc
            )
            call_result = ToolCallResult(server_id=server_id, tool_name=tool_name, ok=False, error=str(exc))
            if cache_key is not None:
                call_cache[cache_key] = call_result
            return call_result

        if result.is_error:
            error_message = _stringify_content(result.content) or "Error desconocido de la herramienta"
            call_result = ToolCallResult(server_id=server_id, tool_name=tool_name, ok=False, error=error_message)
            if cache_key is not None:
                call_cache[cache_key] = call_result
            return call_result

        data = _extract_result_data(result)
        call_result = ToolCallResult(server_id=server_id, tool_name=tool_name, ok=True, data=data)
        if cache_key is not None:
            call_cache[cache_key] = call_result
        return call_result

    @staticmethod
    def _qualify(server_id: str, tool_name: str) -> str:
        return f"{server_id}{_TOOL_SEPARATOR}{tool_name}"


def _extract_result_data(result: types.CallToolResult) -> Any:
    """Extrae el dato util de un CallToolResult, prefiriendo structured_content."""
    if result.structured_content is not None:
        return result.structured_content

    texts = [block.text for block in result.content if isinstance(block, types.TextContent)]
    if not texts:
        return None
    if len(texts) == 1:
        return _try_parse_json(texts[0])
    return [_try_parse_json(text) for text in texts]


def _try_parse_json(text: str) -> Any:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return text


def _stringify_content(content: list[types.ContentBlock]) -> str:
    texts = [block.text for block in content if isinstance(block, types.TextContent)]
    return "\n".join(texts)
