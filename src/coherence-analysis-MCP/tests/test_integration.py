"""
Prueba de integracion end-to-end del servidor MCP.

Arranca el servidor como subproceso (stdio) y actua como cliente MCP real:
hace el handshake, lista las herramientas y llama a cada una, verificando
las respuestas. Fuerza COHERENCE_LLM_PROVIDER=mock en el entorno del
subproceso, para no depender de ninguna API ni API key. Es la forma mas
fiel de comprobar que un orquestador podra usar el servidor. Ejecutar con:
python tests/test_integration.py
"""

import asyncio
import json
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from coherence_analysis_mcp.llm_engine import MOCK_EMAIL_TEXT  # noqa: E402

# Arranca el servidor via run_server.py, el mismo mecanismo recomendado en el
# README (y el que usaria un cliente MCP real como Claude Desktop). No
# depende de la instalacion editable del paquete, asi que esta prueba valida
# el camino real de arranque, no un atajo artificial.
RUN_SERVER = str(Path(__file__).parent.parent / "run_server.py")

SERVER = StdioServerParameters(
    command=sys.executable,
    args=[RUN_SERVER],
    env={
        **os.environ,
        "PYTHONUTF8": "1",
        "COHERENCE_LLM_PROVIDER": "mock",
    },
)


def _leer_json(resultado) -> dict:
    """Extrae y decodifica el JSON de texto que devuelve una herramienta."""
    return json.loads(resultado.content[0].text)


async def run() -> None:
    async with stdio_client(SERVER) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("Handshake MCP: OK")

            # 1. Listar herramientas
            tools = (await session.list_tools()).tools
            names = [t.name for t in tools]
            assert len(names) == 3, f"Se esperaban 3 tools, hay {len(names)}"
            print(f"Herramientas: {len(names)} -> {', '.join(names)}")

            # 2. list_incoherence_categories
            r = await session.call_tool("list_incoherence_categories", {})
            assert not r.is_error, "list_incoherence_categories fallo"
            categorias = _leer_json(r)
            assert categorias["count"] == 6 and len(categorias["categories"]) == 6
            for entrada in categorias["categories"]:
                assert entrada["id"] and entrada["description"]
            print(f"list_incoherence_categories: OK ({categorias['count']} categorias)")

            # 3. get_output_schema
            r = await session.call_tool("get_output_schema", {})
            assert not r.is_error, "get_output_schema fallo"
            esquema = _leer_json(r)
            propiedades = esquema.get("properties", {})
            for campo in ("incoherences", "coherence_score", "summary", "discarded_count"):
                assert campo in propiedades, f"Falta '{campo}' en el esquema de salida"
            print("get_output_schema: OK")

            # 4. analyze_coherence, con el correo de referencia del modo mock:
            # las citas fijas del mock existen literalmente en este correo,
            # asi que deben sobrevivir al validador de evidencia.
            r = await session.call_tool(
                "analyze_coherence", {"email_text": MOCK_EMAIL_TEXT}
            )
            assert not r.is_error, "analyze_coherence fallo"
            reporte = _leer_json(r)
            for campo in ("incoherences", "coherence_score", "summary", "discarded_count"):
                assert campo in reporte, f"Falta '{campo}' en la respuesta de analyze_coherence"
            assert len(reporte["incoherences"]) == 5
            assert reporte["discarded_count"] == 0
            assert 0.0 <= reporte["coherence_score"] <= 1.0
            ids_validos = {c["id"] for c in categorias["categories"]}
            for incoherencia in reporte["incoherences"]:
                assert incoherencia["category"] in ids_validos
                assert incoherencia["quote"] in MOCK_EMAIL_TEXT, (
                    "Toda cita devuelta debe existir literal en el correo analizado"
                )
            print(
                f"analyze_coherence: OK ({len(reporte['incoherences'])} incoherencias, "
                f"coherence_score={reporte['coherence_score']:.2f})"
            )

            # 5. analyze_coherence con un correo que no contiene las citas
            # fijas del mock: no debe fallar, y debe descartar todo.
            r = await session.call_tool(
                "analyze_coherence",
                {"email_text": "This is a completely unrelated legitimate email about a meeting."},
            )
            assert not r.is_error, "analyze_coherence (correo sin coincidencias) fallo"
            reporte_vacio = _leer_json(r)
            assert reporte_vacio["incoherences"] == []
            assert reporte_vacio["discarded_count"] == 5
            print("analyze_coherence (sin coincidencias de evidencia): OK")

    print("\nTodas las herramientas respondieron correctamente end-to-end.")


if __name__ == "__main__":
    asyncio.run(run())
