"""
Prueba de integracion end-to-end del servidor MCP.

Arranca el servidor como subproceso (stdio) y actua como cliente MCP real:
hace el handshake, lista las herramientas y llama a cada una, verificando
las respuestas. Es la forma mas fiel de comprobar que un orquestador podra
usar el servidor. Ejecutar con:  python tests/test_integration.py
"""

import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Arranca el servidor via run_server.py, el mismo mecanismo recomendado en el
# README (y el que usaria un cliente MCP real como Claude Desktop). No
# depende de la instalacion editable del paquete, asi que esta prueba valida
# el camino real de arranque, no un atajo artificial.
RUN_SERVER = str(Path(__file__).parent.parent / "run_server.py")

SERVER = StdioServerParameters(
    command=sys.executable,
    args=[RUN_SERVER],
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

            # 2. list_archetypes
            r = await session.call_tool("list_archetypes", {})
            assert not r.is_error, "list_archetypes fallo"
            datos = _leer_json(r)
            assert datos["count"] == len(datos["archetypes"]) and datos["count"] > 0
            print(f"list_archetypes: OK ({datos['count']} arquetipos)")

            primer_id = datos["archetypes"][0]["id"]

            # 3. get_archetype (id valido)
            r = await session.call_tool("get_archetype", {"archetype_id": primer_id})
            assert not r.is_error, "get_archetype fallo"
            perfil = _leer_json(r)
            assert perfil["found"] is True and perfil["id"] == primer_id
            assert "representative_examples" in perfil
            print("get_archetype (id valido): OK")

            # 4. get_archetype (id invalido, no debe explotar)
            r = await session.call_tool("get_archetype", {"archetype_id": -999999})
            assert not r.is_error, "get_archetype con id invalido no deberia fallar como error de protocolo"
            perfil_invalido = _leer_json(r)
            assert perfil_invalido["found"] is False
            print("get_archetype (id invalido): OK")

            # 5. classify_archetype
            r = await session.call_tool(
                "classify_archetype",
                {
                    "email_text": (
                        "URGENT: your account has been suspended, verify your "
                        "bank details now or you will lose access"
                    )
                },
            )
            assert not r.is_error, "classify_archetype fallo"
            clasificacion = _leer_json(r)
            for campo in ("archetype_id", "similarity", "label", "dominant_emotion", "social_engineering_tactic", "caveat"):
                assert campo in clasificacion, f"Falta '{campo}' en la respuesta de classify_archetype"
            print(
                f"classify_archetype: OK (archetype_id={clasificacion['archetype_id']}, "
                f"similarity={clasificacion['similarity']:.3f})"
            )

    print("\nTodas las herramientas respondieron correctamente end-to-end.")


if __name__ == "__main__":
    asyncio.run(run())
