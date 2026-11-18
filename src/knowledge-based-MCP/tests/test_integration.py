"""
Prueba de integracion end-to-end del servidor MCP.

Arranca el servidor como subproceso (stdio) y actua como cliente MCP real:
hace el handshake, lista las herramientas y llama a cada una, verificando
las respuestas. Es la forma mas fiel de comprobar que un orquestador podra
usar el servidor. Ejecutar con:  python tests/test_integration.py
"""

import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Arranca el servidor con el mismo interprete, importando el modulo
SRC = str(Path(__file__).parent.parent / "src")

SERVER = StdioServerParameters(
    command=sys.executable,
    args=["-c", "from knowledge_based_mcp.server import main; main()"],
    env={"PYTHONPATH": SRC},
)


async def run() -> None:
    async with stdio_client(SERVER) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("Handshake MCP: OK")

            # 1. Listar herramientas
            tools = (await session.list_tools()).tools
            names = [t.name for t in tools]
            assert len(names) == 8, f"Se esperaban 8 tools, hay {len(names)}"
            print(f"Herramientas: {len(names)} -> {', '.join(names)}")

            # 2. get_definition
            r = await session.call_tool("get_definition",
                                        {"name_or_id": "tactic_urgency"})
            assert not r.is_error, "get_definition fallo"
            print("get_definition: OK")

            # 3. list_types
            r = await session.call_tool("list_types", {})
            assert not r.is_error
            print("list_types: OK")

            # 4. list_by_type
            r = await session.call_tool("list_by_type",
                                        {"entry_type": "persuasion_principle"})
            assert not r.is_error
            print("list_by_type: OK")

            # 5. search_knowledge
            r = await session.call_tool("search_knowledge",
                                        {"query": "fake invoice", "limit": 3})
            assert not r.is_error
            print("search_knowledge: OK")

            # 6. match_reference_phrases
            r = await session.call_tool(
                "match_reference_phrases",
                {"text": "act now, immediate action required within 24 hours"})
            assert not r.is_error
            print("match_reference_phrases: OK")

            # 7. explain_concepts
            r = await session.call_tool("explain_concepts",
                                        {"concepts": ["tactic_urgency"]})
            assert not r.is_error
            print("explain_concepts: OK")

            # 8. get_label_schema
            r = await session.call_tool("get_label_schema", {"name": "dataphish"})
            assert not r.is_error
            print("get_label_schema: OK")

            # 9. get_analysis_policy
            r = await session.call_tool("get_analysis_policy", {})
            assert not r.is_error
            print("get_analysis_policy: OK")

    print("\nTodas las herramientas respondieron correctamente end-to-end.")


if __name__ == "__main__":
    asyncio.run(run())
