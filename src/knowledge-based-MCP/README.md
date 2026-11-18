# Knowledge-based MCP

Servidor MCP de conocimiento sobre phishing e ingeniería social. Componente del prototipo de detección de phishing con modelos de lenguaje grandes y servidores MCP (trabajo de graduación, Universidad del Valle de Guatemala).

Para la descripción completa del servidor (arquitectura, protocolo de comunicación, detalle de cada herramienta y de la base de conocimiento), ver [DESCRIPCION_MCP.md](DESCRIPCION_MCP.md).

## Qué es

Este servidor expone una base de conocimiento curada (111 entradas, 13 fuentes) como herramientas consultables por un orquestador. Provee definiciones, taxonomías, principios de persuasión, tácticas de ingeniería social, patrones de señuelo, emociones, motivaciones e indicadores técnicos, cada uno con su fuente.

Punto central de diseño: **el servidor no clasifica correos ni emite veredictos.** Solo aporta conocimiento fundamentado para que el orquestador construya explicaciones interpretables del porqué un correo puede ser riesgoso. La decisión final de clasificación pertenece al orquestador, no a este servidor. Esta separación está codificada en los guardrails de la propia base de conocimiento (`analysis_guardrails`).

El alcance es correo electrónico **en inglés**: tanto las entradas como las frases de referencia están en ese idioma.

## Estructura del proyecto

```
knowledge-based-mcp/
├── src/knowledge_based_mcp/
│   ├── __init__.py            Expone main() importándola desde server
│   ├── server.py              Servidor MCP y definición de las 8 herramientas
│   ├── knowledge.py           Capa de acceso a la base (consultas deterministas)
│   └── knowledge_base.json    Base de conocimiento (111 entradas, 13 fuentes)
├── tests/
│   ├── test_knowledge.py      Pruebas unitarias de la capa de conocimiento
│   └── test_integration.py    Prueba end-to-end (cliente MCP real por stdio)
├── DESCRIPCION_MCP.md         Descripción completa del servidor
├── pyproject.toml
├── uv.lock
└── README.md
```

## Herramientas expuestas

| Herramienta | Argumentos | Qué hace |
|---|---|---|
| `get_definition` | `name_or_id` | Definición de un concepto, táctica o emoción por id o nombre, con citas |
| `list_types` | — | Lista los tipos de entrada disponibles |
| `list_by_type` | `entry_type` | Lista todas las entradas de un tipo |
| `search_knowledge` | `query`, `limit` (opcional, 10) | Búsqueda léxica libre sobre la base |
| `match_reference_phrases` | `text` | Detecta frases de referencia conocidas en un texto (señal de línea base) |
| `explain_concepts` | `concepts` (lista) | Explicación fundamentada a partir de conceptos detectados, con citas |
| `get_label_schema` | `name` (opcional, `dataphish`) | Esquema de etiquetas (emociones y motivaciones) del dataset fuente |
| `get_analysis_policy` | — | Guardrails y alcance del servidor |

Todas son de solo lectura. Cada respuesta llega al cliente como un bloque de texto con JSON. Una consulta sin resultado no es un error: se indica en el contenido (`"found": false` o una lista vacía).

## Requisitos

- Python 3.10 o superior
- `mcp[cli]` 2.0.0 o superior

## Instalación

Con `uv` (recomendado):

```bash
uv sync
```

Con pip en modo editable:

```bash
pip install -e .
```

## Cómo probarlo

Los comandos usan `uv run` para ejecutarse dentro del entorno del proyecto. Si instalaste con pip, activa tu entorno y omite el prefijo `uv run`.

**1. Pruebas unitarias** (rápidas, no arrancan el servidor):

```bash
uv run python tests/test_knowledge.py
```

**2. Prueba de integración end-to-end** (arranca el servidor y actúa como cliente MCP real, con handshake y llamada a las 8 herramientas):

```bash
uv run python tests/test_integration.py
```

**3. Inspección manual con el MCP Inspector** (interfaz visual oficial):

```bash
uv run mcp dev src/knowledge_based_mcp/server.py
```

**4. Arranque directo del servidor** (queda esperando mensajes por stdio):

```bash
uv run knowledge-based-mcp
```

## Cómo conectarlo a un cliente MCP

El servidor se comunica por **stdio**: el cliente lo lanza como subproceso e intercambia mensajes JSON-RPC por la entrada y la salida estándar. No abre puertos de red.

Para usarlo desde un cliente compatible (por ejemplo, Claude Desktop), agrega al archivo de configuración del cliente:

```json
{
  "mcpServers": {
    "knowledge-based-mcp": {
      "command": "knowledge-based-mcp"
    }
  }
}
```

Si no está instalado como comando de consola, usa `uv`:

```json
{
  "mcpServers": {
    "knowledge-based-mcp": {
      "command": "uv",
      "args": ["run", "knowledge-based-mcp"],
      "cwd": "/ruta/al/proyecto/knowledge-based-mcp"
    }
  }
}
```

## Base de conocimiento

Diagnóstico verificado de `knowledge_base.json`:

- 111 entradas, 13 fuentes. Los conteos declarados en `meta` coinciden con los reales.
- Cero enlaces rotos en `related_entry_ids`.
- Cero referencias rotas en `source_ids`; todas las entradas tienen fuente.
- 11 tipos de entrada, con roles de clasificación (context, supporting_context, background_context, safety_guardrail, reasoning_guardrail).
- 32 entradas con frases de referencia, 87 frases en total: 23 de las 24 tácticas de ingeniería social más los 9 patrones de señuelo. Son ejemplos redactados para la tesis, no citas de las fuentes.
- Guardrails de análisis y política de alcance presentes y aplicados por el servidor.

Entradas por tipo:

| Tipo | Entradas |
|---|---|
| `social_engineering_tactic` | 24 |
| `core_concept` | 13 |
| `technical_indicator` | 12 |
| `requested_action` | 10 |
| `lure_pattern` | 9 |
| `attacker_goal` | 8 |
| `detection_method` | 8 |
| `emotion` | 8 |
| `llm_security` | 8 |
| `persuasion_principle` | 6 |
| `reasoning_rule` | 5 |

## Fuentes del cuerpo de conocimiento

Las 13 fuentes combinan literatura académica y reportes de industria:

- **Persuasión:** Cialdini (2007).
- **Ingeniería social y detección de phishing:** Alsufyani y Alzahrani (2021); Safi y Singh (2023); Koide et al. (2024); Zheng (2025); Panda (2025); Hasan et al. (2025); Gobinath y Manikandan (2026).
- **Esquema de emociones y motivaciones:** Tóth et al. (2025).
- **Reportes de industria:** Verizon DBIR 2025; Comcast Business 2025; IBM Cost of a Data Breach 2025; CrowdStrike Global Threat Report 2026.

Las citas completas están en la sección `sources` de `knowledge_base.json` y el servidor las devuelve junto con cada definición o explicación.
