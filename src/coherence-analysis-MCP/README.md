# Coherence Analysis MCP

Servidor MCP de analisis de coherencia interna de correos. Componente del
prototipo de deteccion de phishing con modelos de lenguaje grandes y
servidores MCP (trabajo de graduacion, Universidad del Valle de Guatemala).

## Que es

Este servidor audita las **contradicciones internas** de un correo: si lo que
dice ser el remitente, el tono, el formato, lo que pide y la firma son
consistentes entre si. La idea central es que un correo legitimo suele ser
internamente coherente, mientras que uno de phishing casi siempre tiene
costuras, aunque cada elemento por separado no parezca sospechoso: dice ser
tu banco pero saluda de forma generica, transmite urgencia extrema con un
tono informal y errores, pide datos que una entidad real nunca pediria por
correo, o firma como una organizacion distinta a la que aparece en el
remitente.

Punto central de diseno: **el servidor no emite un veredicto de phishing.**
Solo reporta las incoherencias detectadas, cada una con su cita textual
literal como evidencia. La decision final de clasificacion pertenece al
orquestador.

Otro punto central de diseno: **la deteccion la hace un LLM con salida
estructurada, no listas de palabras clave ni conteos lexicos.** Se probo que
los conteos lexicos no discriminan bien entre correos legitimos y de
phishing; el LLM puede razonar sobre coherencia semantica y de estilo de una
forma que un conteo de palabras no puede.

El servidor esta pensado para correos **en ingles**: el prompt y las
descripciones de las categorias estan escritos para ese idioma.

Para la descripcion tecnica completa (como se comunica, que hace paso a paso
y cuales son sus limites) ver [DESCRIPCION.md](DESCRIPCION.md).

## Categorias de incoherencia auditadas

| Categoria | Que busca |
|---|---|
| `sender_vs_content` | Afirma ser una entidad conocida pero el saludo es generico o el estilo no cuadra |
| `urgency_vs_channel` | Comunica algo grave o urgente de forma informal o con errores |
| `subject_vs_body` | El asunto y el cuerpo no coinciden en lo que ofrecen o piden |
| `authority_vs_execution` | Se presenta como oficial pero tiene errores de gramatica, formato pobre o inconsistencias |
| `request_vs_context` | Pide datos sensibles o acciones que una entidad legitima no solicitaria por correo |
| `identity_consistency` | El remitente, la firma y el contenido nombran entidades distintas o inconsistentes |

Un correo puede mostrar cero, una o varias de estas incoherencias; el LLM no
esta forzado a encontrar algo en cada categoria.

## Estructura del proyecto

```
coherence-analysis-MCP/
├── src/coherence_analysis_mcp/
│   ├── __init__.py       Expone main() importandola desde server
│   ├── server.py         Servidor MCP y definicion de las 3 herramientas
│   ├── schema.py         Esquema Pydantic de salida y las 6 categorias
│   ├── llm_engine.py     Abstraccion del motor LLM (mock + Anthropic)
│   └── coherence.py      Logica del analisis: prompt, guardrails, validacion de evidencia
├── tests/
│   ├── test_coherence.py     Pruebas unitarias (esquema, evidencia, modo mock)
│   └── test_integration.py   Prueba end-to-end (cliente MCP real por stdio, modo mock)
├── run_server.py          Punto de entrada recomendado para arrancar el servidor
├── pyproject.toml         Metadatos, dependencias y comando de consola
├── uv.lock                Versiones exactas de las dependencias
├── .python-version        Version de Python que usa uv (3.10)
├── .env                   Variables de entorno locales (no se versiona)
├── DESCRIPCION.md         Descripcion tecnica completa del servidor
└── README.md
```

## Requisitos

- Python 3.10 o superior.
- SDK de MCP para Python version 2 o superior (`mcp[cli]>=2.0.0`), Pydantic 2
  y el SDK de Anthropic. Se instalan solos con los comandos de abajo.

## Instalacion

Con `uv` (recomendado; instala tambien `pytest`, que esta en el grupo `dev`):

```bash
uv sync
```

Con pip en modo editable (`pytest` se instala aparte porque `dev` es un grupo
de dependencias de `uv`, no un extra de pip):

```bash
pip install -e . pytest
```

## Configuracion del motor LLM

El motor LLM se configura por variable de entorno; nunca hay una API key
hardcodeada en el codigo.

| Variable | Valores | Por defecto |
|---|---|---|
| `COHERENCE_LLM_PROVIDER` | `mock` o `anthropic` | `mock` |
| `COHERENCE_LLM_MODEL` | nombre del modelo (solo aplica si el proveedor no es `mock`) | `claude-sonnet-5` |
| `COHERENCE_LLM_API_KEY` | API key del proveedor configurado | (vacio) |

**El codigo no lee el archivo `.env` por si solo.** Las variables tienen que
estar en el entorno del proceso que arranca el servidor. Hay dos formas:

- Desde la terminal, pedirle a `uv` que cargue el archivo:

  ```bash
  uv run --env-file .env python run_server.py
  ```

- Desde un cliente MCP, declararlas en el bloque `env` de su configuracion
  (ver "Como conectarlo a un cliente MCP").

Sin ninguna de las dos, el servidor arranca en modo mock. `.env` no se
versiona porque contiene la API key.

**Modo mock (`COHERENCE_LLM_PROVIDER=mock`, valor por defecto):** no llama a
ninguna API ni necesita conectividad ni API key. Devuelve siempre la misma
respuesta fija y valida, calibrada sobre un correo de referencia
(`MOCK_EMAIL_TEXT` en `llm_engine.py`). Es el modo que usan las pruebas
automatizadas. Como la respuesta es fija, en este modo el servidor **no
analiza de verdad** el correo que recibe: si el correo no contiene las citas
del correo de referencia, todas se descartan y el reporte sale sin
incoherencias. Sirve para probar el servidor, no para evaluar correos.

**Proveedor real implementado: Anthropic.** Usa *tool use* forzado
(`tool_choice`) contra la API de Claude para obtener JSON valido segun el
esquema de `schema.py`, que luego se vuelve a validar con Pydantic. Es el
unico proveedor real de referencia por ahora; la clase `LLMEngine` en
`llm_engine.py` esta disenada para que agregar otro proveedor (OpenAI, por
ejemplo) sea sumar una subclase nueva y una rama en `get_engine()`, sin tocar
`coherence.py` ni `server.py`.

## Herramientas expuestas

| Herramienta | Que hace |
|---|---|
| `analyze_coherence` | Dado el texto de un correo, devuelve el reporte de incoherencias detectadas (JSON validado) |
| `get_output_schema` | Devuelve el esquema JSON de salida, para que el orquestador sepa que esperar sin llamar primero a `analyze_coherence` |
| `list_incoherence_categories` | Lista las 6 categorias de incoherencia auditadas, con su descripcion |

### Forma del reporte de `analyze_coherence`

```json
{
  "incoherences": [
    {
      "category": "sender_vs_content",
      "description": "...",
      "quote": "cita textual literal del correo"
    }
  ],
  "coherence_score": 0.15,
  "summary": "Resumen en lenguaje claro de las principales incoherencias.",
  "discarded_count": 0
}
```

- `coherence_score` va de 0 (lleno de contradicciones) a 1 (totalmente
  coherente). Es la estimacion del LLM y **no se recalcula** cuando se
  descartan incoherencias: un reporte puede traer un puntaje bajo y una lista
  vacia si todas las citas resultaron invalidas. En ese caso `discarded_count`
  es la senal de que el puntaje no esta respaldado por evidencia.
- Cada incoherencia trae una cita textual **literal** del correo como
  evidencia obligatoria. `coherence.py` valida que cada cita aparezca
  realmente en el texto (ignorando solo diferencias de espacios); cualquier
  incoherencia cuya cita no exista se descarta antes de devolver el
  resultado, y `discarded_count` indica cuantas se descartaron asi.
- El correo se trata siempre como dato no confiable: el prompt lo delimita
  explicitamente y le indica al LLM que ignore cualquier instruccion dentro
  del texto del correo (guardrail contra prompt injection).

### Que pasa cuando algo falla

| Situacion | Resultado |
|---|---|
| La respuesta del LLM no cumple el esquema, o no trae el bloque `tool_use` | Se reintenta una vez. Si vuelve a fallar se devuelve un reporte de respaldo: sin incoherencias, `coherence_score` 0.5 y un `summary` que explica que el analisis no se pudo completar |
| Proveedor desconocido, o `anthropic` sin API key | La herramienta responde con error (`isError: true`); no hay reporte de respaldo |
| Error de la API de Anthropic (red, autenticacion, limite de uso) | La herramienta responde con error (`isError: true`); no hay reintento ni reporte de respaldo |

El orquestador debe revisar `isError` antes de leer el reporte, y tratar un
`coherence_score` de 0.5 con lista vacia como "sin senal", no como "correo
medianamente coherente".

## Como probarlo

**1. Pruebas unitarias** (rapidas, sin arrancar el servidor ni llamar a
ninguna API; usan el modo mock):

```bash
uv run python tests/test_coherence.py
```

**2. Prueba de integracion end-to-end** (arranca el servidor y actua como
cliente MCP real, con handshake y llamada a las 3 herramientas, forzando
modo mock):

```bash
uv run python tests/test_integration.py
```

**3. Con pytest** (corre solo las 11 pruebas unitarias):

```bash
uv run pytest tests/
```

`pytest` no ejecuta la prueba de integracion, porque `test_integration.py` no
define funciones `test_*`; esa prueba se corre siempre con el comando del
punto 2.

**4. Inspeccion manual con el MCP Inspector** (interfaz visual oficial):

```bash
uv run mcp dev src/coherence_analysis_mcp/server.py
```

**5. Arranque directo del servidor** (queda esperando mensajes por stdio;
usa Ctrl+C para salir):

```bash
uv run python run_server.py
```

Arranca en modo mock. Para usar el proveedor real desde la terminal, agrega
`--env-file .env` como se explica en "Configuracion del motor LLM".

## Como conectarlo a un cliente MCP

Para usarlo desde un cliente compatible (por ejemplo, Claude Desktop, o el
orquestador del prototipo), agrega al archivo de configuracion del cliente:

```json
{
  "mcpServers": {
    "coherence-analysis-mcp": {
      "command": "uv",
      "args": ["run", "python", "run_server.py"],
      "cwd": "/ruta/al/proyecto/coherence-analysis-MCP",
      "env": {
        "PYTHONUTF8": "1",
        "COHERENCE_LLM_PROVIDER": "anthropic",
        "COHERENCE_LLM_MODEL": "claude-sonnet-5",
        "COHERENCE_LLM_API_KEY": "..."
      }
    }
  }
}
```

## Por que existe run_server.py (y no simplemente el comando de consola)

El proyecto tambien instala un comando de consola (`coherence-analysis-mcp`,
definido en `[project.scripts]` de `pyproject.toml`), que es la convencion
normal de este tipo de servidor MCP. Sin embargo, ese comando depende de que
`coherence_analysis_mcp` sea importable a traves del mecanismo de instalacion
editable de `uv`/pip (un archivo `.pth` en `site-packages` que apunta de
vuelta a `src/`). En maquinas donde la ruta del proyecto contiene caracteres
no ASCII (como las tildes y la eñe de este proyecto: `Sofía`, `año`), Python
puede leer ese `.pth` con la codificacion de texto por defecto del sistema
(`cp1252` en Windows en vez de UTF-8), la ruta queda corrupta, y el import
falla en silencio con `ModuleNotFoundError: No module named
'coherence_analysis_mcp'`, sin relacion alguna con el codigo del servidor.

`run_server.py` evita el problema de raiz: agrega `src/` a `sys.path`
directamente en Python (con `pathlib`, sin leer ningun archivo `.pth`) antes
de importar el paquete. Funciona igual sin importar quien lo invoque (tu
terminal, `mcp dev`, o un cliente MCP como Claude Desktop) y sin necesitar
ninguna variable de entorno. Por eso es el metodo recomendado, tanto en los
comandos de arriba como en el ejemplo de configuracion de cliente MCP.

Si prefieres usar `uv run coherence-analysis-mcp` de todas formas y tu
maquina tiene el mismo problema, corre `set PYTHONUTF8=1` (cmd) o
`$env:PYTHONUTF8=1` (PowerShell) antes, en la misma terminal donde vas a
correr el comando.

La variable de entorno `PYTHONUTF8=1` fuerza a Python a usar UTF-8 en todos
lados y resuelve esto por completo. Por eso aparece en el `.env` del proyecto
y en el `env` del ejemplo de configuracion de cliente MCP arriba (los
clientes como Claude Desktop arrancan el servidor como un subproceso nuevo,
que no hereda las variables que hayas exportado en tu propia terminal). Ojo:
tenerla en `.env` solo tiene efecto si arrancas con
`uv run --env-file .env`, porque nada mas carga ese archivo.

Las pruebas (`test_coherence.py`, `test_integration.py`, `pytest`) no
necesitan esto porque agregan `src/` a `sys.path` explicitamente en el codigo
(o arrancan el servidor via `run_server.py`), sin depender de la instalacion
editable.

## Autoria

Sofia Mishell Velasquez - Universidad del Valle de Guatemala.
