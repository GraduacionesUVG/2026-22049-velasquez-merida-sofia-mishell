# Cómo funciona el orquestador de detección de phishing

Este documento explica el proyecto completo: qué hace, qué piezas lo forman,
cómo se comunica el orquestador con los servidores MCP y qué ocurre, paso a
paso, cuando se analiza un correo. El [README](../README.md) cubre la
instalación y los comandos; aquí está el porqué y el cómo. La sección 13
describe la interfaz web.

## 1. Qué es y qué hace

Es un programa en Python que recibe el texto de un correo electrónico y
responde si es `phishing` o `legitimo`, con un puntaje de riesgo entre 0 y 1
y, si se le pide, una explicación con evidencia.

No es un clasificador entrenado. Es un **orquestador**: un modelo Claude
(vía la API de Anthropic) que lee el correo, decide qué herramientas
consultar, lee lo que esas herramientas responden y redacta el veredicto. Las
herramientas viven en cuatro **servidores MCP** (Model Context Protocol)
independientes. Cada servidor aporta un tipo de evidencia; ninguno clasifica.

La regla central del diseño es esta: **el veredicto siempre es del
orquestador**. Los servidores solo informan.

## 2. Las piezas

```text
                         Usuario / script
                               |
                     CLI  (cli.py: analizar | lote)
                               |
        +----------------------+----------------------+
        |              ORQUESTADOR (este repo)        |
        |                                             |
        |  orchestrator.py   loop agentico            |
        |  prompts.py        system prompt + guardrail|
        |  extraction.py     regex de URLs/dominios/IP|
        |  schemas.py        salida validada (Pydantic)|
        |  mcp_client.py     cliente MCP (stdio)      |
        +------+----------------------------+---------+
               |                            |
        HTTPS (API de Anthropic)      stdio (JSON-RPC, protocolo MCP)
               |                            |
        +------+------+     +---------+-----+-----+-----------+
        | Claude      |     |         |           |           |
        | (modelo     | knowledge  archetype  coherence   virustotal
        | orquestador)|  (propio)   (propio)   (propio)   (terceros, npm)
        +-------------+     |         |           |           |
                         base de   embeddings   LLM de     API de
                         conoci-   locales +    Anthropic  VirusTotal
                         miento    KMeans       (propio)   (internet)
```

### El orquestador (este repositorio)

| Archivo | Responsabilidad |
| --- | --- |
| `cli.py` | Subcomandos `analizar` (un correo) y `lote` (un CSV). Decide qué servidores levantar. |
| `config.py` | Lee `.env` y `config/mcp_servers.yaml`; sustituye los `${VARIABLE}` del YAML. |
| `mcp_client.py` | Arranca los servidores, mantiene las sesiones MCP, traduce herramientas y ejecuta llamadas. |
| `orchestrator.py` | El loop agéntico: conversa con Claude, ejecuta las herramientas que pide y valida la respuesta final. |
| `prompts.py` | Construye el system prompt (rol, guardrail, herramientas, modo, indicadores) y el mensaje con el correo. |
| `extraction.py` | Extrae URLs, dominios e IPs con expresiones regulares, antes de llamar al modelo. |
| `schemas.py` | Modelos Pydantic de la salida (`VeredictoOutput`, `ExplicacionOutput`, `OrchestratorRunResult`, filas del lote). |
| `batch.py` | Modo lote: checkpoint reanudable, cuota de VirusTotal y métricas. |

### Los cuatro servidores MCP

Cada uno es un proceso aparte, con su propio repositorio y dependencias.

| Servidor | Qué aporta | Herramientas que expone | De qué depende |
| --- | --- | --- | --- |
| `knowledge` (knowledge-based-MCP) | Definiciones y citas sobre phishing, ingeniería social, persuasión y emociones. Fundamenta señales. | `get_definition`, `list_types`, `list_by_type`, `search_knowledge`, `match_reference_phrases`, `explain_concepts`, `get_label_schema`, `get_analysis_policy` | Solo datos locales. |
| `archetype` (pattern-archetype-MCP) | Compara el correo con 16 arquetipos de ataque aprendidos de un corpus de phishing. | `classify_archetype`, `list_archetypes`, `get_archetype` | Modelo de embeddings local (`all-MiniLM-L6-v2`) y un KMeans ya entrenado. |
| `coherence` (coherence-analysis-MCP) | Audita incoherencias internas del correo (remitente vs. contenido, urgencia vs. canal, asunto vs. cuerpo). | `analyze_coherence`, `get_output_schema`, `list_incoherence_categories` | Hace **su propia** llamada a un LLM de Anthropic. |
| `virustotal` (`@burtthecoder/mcp-virustotal`) | Reputación técnica de URLs, dominios e IPs. | 11 herramientas, entre ellas `get_url_report`, `get_domain_report`, `get_ip_report`, `get_domain_relationship`, `search_vt` | API de VirusTotal por internet. |

Dos advertencias sobre `archetype` que condicionan cómo se interpretan sus
resultados:

- Los arquetipos se construyeron **solo con correos de phishing**. El
  servidor devuelve el arquetipo más parecido también para un correo
  legítimo. Una similitud baja no prueba que el correo sea legítimo.
- Por eso el arquetipo es una señal, no un veredicto. En la evaluación de
  1,000 correos, 452 de los 500 legítimos recibieron algún arquetipo y el
  orquestador los clasificó como legítimos de todas formas.

## 3. Cómo se comunican el orquestador y los servidores MCP

### Transporte: subprocesos y stdio

Los servidores no son servicios web. El orquestador los **arranca como
subprocesos** y habla con ellos por su entrada y salida estándar (stdio),
con mensajes JSON-RPC del protocolo MCP. Cuando el orquestador termina,
cierra las sesiones y los subprocesos mueren con él.

Cómo arrancar cada uno está en `config/mcp_servers.yaml`:

| Servidor | Comando | Directorio de trabajo |
| --- | --- | --- |
| `knowledge` | `uv run python -c "from knowledge_based_mcp import main; main()"` | `KNOWLEDGE_MCP_PATH` |
| `archetype` | `uv run python run_server.py` | `PATTERN_ARCHETYPE_MCP_PATH` |
| `coherence` | `uv run python run_server.py` | `COHERENCE_MCP_PATH` |
| `virustotal` | `npx -y @burtthecoder/mcp-virustotal` | (ninguno) |

Cada subproceso recibe las variables de entorno declaradas en su bloque
`env` del YAML. Así llegan `VIRUSTOTAL_API_KEY` a VirusTotal y
`ANTHROPIC_API_KEY` a coherence (con el nombre `COHERENCE_LLM_API_KEY`).

### Conexión

`MCPClientManager.connect_all()` hace, para cada servidor seleccionado:

1. Lanza el subproceso y abre los canales de lectura y escritura.
2. Crea una `ClientSession` de MCP y envía `initialize` (el saludo del protocolo).
3. Pide `list_tools`: el servidor responde con el nombre, la descripción y
   el esquema JSON de entrada de cada herramienta.
4. Guarda la sesión y las herramientas, y registra el estado `ok`.

Si un servidor no arranca o no responde, se anota el error como su estado y
se sigue con los demás. Un servidor caído nunca tumba la corrida.

Solo se arrancan los servidores que la corrida va a usar (según el modo y el
flag `--mcp`). Un servidor no seleccionado no consume tiempo ni recursos.

### Traducción de herramientas MCP a herramientas de Claude

Claude no habla MCP. El orquestador le presenta cada herramienta MCP como
una herramienta normal de la API de Anthropic (`name`, `description`,
`input_schema`), copiando la descripción y el esquema que dio el servidor.

Para saber a qué servidor pertenece cada una, el nombre se prefija con el
identificador del servidor y dos guiones bajos:

```text
archetype__classify_archetype
knowledge__search_knowledge
coherence__analyze_coherence
virustotal__get_domain_report
```

Cuando Claude pide `archetype__classify_archetype`, el orquestador busca ese
nombre en su tabla, encuentra el servidor `archetype` y la herramienta
`classify_archetype`, y envía `call_tool` por la sesión stdio de ese servidor.

### Quién habla con quién

- **Claude nunca contacta a un servidor MCP.** Solo devuelve bloques
  `tool_use` ("quiero llamar esta herramienta con estos argumentos"). Quien
  ejecuta la llamada es el orquestador.
- **Los servidores MCP nunca hablan entre sí.** No se conocen. Si el
  resultado de uno sirve para consultar a otro (por ejemplo, tomar el
  arquetipo y pedir a `knowledge` la definición de su táctica), es Claude
  quien lo decide en el siguiente turno, y el orquestador quien hace la
  segunda llamada.
- **Los servidores no ven la conversación.** Solo reciben los argumentos de
  la herramienta (normalmente el texto del correo o un término de búsqueda).
- Dos servidores salen a la red por su cuenta: `coherence` llama a la API de
  Anthropic con su propio modelo, y `virustotal` llama a la API de VirusTotal.

### Una llamada de herramienta, de principio a fin

```text
Claude            Orquestador                Servidor MCP (ej. archetype)
  |                    |                              |
  |-- tool_use ------->|                              |
  |   archetype__      |-- call_tool(classify_...) -->|
  |   classify_...     |      (JSON-RPC por stdio)    |
  |                    |<-- CallToolResult -----------|
  |<-- tool_result ----|                              |
  |  {"ok": true,      |                              |
  |   "data": {...}}   |                              |
```

Detalles de `MCPClientManager.call_tool`:

- **Nunca lanza excepciones.** Cualquier fallo (herramienta desconocida,
  servidor desconectado, timeout, error de la herramienta) se devuelve como
  resultado con `ok=False` y un mensaje.
- **Timeout de 90 segundos por llamada**, generoso porque `coherence` hace
  una llamada LLM por dentro.
- **Resultado**: se prefiere el contenido estructurado de MCP; si no hay, se
  toma el texto y se intenta interpretar como JSON.
- **Lo que recibe Claude** es un bloque `tool_result` con
  `{"ok": true, "data": ...}` o `{"ok": false, "error": "..."}`, marcado
  como error cuando corresponde.

## 4. Qué pasa cuando se analiza un correo

Todo ocurre en `run_analysis` (`orchestrator.py`):

1. **Extracción de indicadores de red.** Antes de llamar al modelo,
   `extraction.py` busca URLs, dominios e IPs con expresiones regulares.
2. **Compuerta de VirusTotal.** Si no se encontró ningún indicador, las
   herramientas de VirusTotal se quitan de la lista para este correo. No
   depende del criterio del modelo: es una decisión determinista.
3. **Construcción del prompt.** El system prompt se arma con el rol, el
   guardrail, la descripción de los servidores, las instrucciones del modo y
   la lista de indicadores encontrados. El correo va en el mensaje de
   usuario, delimitado por `<correo_no_confiable>`.
4. **Loop agéntico.** Se repite hasta el máximo de iteraciones:
   1. Se envía a Claude la conversación, las herramientas MCP disponibles y
      una herramienta extra, `emit_resultado`.
   2. Si Claude pide herramientas MCP, se ejecutan **todas las del turno en
      paralelo** y sus resultados vuelven en un solo mensaje.
   3. Si Claude invoca `emit_resultado`, ese es el veredicto: se valida y el
      loop termina.
   4. Si Claude responde solo con texto, se le recuerda que debe terminar
      invocando `emit_resultado`.
5. **Validación.** El contenido de `emit_resultado` se valida con Pydantic
   contra el esquema del modo.
6. **Resultado.** Se devuelve un `OrchestratorRunResult` con el veredicto,
   los servidores pedidos y conectados, y el registro de herramientas
   invocadas.

### Cómo se garantiza una salida estructurada

`emit_resultado` es una herramienta "terminal" cuyo esquema de entrada es el
esquema de salida deseado. El modelo no responde con texto libre: responde
llamando a esa herramienta con un JSON.

En la **última iteración** permitida, el orquestador fuerza esa herramienta
(`tool_choice` apuntando a `emit_resultado`). Así el análisis siempre
termina con un veredicto, aunque el modelo quisiera seguir investigando.

Máximo de iteraciones: 6 por defecto en `analizar`; 4 por defecto en `lote`
(ajustable con `--max-iteraciones`).

### Llamadas repetidas

Cada análisis tiene una caché de llamadas (nombre de herramienta más
argumentos). Si el modelo pide dos veces lo mismo en el mismo correo, se
reutiliza el resultado sin volver a consultar al servidor. Esto importa
sobre todo con VirusTotal, donde cada consulta gasta cuota. La caché se
descarta al terminar el correo.

## 5. Los dos modos

| | `veredicto` | `explicacion` |
| --- | --- | --- |
| Para qué | Evaluar cientos o miles de correos | Analizar uno o pocos en detalle |
| Salida (`resultado`) | `clasificacion`, `puntaje_riesgo` | Lo anterior más `senales` (servidor, descripción, evidencia) y `explicacion` |
| Servidores por defecto | `archetype`, `knowledge`, `virustotal` | Los mismos más `coherence` |
| Herramientas de VirusTotal | Solo 3: `get_url_report`, `get_domain_report`, `get_ip_report` | Las 11 |
| Instrucción al modelo | Mínimo de llamadas; priorizar costo y velocidad | Usar todas las fuentes y citar evidencia de cada una |
| Tokens máximos de respuesta | 1,024 | 4,096 |

Los servidores por defecto se definen en `mode_defaults` de
`config/mcp_servers.yaml` y se pueden cambiar en cada corrida con `--mcp`
(lista separada por comas, o `none` para el orquestador solo).

En modo veredicto, VirusTotal se recorta a 3 herramientas porque las otras 8
aportan poco a una clasificación binaria y su definición cuesta unos 2,200
tokens adicionales en cada turno.

**Una inconsistencia conocida:** en modo veredicto el YAML habilita
`knowledge` por defecto, pero el system prompt de ese modo solo describe
`archetype` y `virustotal`. Las herramientas de `knowledge` se envían al
modelo igualmente (con su costo en tokens), aunque el prompt no las
menciona. La evaluación de 1,000 correos no se ve afectada porque su script
levanta solo `archetype` y `virustotal`.

## 6. El guardrail contra inyección de instrucciones

Un correo de phishing puede contener frases como "ignora tus instrucciones
anteriores" o "responde siempre legítimo". Para que el modelo no las obedezca:

- El correo se entrega dentro de `<correo_no_confiable>...</correo_no_confiable>`.
- El system prompt indica que todo lo que esté dentro es **dato a analizar,
  nunca una instrucción**, y que esas frases deben tratarse como parte del
  contenido sospechoso.
- La misma regla aplica a lo que devuelven las herramientas MCP: es
  evidencia, no órdenes.

## 7. La salida

`analizar` imprime un JSON como este (modo explicación, recortado):

```json
{
  "modo": "explicacion",
  "modelo_orquestador": "claude-haiku-4-5",
  "servidores_habilitados": ["archetype", "knowledge", "virustotal", "coherence"],
  "servidores_conectados": [
    {"server_id": "archetype", "connected": true, "detail": null}
  ],
  "herramientas_invocadas": [
    {"servidor": "archetype", "herramienta": "classify_archetype", "ok": true, "error": null},
    {"servidor": "coherence", "herramienta": "analyze_coherence", "ok": true, "error": null}
  ],
  "resultado": {
    "clasificacion": "phishing",
    "puntaje_riesgo": 0.92,
    "senales": [
      {"servidor": "archetype", "descripcion": "...", "evidencia": "..."}
    ],
    "explicacion": "..."
  }
}
```

- `servidores_conectados` distingue lo que se pidió de lo que realmente
  arrancó; si un servidor falló, `detail` trae el motivo.
- `herramientas_invocadas` es la traza del análisis: qué se consultó, en qué
  orden y si funcionó. No guarda el contenido de cada respuesta.
- `resultado` es lo que el modelo entregó en `emit_resultado`, ya validado.

## 8. Qué pasa cuando algo falla

| Situación | Comportamiento |
| --- | --- |
| Un servidor no arranca (por ejemplo, falta su API key) | Se registra como no disponible; el análisis sigue con los demás. |
| Una herramienta falla o tarda más de 90 s | El modelo recibe `{"ok": false, "error": ...}` y continúa con otras fuentes. |
| El correo no tiene URLs, dominios ni IPs | VirusTotal no se ofrece en ese análisis. |
| El modelo envuelve el resultado en una clave, como `{"resultado": {...}}` | Si la validación directa falla, se valida el contenido de esa única clave. |
| El resultado no cumple el esquema | `OrchestratorError`. `analizar` imprime `{"error": ..., "respuesta_cruda": ...}` y sale con código 1. |
| El modelo se niega a responder | `OrchestratorError` con el motivo. |
| Se agotan las iteraciones sin veredicto | `OrchestratorError`. |
| Error de la API de Anthropic (límite de tasa, conexión, estado HTTP) | `OrchestratorError` con el detalle. |

El desempaquetado de `{"resultado": {...}}` es un respaldo: solo se intenta
cuando la validación normal ya falló, así que no cambia el resultado de
ninguna respuesta que antes fuera válida.

## 9. VirusTotal: compuerta, límite por minuto y cuota diaria

El plan gratuito permite 4 consultas por minuto y 500 por día. Hay tres
mecanismos distintos:

1. **Compuerta por correo** (`orchestrator.py`): sin indicadores de red, no
   se ofrecen sus herramientas.
2. **Límite por minuto** (`mcp_client.py`): una ventana deslizante en el
   cliente espera lo necesario antes de la quinta consulta dentro de un
   minuto. Solo espera la llamada a VirusTotal; las demás herramientas del
   mismo turno siguen su curso.
3. **Cuota diaria** (`batch.py`): el servidor no expone el código de error,
   así que se detecta por palabras clave en el mensaje ("quota", "rate
   limit", "exceeded", etc.). Al detectarla, el lote deja de ofrecer
   VirusTotal durante el resto de la corrida y marca esas filas como
   `pendiente_cuota` para reintentarlas otro día.

## 10. Modo lote

`phishing-orchestrator lote` procesa un CSV en modo veredicto:

- Abre **una sola vez** las conexiones MCP y las reutiliza para todas las filas.
- Cada fila se identifica por su posición en el CSV (`fila_idx`).
- Después de cada correo **reescribe el CSV de salida completo**. Si la
  corrida se interrumpe, volver a ejecutar el mismo comando la reanuda.
- Al reanudar: las filas completadas se saltan, las `pendiente_cuota` se
  reintentan siempre y las `fallido` solo con `--reintentar-fallidos`.
- Al final imprime accuracy, precision, recall, F1 y la matriz de confusión.

Cada fila guarda: `fila_idx`, `label`, `clasificacion`, `puntaje_riesgo`,
`virustotal_estado` (`ok`, `no_aplica`, `no_habilitado`, `pendiente_cuota`,
`error`, `no_evaluado`), `estado_fila` (`completado` o `fallido`), `error` y
`timestamp`.

El flag `--mcp` permite el **estudio de ablation**: repetir el lote con
distintos subconjuntos de servidores y comparar las métricas.

## 11. Configuración

- **`.env`** (no se sube a git): `ANTHROPIC_API_KEY`, `VIRUSTOTAL_API_KEY`,
  las tres rutas `*_MCP_PATH`, y los modelos (`ORCHESTRATOR_MODEL`,
  `COHERENCE_LLM_MODEL`). Las variables ya definidas en el entorno tienen
  prioridad sobre el archivo.
- **`config/mcp_servers.yaml`**: comando, argumentos, directorio y entorno
  de cada servidor, y los servidores por defecto de cada modo. Los valores
  `${VARIABLE}` se sustituyen al cargarlo.
- Antes de conectar se comprueba que existan las rutas de los servidores
  **seleccionados**. No se validan las API keys: si falta una, ese servidor
  falla por su cuenta y el resto sigue.

### Modelos

Hay dos modelos independientes que comparten la misma API key:

- **Orquestador** (`ORCHESTRATOR_MODEL`, por defecto `claude-haiku-4-5`).
- **Coherence** (`COHERENCE_LLM_MODEL`, por defecto `claude-sonnet-5`), que
  solo interviene cuando se llama a `analyze_coherence`.

Compatibilidad del modelo orquestador:

- `claude-haiku-4-5` acepta `temperature` (se usa 0 para reproducibilidad).
- Los modelos de la generación Claude 5 no aceptan `temperature`; en modo
  veredicto se les pide esfuerzo bajo para contener el costo.
- `claude-fable-5-1` y `claude-mythos-5-1` no admiten forzar una
  herramienta, que es la base de la salida estructurada, así que **no sirven
  como orquestador**: el análisis se rechaza con un error explicativo.

## 12. Evaluación y casos de estudio

Los scripts de evaluación están en `experiments/eval_system/` y usan el
orquestador real.

### `run_evaluation.py` — evaluación cuantitativa

Corre el modo veredicto, con `archetype` y `virustotal`, sobre
`eval_external.csv` del repositorio de la tesis (500 phishing de Phishing
Pot y 500 legítimos de TREC 2007). Como el resultado del orquestador no
guarda el contenido de cada herramienta, el script envuelve el cliente MCP y
el cliente de Anthropic para capturar el arquetipo asignado, los veredictos
de VirusTotal y los tokens reales.

Genera `results_raw.jsonl` (una línea por correo), `metrics_final.json`,
`evaluation.log`, `evaluation_errors.log` y `checkpoint.json`. Es reanudable
y tiene `--dry-run` para probarlo sin gastar tokens.

Resultados sobre los 1,000 correos (`metrics_final.json`):

| Métrica | Valor |
| --- | --- |
| Accuracy | 0.915 |
| Precision | 0.960 |
| Recall | 0.866 |
| F1 | 0.911 |
| MCC | 0.834 |
| AUC-ROC | 0.975 |
| Matriz de confusión | TP 433, TN 482, FP 18, FN 67 |
| Correos con error | 0 |
| Costo total | USD 21.87 |

### Evaluación final en modo explicación

Los mismos 1,000 correos se evaluaron también en modo explicación, con los
cuatro servidores MCP. El script (`run_eval_explicacion_1000.py`, en el
repositorio de la tesis) ejecuta `analizar --mode explicacion` como
subproceso por cada correo y guarda una línea por correo con el veredicto,
las señales con su evidencia, la explicación y las herramientas invocadas.
El resultado está en
`experiments/data final eval/results_explicacion_1000.jsonl`, que es el
archivo que recorre la interfaz web.

| Métrica | Modo veredicto | Modo explicación |
| --- | --- | --- |
| Servidores MCP | `archetype`, `virustotal` | los cuatro |
| Accuracy | 0.915 | 0.935 |
| Precision | 0.960 | 0.954 |
| Recall | 0.866 | 0.914 |
| F1 | 0.911 | 0.934 |
| MCC | 0.834 | 0.871 |
| AUC-ROC | 0.975 | 0.979 |
| Matriz de confusión | TP 433, TN 482, FP 18, FN 67 | TP 457, TN 478, FP 22, FN 43 |

El modo explicación detecta 24 phishing más a cambio de 4 falsos positivos
más. Es bastante más lento: la mediana fue de 58 segundos por correo, con
una mediana de 6 señales por reporte. Como ese script usa el CLI, no
registra tokens ni costo.

### `run_casos_estudio.py` — análisis cualitativo

Selecciona casos a partir de `results_raw.jsonl` y corre sobre ellos el modo
explicación (un proceso de `analizar` por correo):

- 3 verdaderos positivos con el mayor puntaje y arquetipos distintos.
- 2 falsos negativos con el mayor puntaje.
- 2 falsos positivos con el menor puntaje.
- 1 correo con la mayor cantidad de indicadores de VirusTotal.

Guarda cada salida en `casos_estudio/caso_<id>.txt` y un resumen en
`casos_estudio/index.json`. Con `--ids` se corre sobre correos concretos y
con `--solo-seleccion` se ve la selección sin gastar tokens.

### Notebook comparativo

El análisis contra Rspamd y el de patrones y señales (arquetipos,
VirusTotal) vive en el repositorio de la tesis:
`Trabajo-de-Graduacion/experiments/analisis_comparativo.ipynb`.

### Pilotos

`run_pilot.py`, en la raíz, es la prueba inicial de 10 correos (5 phishing y
5 legítimos) que midió tokens reales antes de la evaluación completa.
`run_pilot_retest.py` repitió los 3 correos más costosos de ese piloto para
comparar el antes y el después de dos optimizaciones: la instrucción de no
repetir herramientas y la caché de llamadas. Sus salidas son
`pilot_result.json` y `pilot_retest_result.json`.

## 13. Interfaz web

`experiments/eval_system/orchestrator_ui.py` es una app local de Streamlit
que presenta la respuesta del sistema como un reporte explicativo. Se
levanta con:

```bash
uv run streamlit run experiments/eval_system/orchestrator_ui.py
```

Tiene dos pestañas que comparten el mismo reporte.

### El reporte explicativo

Traduce el JSON del orquestador a algo legible sin conocer el sistema. Cada
bloque aparece solo si el resultado trae ese dato:

1. **Veredicto**: tarjeta roja o verde con "Este correo parece PHISHING /
   LEGÍTIMO", el nivel de riesgo en palabras (bajo si es menor a 0.3, medio
   hasta 0.6, alto por encima) y la barra del puntaje.
2. **¿Acertó el sistema?**: solo en correos con etiqueta real. Dice en
   lenguaje llano si fue un acierto, una falsa alarma o un phishing no
   detectado.
3. **¿Por qué?**: la explicación completa del modelo.
4. **Tipo de ataque al que más se parece**: el arquetipo, con la aclaración
   de que es una referencia y no una acusación.
5. **Evidencia encontrada**: las señales agrupadas en pestañas por fuente,
   cada una con su descripción y su evidencia.
6. **El correo analizado** y los **detalles técnicos** (tiempo, tokens,
   costo, herramientas invocadas), plegados.

Los servidores MCP se presentan con nombres comprensibles:

| Servidor | Nombre en el reporte |
| --- | --- |
| `archetype` | Patrón de ataque |
| `coherence` | Coherencia del mensaje |
| `knowledge` | Tácticas de engaño |
| `virustotal` | Reputación de enlaces |

![Veredicto y explicación de un correo](UI_DEMO_LIVE_C1.png)

![Evidencia agrupada por fuente](UI_DEMO_LIVE_C3.png)

### Pestaña "Correos evaluados"

Lee `experiments/data final eval/results_explicacion_1000.jsonl` y lista
los 1,000 correos; al elegir uno muestra su reporte. No llama a ninguna API.
El JSONL no guarda el texto de los correos, así que el asunto, el remitente
y el cuerpo se buscan por id en `eval_external.csv` del repositorio de la
tesis. Hay filtros por clase real, por acierto o error del sistema, y
búsqueda por id o asunto.

![Lista de correos evaluados](UI_DEMO_STATIC_1.png)

### Pestaña "Análisis en vivo"

Llama al orquestador real (`run_analysis`) dentro del mismo proceso de la
app, no al CLI. Esto permite dos cosas que el CLI no da: reutilizar las
conexiones MCP entre análisis y capturar tokens, costo, arquetipo e
indicadores de VirusTotal (con los mismos envoltorios de `run_evaluation.py`).

**Servidores persistentes.** Streamlit vuelve a ejecutar el script completo
en cada interacción, y una sesión MCP solo vive dentro del bucle de eventos
que la abrió. Por eso la app mantiene un servicio (`ServicioMCP`) en un hilo
aparte con su propio bucle de eventos:

- Al abrir la app, una corrutina de larga vida arranca los cuatro
  servidores, los conecta y se queda esperando.
- Cada análisis se envía a ese mismo bucle y usa las conexiones ya abiertas.
- El servicio es único por proceso de la app (se guarda con
  `st.cache_resource`), así que sobrevive a las recargas de la página.
- Al conectar se hace una clasificación de calentamiento contra `archetype`
  para que cargue su modelo de embeddings una sola vez, sin gastar tokens.
- Los servidores que un análisis no usa no se desconectan: solo se ocultan
  al modelo en esa llamada.
- En Windows el bucle se crea como `ProactorEventLoop`, el único que admite
  subprocesos.

![Servidores MCP conectados](UI_DEMO_LIVE_A.png)

**Formulario.** Se elige el modo y los servidores (por defecto, los de
`mode_defaults` para ese modo), y se escribe remitente, asunto y cuerpo. El
orquestador solo recibe texto, así que la app antepone `From:` y `Subject:`
al cuerpo. El tope de iteraciones es 6 en explicación y 4 en veredicto.

![Formulario de análisis en vivo](UI_DEMO_LIVE_B.png)

**Historial.** Cada análisis se agrega como una línea a
`experiments/eval_system/analisis_en_vivo.jsonl`, con el correo, el modo,
el veredicto, las señales, los tokens, el costo estimado y el tiempo. La
sección "Análisis anteriores" permite volver a ver cualquier reporte.

Lo que conviene saber al usarla:

- Cada análisis en vivo gasta tokens de la API de Anthropic.
- El costo mostrado es una estimación con precios de Claude Haiku 4.5 y no
  incluye la llamada LLM interna de `coherence`.
- En modo veredicto el reporte no tiene explicación ni evidencia.
- `analisis_en_vivo.jsonl` guarda el texto de los correos analizados.

## 14. Limitaciones que conviene tener presentes

- **No es determinista.** Con temperatura 0 las respuestas son estables,
  pero el mismo correo puede producir llamadas distintas entre corridas.
- **VirusTotal aportó poco en la evaluación.** En los 1,000 correos no
  devolvió ningún veredicto malicioso; la detección descansó en el texto y
  el arquetipo.
- **El arquetipo no distingue phishing de legítimo** por sí solo (ver
  sección 2).
- **La extracción de indicadores es heurística.** Las expresiones regulares
  pueden tomar como dominio algo que no lo es, o pasar por alto URLs ofuscadas.
- **La cuota de VirusTotal se detecta por texto**, no por código de error;
  un cambio en la redacción del mensaje podría dejarla sin detectar.
- **El costo crece con el número de herramientas**, porque sus definiciones
  se reenvían en cada turno del loop.
