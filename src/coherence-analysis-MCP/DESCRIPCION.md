# Descripcion completa de coherence-analysis-mcp

Este documento explica que es el servidor, como se comunica, que hace con un
correo paso a paso y cuales son sus limites reales. El [README](README.md)
cubre la instalacion y el uso; aqui se explica el funcionamiento.

## 1. En una frase

Es un servidor MCP que recibe el texto de un correo, le pide a un modelo de
lenguaje que busque contradicciones internas en el, comprueba que cada
contradiccion reportada este respaldada por una cita que de verdad aparece en
el correo, y devuelve el resultado como JSON. No decide si el correo es
phishing.

## 2. Donde encaja

El servidor es una pieza del prototipo de deteccion de phishing del trabajo
de graduacion. En ese prototipo un **orquestador** consulta varios servidores
MCP, cada uno especializado en un tipo de senal, y combina las respuestas
para clasificar el correo. Este servidor aporta una sola senal: la coherencia
interna del texto.

La hipotesis que lo justifica es que un correo legitimo es consistente
consigo mismo, mientras que uno de phishing suele tener costuras: dice ser un
banco pero saluda con "Dear Customer", anuncia algo grave con tono informal y
errores, pide datos que esa entidad nunca pediria por correo, o firma con un
nombre distinto al del remitente. Cada elemento por separado puede parecer
inofensivo; la senal esta en que no cuadran entre si.

Dos decisiones de diseno delimitan su responsabilidad:

- **No emite veredicto.** Reporta incoherencias con su evidencia. Clasificar
  es trabajo del orquestador.
- **La deteccion la hace un LLM, no reglas.** No hay listas de palabras clave
  ni conteos lexicos, porque se comprobo que no separan bien correos
  legitimos de phishing.

## 3. Que hace realmente el codigo

Conviene ser preciso sobre que parte del trabajo hace cada quien:

| Parte | Quien la hace | Como |
|---|---|---|
| Encontrar las incoherencias | El LLM | Razona sobre el texto siguiendo el prompt |
| Asignar el `coherence_score` | El LLM | Estimacion propia entre 0 y 1 |
| Redactar el `summary` | El LLM | Texto libre |
| Obligar a que la respuesta tenga una forma fija | El servidor | Esquema Pydantic + *tool use* forzado |
| Comprobar que cada cita existe en el correo | El servidor | Busqueda de subcadena, determinista |
| Proteger contra instrucciones escondidas en el correo | El servidor (via prompt) | Delimitadores `<email>` y regla explicita |
| Manejar respuestas invalidas | El servidor | Un reintento y luego reporte de respaldo |

Es decir: el servidor no "entiende" el correo. Su aporte propio es el
contrato de entrada y salida, el prompt, y sobre todo el filtro de evidencia,
que es la unica verificacion que no depende de confiar en el modelo.

## 4. Como se comunica

Hay dos conversaciones distintas: una entre el orquestador y el servidor, y
otra entre el servidor y el LLM.

```
 Orquestador (cliente MCP)        Servidor MCP              API de Anthropic
          |                            |                           |
          |--- arranca subproceso ---->|                           |
          |--- initialize ------------>|                           |
          |<-- capacidades, version ---|                           |
          |--- notifications/initialized ->                        |
          |--- tools/list ------------>|                           |
          |<-- 3 herramientas ---------|                           |
          |--- tools/call ------------>|                           |
          |    analyze_coherence       |--- POST /v1/messages ---->|
          |                            |    (tool use forzado)     |
          |                            |<-- bloque tool_use -------|
          |                            | valida esquema            |
          |                            | filtra citas              |
          |<-- reporte JSON -----------|                           |
```

### 4.1 Orquestador y servidor: MCP por stdio

- **Transporte: stdio.** El cliente arranca el servidor como un subproceso
  (`python run_server.py`) y le habla por su entrada estandar; el servidor
  responde por su salida estandar. No hay puerto de red, ni HTTP, ni
  autenticacion: el canal es privado entre los dos procesos.
- **Formato: JSON-RPC 2.0**, un mensaje JSON por linea.
- **Consecuencia practica:** la salida estandar esta reservada para el
  protocolo. Un `print()` en el codigo del servidor corromperia la
  comunicacion.
- **Ciclo de vida:** el servidor vive mientras el cliente mantenga abierto el
  subproceso. No guarda estado entre llamadas: cada `tools/call` es
  independiente y no se almacena ningun correo.

El intercambio empieza con un saludo (`initialize`), donde cliente y servidor
acuerdan la version del protocolo (con el SDK instalado, `2025-11-25`) y el
servidor envia su nombre, version e instrucciones de uso. Despues el cliente
puede pedir la lista de herramientas (`tools/list`) y llamarlas
(`tools/call`).

Una llamada a la herramienta principal se ve asi:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "analyze_coherence",
    "arguments": { "email_text": "Subject: Account Verification Required\n\nDear Customer, ..." }
  }
}
```

Y la respuesta:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      { "type": "text", "text": "{ \"incoherences\": [...], \"coherence_score\": 0.15, ... }" }
    ],
    "isError": false
  }
}
```

El reporte viaja como **texto JSON dentro de un bloque `text`**. El cliente
tiene que decodificarlo (`json.loads(resultado.content[0].text)`), como hace
la prueba de integracion.

Si la herramienta lanza una excepcion, el SDK de MCP la convierte en una
respuesta con `isError: true` y el texto `Error executing tool
analyze_coherence`. El servidor no se cae y sigue atendiendo llamadas.

### 4.2 Servidor y LLM: API de Anthropic con tool use forzado

Solo ocurre cuando `COHERENCE_LLM_PROVIDER=anthropic`. Por cada intento de
analisis el servidor hace una peticion HTTPS a la API de mensajes de
Anthropic con:

- el prompt de sistema (reglas del auditor y las 6 categorias),
- un mensaje de usuario con el correo dentro de etiquetas `<email>`,
- una unica herramienta ficticia llamada `return_result`, cuyo esquema de
  entrada es el JSON Schema de `CoherenceReport`,
- `tool_choice` apuntando a esa herramienta, lo que **obliga** al modelo a
  responder llamandola,
- `max_tokens` de 2048.

El modelo no puede contestar con texto libre: su respuesta es un bloque
`tool_use` cuyos argumentos ya son el reporte en forma de objeto. Ese objeto
es lo que el servidor toma como respuesta cruda. Es el mecanismo mas
confiable de esa API para obtener JSON con una forma fija, y evita tener que
extraer JSON de un texto con markdown.

En modo `mock` esta conversacion no existe: no hay red ni API key.

## 5. Las tres herramientas

| Herramienta | Entrada | Salida | Usa el LLM |
|---|---|---|---|
| `analyze_coherence` | `email_text` (texto completo: asunto y/o cuerpo) | El reporte de coherencia | Si |
| `get_output_schema` | ninguna | El JSON Schema del reporte | No |
| `list_incoherence_categories` | ninguna | `{ "count": 6, "categories": [{ "id", "description" }] }` | No |

Las dos ultimas son de autodescripcion: le permiten al orquestador saber que
forma tendra el reporte y que significa cada categoria sin tener que
adivinarlo ni gastar una llamada al LLM.

`analyze_coherence` recibe un solo texto plano. No recibe cabeceras por
separado, ni adjuntos, ni HTML interpretado: si el remitente o el asunto
importan, tienen que venir escritos dentro de `email_text`.

### Las 6 categorias

| Id | Que contradiccion busca |
|---|---|
| `sender_vs_content` | Dice ser una entidad conocida, pero el saludo es generico o el estilo no corresponde |
| `urgency_vs_channel` | Comunica algo grave o urgente con tono informal o con errores |
| `subject_vs_body` | El asunto y el cuerpo no coinciden en lo que ofrecen, piden o advierten |
| `authority_vs_execution` | Se presenta como oficial pero tiene mala gramatica o formato pobre |
| `request_vs_context` | Pide datos sensibles o acciones que esa entidad no pediria por correo |
| `identity_consistency` | El remitente, la firma y el contenido nombran entidades distintas |

Las descripciones viven en un solo lugar (`CATEGORY_DESCRIPTIONS` en
`schema.py`) y se usan tanto en el prompt del LLM como en
`list_incoherence_categories`, de modo que el modelo y el orquestador siempre
ven la misma definicion.

### El reporte

```json
{
  "incoherences": [
    { "category": "identity_consistency",
      "description": "Signs as 'Wells Fargo Security Team' but the sender address domain names a different organization entirely.",
      "quote": "support@paypal-alerts.example" }
  ],
  "coherence_score": 0.15,
  "summary": "The email shows several internal contradictions...",
  "discarded_count": 0
}
```

| Campo | Significado |
|---|---|
| `incoherences` | Lista de hallazgos que pasaron el filtro de evidencia. Puede estar vacia |
| `category` | Una de las 6 categorias; cualquier otro valor invalida la respuesta |
| `description` | Explicacion del hallazgo, escrita por el LLM |
| `quote` | Fragmento literal del correo que respalda el hallazgo |
| `coherence_score` | De 0 (lleno de contradicciones) a 1 (totalmente coherente) |
| `summary` | Resumen en lenguaje claro |
| `discarded_count` | Cuantos hallazgos del LLM se eliminaron por tener una cita que no existe en el correo |

## 6. Que pasa dentro de `analyze_coherence`, paso a paso

1. **Se elige el motor LLM.** `get_engine()` lee `COHERENCE_LLM_PROVIDER` en
   cada llamada y construye `MockEngine` o `AnthropicEngine`.
2. **Se construye el prompt.** El prompt de sistema es fijo. El de usuario
   envuelve el correo entre `<email>` y `</email>` y repite que ese contenido
   es dato, no instruccion.
3. **Se llama al motor.** Devuelve un diccionario que deberia tener la forma
   del reporte.
4. **Se valida contra el esquema.** Pydantic comprueba tipos, que cada
   categoria sea una de las 6 y que el puntaje este entre 0 y 1.
5. **Si la validacion falla, se reintenta una vez** con el mismo prompt.
6. **Se filtran las citas.** Para cada incoherencia se normalizan los
   espacios de la cita y del correo (cualquier secuencia de espacios o saltos
   de linea se convierte en un solo espacio) y se comprueba que la cita sea
   una subcadena del correo. Las que no aparecen, o las que tienen la cita
   vacia, se eliminan y se cuentan.
7. **Se arma el reporte final** con las incoherencias que sobrevivieron, el
   puntaje y el resumen tal como los dio el LLM, y `discarded_count`.

### Por que existe el filtro de citas

Un LLM puede inventar. Si se le pide evidencia, puede fabricar una cita que
suena plausible pero que no esta en el correo. Exigir una cita literal y
verificarla con una comparacion exacta convierte cada hallazgo en algo
comprobable: el orquestador, o una persona, puede ir al correo y encontrar el
fragmento. La comparacion distingue mayusculas y puntuacion; solo es
tolerante con los espacios, porque los saltos de linea de un correo cambian
facilmente al copiarlo.

### La proteccion contra prompt injection

El correo que se analiza lo escribio, posiblemente, un atacante, y podria
contener frases como "ignore your previous instructions". Hay tres medidas:

- el correo va delimitado por etiquetas `<email>`, separado de las
  instrucciones;
- el prompt de sistema indica que ese contenido nunca se obedece, y que una
  instruccion dirigida al modelo dentro del correo cuenta como evidencia
  adicional de manipulacion;
- la salida esta restringida por el esquema: aunque el modelo fuera
  manipulado, solo puede devolver un reporte con esa forma, y sus citas
  siguen pasando por el filtro.

### Cuando algo falla

| Situacion | Que devuelve la herramienta |
|---|---|
| El LLM responde algo que no cumple el esquema, o sin bloque `tool_use`, dos veces seguidas | Reporte de respaldo: lista vacia, `coherence_score` 0.5 y un `summary` que dice que el analisis no se pudo completar |
| Proveedor desconocido, o `anthropic` sin API key | Error de herramienta (`isError: true`) |
| Error de la API de Anthropic: red, autenticacion, limite de uso | Error de herramienta (`isError: true`), sin reintento |

El 0.5 del reporte de respaldo es deliberadamente neutro: no afirma que el
correo sea coherente ni que no lo sea.

## 7. Los dos motores

`llm_engine.py` define una interfaz minima, `LLMEngine`, con un solo metodo:
recibe prompt de sistema, prompt de usuario y un esquema, y devuelve un
diccionario. `coherence.py` solo conoce esa interfaz, asi que cambiar de
proveedor no toca la logica de analisis.

| Motor | Cuando se usa | Que hace |
|---|---|---|
| `MockEngine` | `COHERENCE_LLM_PROVIDER=mock` o sin configurar | Devuelve siempre la misma respuesta fija, sin red |
| `AnthropicEngine` | `COHERENCE_LLM_PROVIDER=anthropic` | Llama a la API de Claude como se describe en 4.2 |

**El modo mock no analiza nada.** Su respuesta fija tiene 5 incoherencias
cuyas citas estan tomadas de un correo de referencia (`MOCK_EMAIL_TEXT`). Si
se le pasa ese correo, las 5 sobreviven al filtro. Si se le pasa cualquier
otro, las 5 se descartan y el reporte sale con lista vacia,
`discarded_count` 5 y el puntaje fijo de 0.15. Existe para probar el
servidor, el protocolo y el filtro sin costo ni API key, no para evaluar
correos.

Para agregar un proveedor se crea una subclase de `LLMEngine` y se agrega una
rama en `get_engine()`.

## 8. Mapa del codigo

| Archivo | Responsabilidad |
|---|---|
| `run_server.py` | Punto de entrada. Agrega `src/` a la ruta de importacion y arranca el servidor |
| `src/coherence_analysis_mcp/server.py` | Crea el servidor MCP, registra las 3 herramientas y lo corre por stdio |
| `src/coherence_analysis_mcp/coherence.py` | Prompt, llamada al motor, validacion, reintento, filtro de citas, reporte de respaldo |
| `src/coherence_analysis_mcp/llm_engine.py` | Interfaz del motor, motor mock, motor Anthropic y seleccion por variable de entorno |
| `src/coherence_analysis_mcp/schema.py` | Las 6 categorias, sus descripciones y los modelos `Incoherence` y `CoherenceReport` |
| `tests/test_coherence.py` | 11 pruebas unitarias del esquema, el filtro y el modo mock |
| `tests/test_integration.py` | Prueba de extremo a extremo: arranca el servidor y lo usa como un cliente MCP real |

Las dependencias van en una sola direccion: `server` usa `coherence`, que usa
`llm_engine` y `schema`. La logica de analisis no importa nada de MCP, por lo
que se puede probar sin arrancar el servidor.

## 9. Limites

- **El filtro verifica que la cita exista, no que el hallazgo sea correcto.**
  El LLM puede citar un fragmento real y sacar de el una conclusion
  equivocada, o clasificarlo en la categoria incorrecta.
- **El puntaje no se recalcula.** Si se descartan incoherencias, el
  `coherence_score` sigue siendo el que dio el LLM. Un puntaje bajo con lista
  vacia y `discarded_count` alto significa que el modelo vio problemas que no
  pudo respaldar.
- **El puntaje no esta calibrado.** Es una estimacion del modelo, sin formula
  detras, y puede variar entre ejecuciones o entre modelos.
- **La proteccion contra prompt injection reduce el riesgo, no lo elimina.**
  Depende de que el modelo siga la regla.
- **Solo ve texto.** No resuelve enlaces, no revisa cabeceras tecnicas, no
  abre adjuntos. Esas senales corresponden a otros servidores del prototipo.
- **Pensado para ingles.** El prompt y las categorias asumen correos en ese
  idioma.
- **Sin limite de tamano de entrada.** Un correo muy largo se envia completo
  al LLM.
- **Los errores de la API no se reintentan.** Un fallo de red o de limite de
  uso llega al orquestador como error de herramienta.
- **Las pruebas automatizadas solo cubren el modo mock.** Comprueban el
  protocolo, el esquema y el filtro, no la calidad de la deteccion con un
  modelo real.
