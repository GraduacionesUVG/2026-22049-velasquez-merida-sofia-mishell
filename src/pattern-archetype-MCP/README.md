# Pattern Analysis MCP

Servidor MCP de analisis de patrones y arquetipos de phishing. Componente del
prototipo de deteccion de phishing con modelos de lenguaje grandes y servidores
MCP (trabajo de graduacion, Universidad del Valle de Guatemala).

Este README es la guia rapida de instalacion y uso. La descripcion completa del
componente (protocolo de comunicacion, construccion de los arquetipos, seleccion
de k, detalle de los 15 arquetipos, interpretacion de la similitud y
limitaciones) esta en [DOCUMENTACION.md](DOCUMENTACION.md).

## Que es

Este proyecto construye **arquetipos de ataque** (grupos de correos de phishing
semanticamente similares, agrupados solo entre si) a partir del corpus de
construccion, y expone esos arquetipos como herramientas consultables por un
orquestador mediante un servidor MCP.

Dado un correo nuevo, el servidor indica a que patron de ataque se parece mas,
junto con la emocion que ese patron explota (urgencia, miedo, confianza, codicia,
curiosidad) y la tactica de ingenieria social que usa (autoridad, escasez,
reciprocidad, prueba social, simpatia). Esto le da al orquestador una forma de
"memoria del corpus" que un LLM por si solo no tiene: no es una clasificacion
directa del correo, sino una senal estadistica basada en similitud con patrones
de ataque ya observados.

Punto central de diseno: **el servidor no emite un veredicto de phishing.** Solo
reporta a que arquetipo de ataque se parece el correo. Como los arquetipos se
construyen unicamente con correos de phishing, una similitud alta senala parecido
a un ataque conocido, pero una similitud baja no prueba que el correo sea
legitimo (el store no conoce ningun patron de correo legitimo). La decision final
de clasificacion pertenece al orquestador.

## Flujo del proyecto (dos partes)

Este proyecto se construye y se usa en dos partes secuenciales:

**Parte 1 - Construccion de arquetipos (notebook).** Se generan embeddings de los
correos de phishing (`label == 1`) del corpus de construccion
(`data/corpus_construccion.csv`) con un modelo
local de `sentence-transformers`, se agrupan con KMeans y se guardan los
arquetipos resultantes (`artifacts/archetypes.json` y
`artifacts/kmeans_archetypes.pkl`). Esto se hace una vez (o cada vez que se
quiera reconstruir los arquetipos con un corpus o parametros distintos).

**Parte 2 - Servidor MCP.** El servidor carga los arquetipos ya construidos y los
expone como herramientas MCP por stdio. Esto es lo que se conecta al orquestador.

## Estructura del proyecto

```
pattern-archetype-MCP/
├── data/
│   └── corpus_construccion.csv    Corpus de construccion (no se versiona, ver .gitignore)
├── figures/                        Graficas generadas por el notebook (PNG)
│   ├── codo_inertia.png           Corrida actual (k=5-20)
│   ├── silhouette_por_k.png       Corrida actual (k=5-20)
│   └── diagnostico_k5_20/         Diagnostico del corpus anterior (train.csv), historico
├── artifacts/
│   ├── archetypes.json            Perfil de cada arquetipo (SI se versiona)
│   ├── kmeans_archetypes.pkl      Modelo KMeans entrenado (SI se versiona)
│   └── embeddings_phishing_full.npy   Cache de embeddings (no se versiona)
├── notebooks/
│   └── 01_construccion_arquetipos.ipynb   Parte 1: construccion de arquetipos
├── src/pattern_analysis_mcp/
│   ├── __init__.py                Expone main() importandola desde server
│   ├── server.py                  Servidor MCP y definicion de las 3 herramientas
│   └── archetypes.py              Capa de acceso a los arquetipos (logica de clasificacion)
├── tests/
│   ├── test_archetypes.py         Pruebas unitarias de la logica de clasificacion
│   └── test_integration.py        Prueba end-to-end (cliente MCP real por stdio)
├── run_server.py                  Punto de entrada recomendado para arrancar el servidor
├── pyproject.toml
├── README.md
└── DOCUMENTACION.md               Descripcion completa del componente
```

## Parte 1: construir los arquetipos

### Requisitos

- Python 3.10 o superior.
- `data/corpus_construccion.csv` (corpus Al-Subaiey completo, ya preprocesado)
  con al menos las columnas `text_clean` (texto del correo, en ingles) y `label`
  (1 = phishing, 0 = legitimo). Solo se usan las filas con `label == 1` para
  construir los arquetipos de ataque.

### Instalacion

Con `uv` (recomendado):

```bash
uv sync
```

Con pip en modo editable:

```bash
pip install -e ".[dev]"
```

### Correr el notebook

```bash
uv run jupyter notebook notebooks/01_construccion_arquetipos.ipynb
```

Correr las celdas en orden. La primera corrida genera los embeddings localmente
con `sentence-transformers` (modelo `all-MiniLM-L6-v2`, puede tardar varios
minutos sobre los ~38 mil correos de phishing) y los guarda en
`artifacts/embeddings_phishing_full.npy`; las corridas siguientes reutilizan ese
cache automaticamente (si cambia el corpus hay que borrar ese archivo antes de
correr el notebook). Al final, el notebook guarda los arquetipos en
`artifacts/archetypes.json` y `artifacts/kmeans_archetypes.pkl`.

### Resultado obtenido con el corpus actual

38,066 correos de phishing (de los 77,267 correos de
`data/corpus_construccion.csv`), **k = 15** arquetipos, seleccionado por
Silhouette Score (metrica coseno, calculado sobre el corpus completo sin
submuestreo) dentro de un rango explorado de 5 a 20; ver
`figures/codo_inertia.png` y `figures/silhouette_por_k.png`.

El Silhouette Score sube de forma sostenida de k=5 (0.1256) a k=13 (0.1816), cae
en k=14 (0.1668), alcanza su maximo en **k=15 (0.1886)** y despues se mantiene
entre 0.175 y 0.183 sin volver a superarlo. La inertia baja de forma suave en
todo el rango, sin un codo marcado, por lo que el criterio de seleccion fue el
Silhouette Score. La ventaja de k=15 es pequena (0.005 sobre k=16) y el valor es
bajo en terminos absolutos: los patrones de ataque se traslapan.

| Id | Arquetipo | Correos | Emocion | Tactica |
|---:|---|---:|---|---|
| 0 | Spam farmaceutico y de pastillas para adelgazar con frases concatenadas | 2,726 | codicia | escasez |
| 1 | Spam de atraccion y mejora sexual masculina | 4,496 | curiosidad | autoridad |
| 2 | Spam de acciones bursatiles "pump and dump" | 1,567 | codicia | autoridad |
| 3 | Esquema de dinero facil y ganancias garantizadas | 2,883 | codicia | escasez |
| 4 | Farmacia en linea no autorizada | 5,459 | codicia | escasez |
| 5 | Venta de relojes de imitacion (replica Rolex) | 2,776 | codicia | autoridad |
| 6 | Suplantacion de boletin de noticias (alertas CNN falsas) | 1,407 | confianza | autoridad |
| 7 | Spam de aumento de tamano masculino con garantia de resultados | 2,886 | codicia | prueba social |
| 8 | Spam ofuscado de agrandamiento masculino con pseudo-respaldo medico | 1,838 | confianza | autoridad |
| 9 | Spam ofuscado de medicamentos genericos | 2,632 | codicia | escasez |
| 10 | Spam de hipotecas y prestamos preaprobados | 916 | codicia | escasez |
| 11 | Fraude de anticipo / transferencia de fondos (estafa 419) | 3,791 | urgencia | autoridad |
| 12 | Venta de software pirata a precio muy bajo | 1,523 | codicia | escasez |
| 13 | Phishing de verificacion y suspension de cuenta | 2,171 | miedo | escasez |
| 14 | Spam de bienestar generico con tono amistoso | 995 | confianza | simpatia |

Ver `artifacts/archetypes.json` para el detalle de cada uno (label completo,
top_phrases, representative_examples) y [DOCUMENTACION.md](DOCUMENTACION.md)
para la tabla completa de Silhouette por k y el analisis de los clusters.

**Historial.** La primera version agrupaba el corpus mixto (phishing y
legitimo) con UMAP + HDBSCAN y reportaba la pureza de cada arquetipo (43
arquetipos). La segunda paso a KMeans solo sobre phishing con `data/train.csv`
(26,646 correos) y dio k = 16. La actual repite ese mismo procedimiento sobre
`data/corpus_construccion.csv` y da k = 15. Los archivos de
`figures/diagnostico_k5_20/` corresponden al corpus anterior (`train.csv`, por
eso muestran el maximo en k=16): se conservan como registro del diagnostico que
llevo a ampliar el rango de k de 5-10 a 5-20, y no describen los arquetipos
actuales.

### Decisiones de diseno

- **Solo se agrupan los correos de phishing.** El corpus de construccion tiene
  correos legitimos y de phishing, pero los arquetipos se construyen unicamente
  con los de `label == 1`. El objetivo no es separar phishing de legitimo por
  clustering (para eso esta el clasificador principal del prototipo), sino
  caracterizar los **patrones de ataque** dentro del phishing mismo: que emocion
  explotan y que tactica de ingenieria social usan. Por eso no hay una nocion de
  "pureza" o "composicion de clases" por arquetipo como en versiones anteriores
  de este notebook: el corpus de origen es de una sola clase.
- **Embeddings locales, no APIs externas.** Se usa `sentence-transformers` con el
  modelo `all-MiniLM-L6-v2` en vez de una API externa de embeddings. La razon es
  reproducibilidad: el mismo modelo con la misma semilla (`SEMILLA = 42`) produce
  siempre los mismos resultados, sin depender de cuotas, conectividad o cambios de
  version de un servicio de terceros.
- **Los embeddings se normalizan a norma L2 = 1** directamente al generarlos, para
  que la similitud coseno se calcule como un simple producto punto al reportar
  que tan similar es un correo nuevo al centroide de su arquetipo.
- **KMeans, no HDBSCAN.** A diferencia de versiones anteriores de este proyecto
  (que usaban HDBSCAN sobre una reduccion UMAP para poder marcar "ruido" en un
  corpus con clases mezcladas), aqui se usa KMeans directamente sobre los 384
  embeddings originales. Al ser un corpus de una sola clase (solo phishing) no
  hace falta un algoritmo que descarte puntos como ruido: cada correo de phishing
  pertenece a algun patron de ataque, aunque sea debil. El numero de clusters `k`
  se elige explorando un rango amplio (5 a 20) combinando el metodo del codo
  (inertia) y el Silhouette Score calculado sobre el corpus completo; se
  selecciona el `k` que maximiza el Silhouette Score en ese rango.
- **Las etiquetas semanticas (label, dominant_emotion, social_engineering_tactic)
  son un juicio del analista, no un calculo automatico.** Se asignan inspeccionando
  los `top_phrases` (TF-IDF) y los correos representativos de cada cluster; no
  existe una formula que derive "codicia" o "autoridad" de un vector de embeddings.
  Si se reconstruyen los arquetipos con otro corpus o k distinto, estas etiquetas
  deben revisarse a mano contra el contenido real de los nuevos clusters.

## Parte 2: el servidor MCP

### Herramientas expuestas

| Herramienta | Que hace |
|---|---|
| `classify_archetype` | Dado el texto de un correo, encuentra el arquetipo de ataque mas cercano (cluster KMeans) y devuelve su id, similitud coseno, label, emocion dominante, tactica de ingenieria social y top_phrases |
| `list_archetypes` | Lista todos los arquetipos con su perfil resumido (label, tamano, emocion dominante, tactica, terminos caracteristicos) |
| `get_archetype` | Detalle completo de un arquetipo por id, incluyendo 3 correos representativos mas cercanos al centroide |

`classify_archetype` incluye en su respuesta un campo `caveat` que deja claro
que el resultado es una **senal estadistica de similitud contra patrones de
ataque conocidos**, no un veredicto de phishing; lo mismo indican las
instrucciones que el servidor entrega al cliente en el handshake. Como el store
solo conoce phishing, una similitud baja no prueba que el correo sea legitimo, y
`classify_archetype` siempre devuelve algun arquetipo (no hay umbral). La
decision final es del orquestador.

El servidor se comunica por **stdio** con mensajes JSON-RPC 2.0 (protocolo MCP):
el cliente lo arranca como subproceso, escribe en su `stdin` y lee de su
`stdout`. El detalle del protocolo, el formato de cada respuesta y como
interpretar el valor de `similarity` por arquetipo estan en
[DOCUMENTACION.md](DOCUMENTACION.md).

### Como probarlo

**1. Pruebas unitarias** (rapidas, sin arrancar el servidor):

```bash
uv run python tests/test_archetypes.py
```

**2. Prueba de integracion end-to-end** (arranca el servidor y actua como
cliente MCP real, con handshake y llamada a las 3 herramientas):

```bash
uv run python tests/test_integration.py
```

**3. Con pytest** (corre las pruebas unitarias; la de integracion se corre
directo con Python, ver arriba, ya que no sigue la convencion `test_*` de pytest
a nivel de funcion):

```bash
uv run pytest tests/
```

**4. Inspeccion manual con el MCP Inspector** (interfaz visual oficial):

```bash
uv run mcp dev src/pattern_analysis_mcp/server.py
```

**5. Arranque directo del servidor** (queda esperando mensajes por stdio; usa
Ctrl+C para salir):

```bash
uv run python run_server.py
```

### Como conectarlo a un cliente MCP

Para usarlo desde un cliente compatible (por ejemplo, Claude Desktop, o el
orquestador del prototipo), agrega al archivo de configuracion del cliente:

```json
{
  "mcpServers": {
    "pattern-analysis-mcp": {
      "command": "uv",
      "args": ["run", "python", "run_server.py"],
      "cwd": "/ruta/al/proyecto/pattern-archetype-MCP"
    }
  }
}
```

### Por que existe run_server.py (y no simplemente el comando de consola)

El proyecto tambien instala un comando de consola (`pattern-analysis-mcp`,
definido en `[project.scripts]` de `pyproject.toml`), que es la convencion
normal de este tipo de servidor MCP. Sin embargo, ese comando depende de que
`pattern_analysis_mcp` sea importable a traves del mecanismo de instalacion
editable de `uv`/pip (un archivo `.pth` en `site-packages` que apunta de vuelta
a `src/`). En maquinas donde la ruta del proyecto contiene caracteres no ASCII
(como las tildes y la eñe de este proyecto: `Sofía`, `año`), Python puede leer
ese `.pth` con la codificacion de texto por defecto del sistema (`cp1252` en
Windows en vez de UTF-8), la ruta queda corrupta, y el import falla en
silencio con `ModuleNotFoundError: No module named 'pattern_analysis_mcp'`,
sin relacion alguna con el codigo del servidor.

`run_server.py` evita el problema de raiz: agrega `src/` a `sys.path`
directamente en Python (con `pathlib`, sin leer ningun archivo `.pth`) antes de
importar el paquete. Funciona igual sin importar quien lo invoque (tu
terminal, `mcp dev`, o un cliente MCP como Claude Desktop) y sin necesitar
ninguna variable de entorno. Por eso es el metodo recomendado, tanto en los
comandos de arriba como en el ejemplo de configuracion de cliente MCP.

Si prefieres usar `uv run pattern-analysis-mcp` de todas formas y tu maquina
tiene el mismo problema, corre `set PYTHONUTF8=1` (cmd) o
`$env:PYTHONUTF8=1` (PowerShell) antes, en la misma terminal donde vas a
correr el comando.

La variable de entorno `PYTHONUTF8=1` fuerza a Python a usar UTF-8 en todos
lados y resuelve esto por completo. Si usas el comando de consola desde un
cliente MCP, agrega tambien `"env": {"PYTHONUTF8": "1"}` a la configuracion del
servidor en ese cliente: los clientes como Claude Desktop arrancan el servidor
como un subproceso nuevo, que no hereda las variables que hayas exportado en tu
propia terminal. Con `run_server.py` (el ejemplo de arriba) no hace falta.

Las pruebas (`test_archetypes.py`, `test_integration.py`, `pytest`) no
necesitan esto porque agregan `src/` a `sys.path` explicitamente en el codigo,
sin depender de la instalacion editable.

### Notas de implementacion

- El servidor fuerza modo offline de Hugging Face (`HF_HUB_OFFLINE=1`) al
  cargar el modelo de embeddings, ya que este debe estar en cache local desde
  la Parte 1. Esto evita llamadas de red innecesarias en cada consulta y hace
  que el servidor funcione sin conectividad a internet.
- El modelo de sentence-transformers se carga de forma perezosa (en el primer
  llamado a `classify_archetype`), no al arrancar el servidor, para que
  `list_archetypes` y `get_archetype` respondan de inmediato sin depender de
  tener el modelo cargado. El arranque del servidor tarda de todas formas varios
  segundos, porque importar `sentence-transformers` carga PyTorch.
- KMeans asigna el arquetipo por distancia euclidiana a los centroides sin
  normalizar, y la similitud se reporta como coseno contra el centroide
  normalizado. Por eso el arquetipo asignado no siempre es el de mayor coseno
  (difieren en el 4.87% de los correos del corpus de construccion); ver la
  seccion de limitaciones de [DOCUMENTACION.md](DOCUMENTACION.md).
- Si `archetypes.json` y `kmeans_archetypes.pkl` quedan desalineados (por
  ejemplo, si se edita uno sin regenerar el otro), el servidor falla al iniciar
  con un error explicito en vez de dar resultados incorrectos silenciosamente.

## Autoria

Sofia Mishell Velasquez - Universidad del Valle de Guatemala.
