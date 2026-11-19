# Documentación del proyecto

**Prototipo de sistema para la detección de phishing en correos electrónicos
usando modelos de lenguaje grandes y servidores MCP** — Trabajo de
graduación, Universidad del Valle de Guatemala, Ingeniería en Ciencias de la
Computación y Tecnologías de la Información.

Este documento describe todo lo que hace este repositorio: qué datos toma,
cómo los procesa, qué análisis realiza, qué archivos genera y qué resultados
se han obtenido hasta ahora. Estado al 4 de octubre de 2026.

## 1. Qué hace este repositorio

El repositorio cubre dos partes del trabajo de graduación:

1. **Fase 1 — Preparación del corpus.** Descarga un corpus público de
   correos, lo limpia, lo deduplica, le extrae señales de ingeniería social
   y lo explora. El resultado es el *corpus de construcción*, insumo para
   diseñar los servidores MCP del sistema.
2. **Experimentación — Evaluación externa.** Arma un conjunto de correos que
   el sistema nunca vio, corre sobre él el sistema LLM+MCP y Rspamd (un
   filtro de reglas de uso real), y compara los resultados.

Lo que **no** está aquí:

- **El orquestador LLM+MCP.** Vive en el repositorio
  `phishing-detection-orchestrator`, que los scripts esperan como carpeta
  hermana de este repo. Usa Claude Haiku 4.5 y consulta servidores MCP.
- **Los servidores MCP** (archetype, knowledge, coherence, virustotal).
  Cada uno tiene su propia carpeta, configurada en el `.env` del
  orquestador.

Este repo contiene los datos de evaluación, los scripts que lanzan cada
sistema sobre ellos y el análisis de los resultados.

## 2. Mapa del repositorio

```text
Trabajo-de-Graduacion/
├── 01_preparacion_corpus.ipynb     Fase 1: adquisición, limpieza, EDA
├── data/
│   ├── corpus_construccion.csv     Corpus de construcción (no versionado)
│   └── results_raw.jsonl           Resultados del LLM+MCP, modo veredicto, 1,000 correos
├── figures/                        12 gráficas del análisis exploratorio
├── reports/
│   └── data_quality_fase1.md       Reporte de calidad de datos (generado por el notebook)
├── experiments/
│   ├── README.md                   Guía de la experimentación
│   ├── external_eval/              Conjunto de evaluación externo y submuestras
│   ├── eval_system/                Scripts de evaluación y sus resultados
│   ├── figures/                    Figuras de los notebooks comparativos
│   ├── analisis_comparativo.ipynb       LLM+MCP (veredicto) vs. Rspamd, 1,000 correos
│   └── analisis_comparativo_100.ipynb   Rspamd vs. veredicto vs. explicación, 100 correos
└── DOCUMENTACION_PROYECTO.md       Este documento
```

## 3. Fase 1 — Preparación del corpus

Todo ocurre en [`01_preparacion_corpus.ipynb`](01_preparacion_corpus.ipynb),
que cubre las actividades A1.1 (adquisición y exploración inicial) y A1.2
(limpieza, normalización y deduplicación) del protocolo.

### 3.1 Fuente de datos

El corpus base es el de Al-Subaiey et al. (2024), descargado de Kaggle con
`kagglehub` (`naserabdullahalam/phishing-email-dataset`). Integra seis
fuentes: Enron, CEAS 2008, Ling-Spam, Nazario, Nigerian Fraud y
SpamAssassin.

El paquete trae también un archivo ya consolidado (`phishing_email.csv`),
pero no se usa: su texto viene sin signos de puntuación, así que las URL y
los correos quedan pegados como cadenas continuas y no se pueden extraer. El
notebook trabaja con las **seis fuentes originales por separado**, combina
`subject` y `body` en un campo `text_combined` y conserva remitente y
destinatario donde existen (Enron y Ling-Spam no los traen).

### 3.2 Pasos del procesamiento

| Paso | Qué hace | Resultado |
| --- | --- | --- |
| Carga | Lee las 6 fuentes en UTF-8 y las concatena | 82,486 correos, 4 columnas |
| Extracción de señales | URL, correos, dominios, léxicos de ingeniería social, marcadores tipográficos (sobre el texto crudo) | 16 columnas |
| Limpieza | Decodifica entidades HTML, quita etiquetas, reemplaza URL y correos por los marcadores `URL` y `EMAIL`, colapsa espacios | Columna `text_clean` |
| Deduplicación | Clave MD5 sobre el texto en minúsculas y con espacios normalizados | 77,273 (se eliminan 5,213) |
| Filtrado | Descarta cuerpos vacíos, de menos de 3 palabras o sin etiqueta | 77,267 (se eliminan 6) |
| Exportación | Escribe el corpus final y el reporte de calidad | `corpus_construccion.csv` |

La limpieza es deliberadamente ligera: no se quitan *stopwords*, no se
lematiza ni se pasa todo a minúsculas, porque el análisis semántico necesita
el texto en su forma natural.

### 3.3 Señales que se extraen de cada correo

| Columna | Qué mide |
| --- | --- |
| `n_urls`, `urls` | Número y lista de URL |
| `tiene_url_ip` | Si hay alguna URL basada en dirección IP |
| `n_emails`, `dominios_email` | Direcciones de correo en el cuerpo y sus dominios |
| `remitente_dominio` | Dominio del remitente real (solo 4 de las 6 fuentes) |
| `sig_urgencia` | Conteo de términos de urgencia (*urgent, immediately, expire, suspend...*) |
| `sig_dinero` | Conteo de términos de incentivo económico (*million, prize, lottery, fund...*) |
| `sig_credenciales` | Conteo de términos de credenciales (*password, account, verify, bank...*) |
| `sig_accion` | Conteo de llamados a la acción (*click, download, reply, visit...*) |
| `ratio_mayusculas` | Proporción de caracteres en mayúscula |
| `n_exclamaciones` | Número de signos de exclamación |
| `len_words`, `len_chars` | Longitud del texto limpio |

Los cuatro léxicos son expresiones regulares en inglés, definidas en el
notebook.

### 3.4 Análisis exploratorio

El notebook produce 12 gráficas en [`figures/`](figures/):

| Gráfica | Qué muestra | Hallazgo |
| --- | --- | --- |
| `01_distribucion_clases.png` | Clases en el corpus crudo | 39,595 legítimos (48.0 %) y 42,891 phishing/spam (52.0 %) |
| `02_elementos_estructurales.png` | Correos con HTML, URL, direcciones y entidades HTML | 39.7 % tiene URL, 22.1 % direcciones de correo, 5.8 % etiquetas HTML |
| `03_longitud_corpus_crudo.png` | Distribución de longitud en palabras | Cola larga: mediana de 136 palabras, máximo de 127,506 |
| `04_longitud_por_clase.png` | Longitud por clase (histograma y caja) | Los legítimos son más largos: mediana de 190 palabras frente a 82 |
| `05_senales_por_clase.png` | Promedio de las 4 señales de ingeniería social | Todas son más altas en phishing; la mayor diferencia está en credenciales (1.02 vs. 0.29) y dinero (0.74 vs. 0.31) |
| `06_url_riesgo_por_clase.png` | Correos con URL y con URL basada en IP | Tener URL no distingue las clases (38.9 % legítimos, 33.9 % phishing); la URL con IP es rara pero más frecuente en phishing (0.34 % vs. 0.06 %) |
| `07_marcadores_tipograficos.png` | Mayúsculas y exclamaciones por clase | Algo más altos en phishing |
| `08_idiomas.png` | Idioma detectado en una muestra de 3,000 correos | 98.9 % en inglés |
| `09_correlacion_senales.png` | Correlación entre señales y la clase | Todas débiles; la mayor es `ratio_mayusculas` (0.126) |
| `10_dominios_frecuentes.png` | Dominios más mencionados en el cuerpo | Dominan listas de correo técnicas (`python.org`, `lists.sourceforge.net`) |
| `11_dominios_remitente_frecuentes.png` | Dominios de remitente más frecuentes | `gmail.com`, `hotmail.com`, `yahoo.com` encabezan |
| `12_wordcloud_por_clase.png` | Nubes de palabras por clase | Resumen visual del vocabulario |

La conclusión de esta fase es que ninguna señal léxica simple separa bien las
clases por sí sola (correlaciones por debajo de 0.13), lo que motiva el
enfoque semántico del sistema.

### 3.5 Corpus resultante

- **77,267 correos**: 39,201 legítimos (50.73 %) y 38,066 phishing/spam
  (49.27 %).
- **Cobertura de señales:** 36.4 % con al menos una URL, 26.7 % con señal de
  urgencia, 24.7 % con llamado a la acción, 15.5 % con señal de
  credenciales, 13.8 % con incentivo económico, 56.9 % con dominio de
  remitente.
- **Reproducibilidad:** semilla global 42 y umbral mínimo de 3 palabras.

El detalle está en
[`reports/data_quality_fase1.md`](reports/data_quality_fase1.md), que el
propio notebook genera.

## 4. Experimentación — Evaluación externa

La guía detallada está en [`experiments/README.md`](experiments/README.md).
Aquí va el resumen.

### 4.1 Conjunto de evaluación

`experiments/external_eval/eval_external.csv` tiene 1,000 correos que no
están en el corpus de construcción:

- **500 phishing** de [Phishing Pot](https://github.com/rf-peixoto/phishing_pot),
  archivos `.eml` reales con headers completos.
- **500 legítimos** de
  [TREC 2007](https://www.kaggle.com/datasets/imdeepmind/preprocessed-trec-2007-public-corpus-dataset),
  muestreados con `random_state=42`.

Cada correo tiene dos versiones del texto: `body` (solo el cuerpo) y
`raw_text` (con headers; reales en Phishing Pot, reconstruidos en TREC).

Del conjunto se sacan submuestras estratificadas para el modo explicación,
que es demasiado lento para los 1,000: 100 correos, y luego otros 100 hasta
completar 200.

### 4.2 Sistemas que se comparan

| Sistema | Qué es | Texto que recibe | Correos |
| --- | --- | --- | --- |
| Rspamd | Filtro de reglas self-hosted; phishing si el score es ≥ 6.0 | `raw_text` | 1,000 |
| LLM+MCP, modo veredicto | Orquestador con los servidores archetype y virustotal; devuelve clasificación y puntaje | `body` | 1,000 |
| LLM+MCP, modo explicación | Orquestador con los cuatro servidores; devuelve además señales y explicación | `body` | 100 (y 100 más en curso) |

### 4.3 Scripts

| Script | Qué hace |
| --- | --- |
| `external_eval/build_eval_external.py` | Parsea Phishing Pot, muestrea TREC 2007 y arma `eval_external.csv` |
| `external_eval/build_eval_external_100.py` | Saca la submuestra de 100 (50 + 50) |
| `external_eval/build_eval_external_200.py` | Añade otros 100 y verifica que los primeros 100 no cambien |
| `eval_system/eval_rspamd_external.py` | Envía cada correo a Rspamd por HTTP y guarda score, acción y clasificación |
| `eval_system/run_eval_explicacion_100.py` | Llama al CLI del orquestador en modo explicación, un correo a la vez |
| `eval_system/run_eval_explicacion_101_200.py` | Lo mismo para los 100 correos añadidos |

El modo veredicto sobre los 1,000 correos se corrió con `run_evaluation.py`
desde el repositorio del orquestador; su salida se copió a
`data/results_raw.jsonl`.

Los tres scripts de `eval_system/` guardan un resultado por correo a medida
que avanzan y se pueden reanudar si se interrumpen.

### 4.4 Notebooks de análisis

**[`experiments/analisis_comparativo.ipynb`](experiments/analisis_comparativo.ipynb)**
compara el modo veredicto con Rspamd sobre los 1,000 correos:

| Secciones | Contenido |
| --- | --- |
| 1–2 | Carga, verificación de que ambos sistemas evaluaron los mismos correos |
| 3 | Tabla de métricas (accuracy, precision, recall, F1, MCC, AUC-ROC, FNR, FPR) |
| 4–6 | Matrices de confusión, curvas ROC, distribución de scores |
| 7–8 | Correos donde los sistemas difieren; falsos negativos; prueba de McNemar |
| 9–10 | Gráfico de barras de métricas y conclusiones |
| 11 | Análisis cualitativo: en qué falla cada sistema y complementariedad |
| 12 | Patrones semánticos: distribución de arquetipos, tasa de detección por arquetipo, señales de VirusTotal |

**[`experiments/analisis_comparativo_100.ipynb`](experiments/analisis_comparativo_100.ipynb)**
compara los tres sistemas sobre la submuestra de 100: métricas con
intervalos de confianza por bootstrap, matrices de confusión, curvas ROC,
correos donde veredicto y explicación difieren, y una tabla lista para el
capítulo de resultados.

## 5. Datos y archivos que genera el proyecto

| Archivo | Lo genera | Contenido | En git |
| --- | --- | --- | --- |
| `data/corpus_construccion.csv` | `01_preparacion_corpus.ipynb` | 77,267 correos limpios, 19 columnas (texto, etiqueta, señales) | No (140 MB) |
| `reports/data_quality_fase1.md` | `01_preparacion_corpus.ipynb` | Reporte de calidad de la Fase 1 | Sí |
| `figures/01`–`12_*.png` | `01_preparacion_corpus.ipynb` | Gráficas del análisis exploratorio | Sí |
| `experiments/external_eval/eval_external.csv` | `build_eval_external.py` | 1,000 correos de evaluación | No |
| `experiments/external_eval/eval_external_100.csv` | `build_eval_external_100.py` | Submuestra de 100 | Sí |
| `experiments/external_eval/eval_external_101_200.csv` | `build_eval_external_200.py` | Los 100 correos añadidos | Sin commit aún |
| `experiments/external_eval/eval_external_200.csv` | `build_eval_external_200.py` | Los 200 | Sin commit aún |
| `data/results_raw.jsonl` | `run_evaluation.py` (repo del orquestador) | Resultado por correo del modo veredicto, 1,000 correos | Sí |
| `experiments/eval_system/rspamd_results_raw.jsonl` | `eval_rspamd_external.py` | Resultado por correo de Rspamd, 1,000 correos | Sí |
| `experiments/eval_system/rspamd_metrics_final.json` | `eval_rspamd_external.py` | Métricas agregadas de Rspamd | Sí |
| `experiments/eval_system/results_explicacion_100.jsonl` | `run_eval_explicacion_100.py` | Resultado por correo del modo explicación, con señales y explicación | Sí |
| `experiments/eval_system/results_explicacion_101_200.jsonl` | `run_eval_explicacion_101_200.py` | Ídem para los 100 añadidos (corrida en curso) | Sin commit aún |
| `experiments/figures/*.png` | Notebooks comparativos | Matrices de confusión, ROC, distribuciones, errores, arquetipos | Sí |

Todos los archivos de resultados tienen una línea JSON por correo con los
mismos campos base: `id`, `label_real`, `clasificacion`, `puntaje_riesgo`,
`arquetipo_id`, `arquetipo_label`, `vt_indicadores`, `vt_resultados`,
`input_tokens`, `output_tokens`, `costo_usd`, `tiempo_ms`, `error`. Rspamd
añade `rspamd_score` y `rspamd_action`; el modo explicación añade
`senales_count`, `senales`, `explicacion` y `herramientas_invocadas`.

## 6. Resultados obtenidos hasta ahora

Umbrales objetivo de la tesis: Recall ≥ 0.85, F1 ≥ 0.82, AUC-ROC ≥ 0.88,
MCC ≥ 0.70.

### 6.1 Sobre los 1,000 correos

| Métrica | LLM+MCP (veredicto) | Rspamd |
| --- | --- | --- |
| Accuracy | 0.915 | 0.785 |
| Precision | 0.960 | 0.739 |
| Recall | 0.866 | 0.882 |
| F1 | 0.911 | 0.804 |
| MCC | 0.834 | 0.581 |
| AUC-ROC | 0.975 | 0.839 |
| Falsos positivos (de 500) | 18 | 156 |
| Falsos negativos (de 500) | 67 | 59 |

- El sistema LLM+MCP cumple los cuatro umbrales objetivo; Rspamd solo el de
  Recall.
- Detectan casi el mismo phishing (diferencia de 8 correos, no
  significativa). La ventaja del LLM está en las falsas alarmas: 18 frente
  a 156.
- Fallan en correos distintos: solo 10 phishing se les escapan a los dos.
- El LLM falla sobre todo en spam comercial (63 de sus 67 falsos negativos),
  no en phishing de credenciales. Rspamd deja pasar más correos de
  suplantación de cuenta (18 frente a 4).
- Costo del LLM: USD 21.87 y una mediana de 22 s por correo. Rspamd: 0.27 s
  por correo, sin costo.

### 6.2 Sobre la submuestra de 100

| Sistema | Accuracy | Precision | Recall | F1 | AUC-ROC |
| --- | --- | --- | --- | --- | --- |
| Rspamd | 0.740 | 0.700 | 0.840 | 0.764 | 0.819 |
| LLM+MCP, veredicto | 0.890 | 0.933 | 0.840 | 0.884 | 0.969 |
| LLM+MCP, explicación | 0.910 | 0.956 | 0.860 | 0.905 | 0.980 |

El modo explicación obtiene los mejores valores, pero la diferencia con el
modo veredicto es de 2 correos sobre 100 y no es concluyente. Lo que sí se
puede afirmar es que usar los cuatro servidores MCP no empeora la
clasificación. El modo explicación tarda una mediana de 64 s por correo,
frente a 24 s del modo veredicto.

### 6.3 Baselines anteriores

En una etapa previa se midieron también una regla YARA (Recall 0.002) y un
filtro de palabras clave de SpamAssassin (Recall 0.13) sobre el mismo
conjunto. Ambos fallan porque buscan patrones de texto fijos. Sus scripts y
resultados se eliminaron del repo en el commit `0907577` y se pueden
recuperar del historial de git.

## 7. Limitaciones que hay que declarar

- **Los sistemas no reciben la misma entrada.** El LLM ve solo el cuerpo del
  correo; Rspamd ve el correo con headers.
- **Los legítimos de TREC tienen headers reconstruidos.** Rspamd puntúa en
  buena parte por estructura, así que una parte importante de sus falsos
  positivos se debe probablemente a esa reconstrucción. Marca como phishing
  el 99 % de los legítimos con caracteres no ASCII en el cuerpo.
- **El resultado de Rspamd depende del umbral y de la fecha.** Con `> 6` en
  vez de `≥ 6.0` los falsos positivos bajan de 156 a unos 118. El script
  reescribe la fecha sintética de los correos TREC para que el resultado no
  cambie según el día en que se corra.
- **VirusTotal no aportó señal.** En los 1,000 correos del modo veredicto no
  devolvió ningún veredicto malicioso.
- **Etiquetas de TREC.** Algunos correos etiquetados como legítimos parecen
  spam real.
- **Las submuestras son pequeñas.** En 100 correos, uno o dos cambian las
  métricas entre 1 y 2 puntos.
- **El corpus es casi todo en inglés** (98.9 %), igual que los léxicos de
  señales.
- **El modo explicación no registra tokens ni costo**, porque el CLI del
  orquestador no los expone.

## 8. Cómo reproducir todo

Requisitos: Python 3.10 o superior con `pandas`, `numpy`, `matplotlib`,
`seaborn`, `scikit-learn`, `scipy`, `requests`, `kagglehub`, `langdetect`,
`wordcloud` y Jupyter.

```powershell
# Fase 1: ejecutar el notebook completo (descarga el corpus de Kaggle)
jupyter nbconvert --to notebook --execute --inplace 01_preparacion_corpus.ipynb

# Conjunto de evaluación (requiere clonar Phishing Pot en experiments\external_eval\phishing_pot)
cd experiments
python external_eval\build_eval_external.py
python external_eval\build_eval_external_100.py
python external_eval\build_eval_external_200.py

# Rspamd (requiere Rspamd escuchando en 127.0.0.1:11333)
python eval_system\eval_rspamd_external.py

# Modo explicación (requiere el repo del orquestador con su .env y su .venv)
python eval_system\run_eval_explicacion_100.py
python eval_system\run_eval_explicacion_101_200.py
```

Después se ejecutan los dos notebooks de `experiments/` con *Restart & Run
All*.

Dependencias externas:

| Servicio | Para qué | Notas |
| --- | --- | --- |
| Kaggle (`kagglehub`) | Corpus de Al-Subaiey et al. y TREC 2007 | Descarga a la caché local |
| Phishing Pot | Correos de phishing | `git clone https://github.com/rf-peixoto/phishing_pot.git` |
| Rspamd | Baseline de reglas | Corre en WSL; usar `127.0.0.1`, no `localhost` |
| API de Anthropic | Orquestador y servidor de coherencia | Clave en el `.env` del orquestador |
| VirusTotal | Reputación de URL y dominios | Plan gratuito: 4 consultas por minuto y 500 al día |

Tiempos de referencia: Rspamd sobre 1,000 correos, unos 6 minutos; modo
veredicto sobre 1,000, unos 80 minutos; modo explicación, alrededor de dos
horas por cada 100 correos.

## 9. Estado y pendientes

- **Hecho:** Fase 1 completa; evaluación de Rspamd y del modo veredicto
  sobre los 1,000 correos; evaluación del modo explicación sobre 100;
  notebooks comparativos de 1,000 y de 100.
- **En curso:** modo explicación sobre los correos 101–200.
- **Pendiente:** notebook que analice los 200 correos juntos; commit de los
  archivos de la ampliación a 200.

## Referencia del corpus

Al-Subaiey, A., Al-Thani, M., Alam, N. A., Antora, K. F., Khandakar, A., &
Zaman, S. A. U. (2024). Novel interpretable and robust web-based AI platform
for phishing email detection. *Computers & Electrical Engineering,
120*(Part A), Article 109625.
https://doi.org/10.1016/j.compeleceng.2024.109625
