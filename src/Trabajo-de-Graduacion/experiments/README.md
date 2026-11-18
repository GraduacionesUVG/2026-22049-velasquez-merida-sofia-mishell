# Experimentación — evaluación externa del sistema LLM+MCP

Este directorio contiene la evaluación del sistema LLM+MCP propuesto en la
tesis contra Rspamd, sobre un conjunto externo de correos que ninguno de los
dos vio antes, y los notebooks que comparan sus resultados.

El orquestador LLM+MCP vive en otro repositorio
(`phishing-detection-orchestrator`, que se espera como carpeta hermana de
este repo). Aquí solo están los datos de evaluación, los scripts que corren
cada sistema sobre ellos y el análisis.

La descripción de todo el proyecto, incluida la preparación del corpus de
la Fase 1, está en
[`DOCUMENTACION_PROYECTO.md`](../DOCUMENTACION_PROYECTO.md).

Todos los sistemas se miden contra los mismos umbrales objetivo:

| Métrica | Umbral objetivo |
| --- | --- |
| Recall | ≥ 0.85 |
| F1 | ≥ 0.82 |
| AUC-ROC | ≥ 0.88 |
| MCC | ≥ 0.70 |

## Estructura

```text
experiments/
├── external_eval/                    Conjunto de evaluación y submuestras
│   ├── build_eval_external.py        Construye eval_external.csv (1,000 correos)
│   ├── build_eval_external_100.py    Submuestra estratificada de 100
│   ├── build_eval_external_200.py    Amplía la submuestra a 200
│   ├── eval_external.csv             1,000 correos (no versionado)
│   ├── eval_external_100.csv         100 correos
│   ├── eval_external_101_200.csv     Los 100 correos añadidos
│   ├── eval_external_200.csv         Los 200 (100 originales + 100 nuevos)
│   └── phishing_pot/                 Clon de Phishing Pot (no versionado)
├── eval_system/                      Corridas de cada sistema y sus resultados
│   ├── eval_rspamd_external.py       Rspamd sobre los 1,000
│   ├── rspamd_results_raw.jsonl      Resultado por correo de Rspamd
│   ├── rspamd_metrics_final.json     Métricas agregadas de Rspamd
│   ├── run_eval_explicacion_100.py   LLM+MCP en modo explicación, 100 correos
│   ├── results_explicacion_100.jsonl
│   ├── run_eval_explicacion_101_200.py   Ídem, los 100 correos añadidos
│   └── results_explicacion_101_200.jsonl
├── figures/                          Figuras que generan los notebooks
├── analisis_comparativo.ipynb        LLM+MCP (veredicto) vs. Rspamd, 1,000 correos
└── analisis_comparativo_100.ipynb    Rspamd vs. veredicto vs. explicación, 100 correos
```

Los resultados del sistema LLM+MCP en modo veredicto sobre los 1,000 correos
están en [`data/results_raw.jsonl`](../data/results_raw.jsonl), en la raíz
del repo. Es una copia del archivo que genera `run_evaluation.py` en el
repositorio del orquestador.

## Conjunto de evaluación

**`external_eval/eval_external.csv`** tiene 1,000 correos, 500 por clase,
que no forman parte del corpus de construcción de la tesis
(`data/corpus_construccion.csv`):

- **Phishing (500):** correos reales `.eml` de
  [Phishing Pot](https://github.com/rf-peixoto/phishing_pot), con headers
  SMTP completos, parseados con `email.parser`.
- **Legítimo (500):** muestra aleatoria (`random_state=42`) de los correos
  ham (`label==0`) de
  [TREC 2007](https://www.kaggle.com/datasets/imdeepmind/preprocessed-trec-2007-public-corpus-dataset),
  descargado con `kagglehub`.

Columnas: `id, label, subject, sender, body, raw_text, source`. Hay dos
columnas de texto y cada sistema usa una distinta:

| Columna | Contenido | La usa |
| --- | --- | --- |
| `body` | Cuerpo en texto plano, sin headers | Sistema LLM+MCP (ambos modos) |
| `raw_text` | Correo con headers: reales en Phishing Pot; reconstruidos (`From`, `To`, `Subject`, `Date`, `Message-ID`) en TREC | Rspamd |

### Submuestras

El modo explicación del orquestador usa los cuatro servidores MCP y es
demasiado lento para los 1,000 correos, así que se evalúa sobre submuestras
estratificadas (`random_state=42`, 50 % por clase):

| Archivo | Correos | Contenido |
| --- | --- | --- |
| `eval_external_100.csv` | 100 | 50 phishing + 50 legítimos |
| `eval_external_101_200.csv` | 100 | 50 + 50 adicionales, sin repetir ninguno de los anteriores |
| `eval_external_200.csv` | 200 | Los 100 originales, en el mismo orden, seguidos de los 100 nuevos |

`build_eval_external_200.py` verifica que sus primeros 100 correos sean
idénticos a `eval_external_100.csv` y no escribe nada si no lo son.

## Sistemas evaluados

| Sistema | Qué es | Entrada | Correos evaluados | Script |
| --- | --- | --- | --- | --- |
| Rspamd | Filtro de reglas self-hosted, API HTTP `/checkv2`, umbral de score ≥ 6.0 | `raw_text` | 1,000 | [`eval_rspamd_external.py`](eval_system/eval_rspamd_external.py) |
| LLM+MCP, modo veredicto | Orquestador con los servidores archetype y virustotal | `body` | 1,000 | `run_evaluation.py` (repo del orquestador) |
| LLM+MCP, modo explicación | Orquestador con los cuatro servidores (archetype, knowledge, virustotal, coherence) | `body` | 100 (+100 en curso) | [`run_eval_explicacion_100.py`](eval_system/run_eval_explicacion_100.py), [`run_eval_explicacion_101_200.py`](eval_system/run_eval_explicacion_101_200.py) |

Todos los archivos de resultados comparten el mismo esquema por correo
(`id, label_real, clasificacion, puntaje_riesgo, arquetipo_id,
arquetipo_label, vt_indicadores, vt_resultados, input_tokens,
output_tokens, costo_usd, tiempo_ms, error`), con campos adicionales según
el sistema:

- **Rspamd:** `rspamd_score` (score crudo) y `rspamd_action`.
  `puntaje_riesgo` es el score dividido entre 20 y recortado a [0, 1].
- **Modo explicación:** `senales_count`, `senales`, `explicacion`,
  `herramientas_invocadas`, más `rspamd_score` y `rspamd_action` copiados
  de la corrida de Rspamd. El CLI del orquestador no expone tokens ni
  detalle de VirusTotal, así que `input_tokens`, `output_tokens` y
  `costo_usd` quedan en `null` y `vt_indicadores` / `vt_resultados` vacíos.

## Resultados

### 1,000 correos: LLM+MCP (veredicto) vs. Rspamd

Notebook: [`analisis_comparativo.ipynb`](analisis_comparativo.ipynb).

| Métrica | LLM+MCP (veredicto) | Rspamd |
| --- | --- | --- |
| Accuracy | **0.915** | 0.785 |
| Precision | **0.960** | 0.739 |
| Recall | 0.866 | **0.882** |
| F1 | **0.911** | 0.804 |
| MCC | **0.834** | 0.581 |
| AUC-ROC | **0.975** | 0.839 |
| FNR | 0.134 | **0.118** |
| FPR | **0.036** | 0.312 |
| TP / FP / FN / TN | 433 / 18 / 67 / 482 | 441 / 156 / 59 / 344 |

- El sistema LLM+MCP cumple los cuatro umbrales objetivo. Rspamd solo cumple
  el de Recall.
- En detección de phishing están prácticamente empatados: Rspamd detecta 8
  correos más y la diferencia no es significativa (McNemar exacta, p = 0.50).
- La ventaja del LLM está en las falsas alarmas: marca 18 legítimos como
  phishing, frente a 156 de Rspamd.
- Fallan en correos distintos: solo 10 phishing se les escapan a ambos, y
  entre los dos detectan 490 de 500. Un ensemble OR tendría Recall 0.980,
  pero con 167 falsos positivos (F1 0.847).
- El LLM costó USD 21.87 y tardó una mediana de 22 s por correo; Rspamd,
  0.27 s por correo sin costo.

El notebook incluye además el análisis cualitativo de errores (sección 11:
qué arquetipos no detecta cada sistema, qué correos legítimos los confunden
y la complementariedad entre ambos) y el análisis de patrones semánticos
(sección 12: distribución de arquetipos, tasa de detección por arquetipo y
señales de VirusTotal).

### 100 correos: Rspamd vs. veredicto vs. explicación

Notebook: [`analisis_comparativo_100.ipynb`](analisis_comparativo_100.ipynb).

| Sistema | Accuracy | Precision | Recall | F1 | AUC-ROC | TP | FP | FN | TN |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Rspamd | 0.740 | 0.700 | 0.840 | 0.764 | 0.819 | 42 | 18 | 8 | 32 |
| LLM+MCP, veredicto | 0.890 | 0.933 | 0.840 | 0.884 | 0.969 | 42 | 3 | 8 | 47 |
| LLM+MCP, explicación | **0.910** | **0.956** | **0.860** | **0.905** | **0.980** | 43 | 2 | 7 | 48 |

- El modo explicación obtiene los mejores valores, pero la diferencia con el
  modo veredicto es de 2 correos sobre 100 y los intervalos de confianza se
  solapan casi por completo. Con esta muestra no se puede afirmar que
  clasifique mejor; sí que añadir los servidores de conocimiento y
  coherencia no degrada la clasificación.
- Los dos modos discrepan en 4 correos y comparten 8 errores (6 phishing no
  detectados y 2 legítimos marcados).
- El modo explicación tardó una mediana de 64 s por correo, frente a 24 s
  del modo veredicto en esos mismos correos.

### Correos 101–200 (modo explicación)

La corrida está en curso: `results_explicacion_101_200.jsonl` se va llenando
correo a correo y todavía no cubre los 100. Cuando termine, falta un
notebook que analice los 200 correos juntos: `analisis_comparativo_100.ipynb`
solo lee los 100 originales.

## Cómo reproducir

Desde `experiments/`, en este orden:

```powershell
# 1. Conjunto de evaluación (requiere el clon de Phishing Pot y TREC 2007 vía kagglehub)
python external_eval\build_eval_external.py
python external_eval\build_eval_external_100.py
python external_eval\build_eval_external_200.py

# 2. Rspamd sobre los 1,000 (requiere Rspamd escuchando en 127.0.0.1:11333)
python eval_system\eval_rspamd_external.py

# 3. Modo explicación (requiere el repo del orquestador con su .env y su .venv)
python eval_system\run_eval_explicacion_100.py
python eval_system\run_eval_explicacion_101_200.py
```

Después se ejecutan los notebooks con *Restart & Run All*.

- **Modo veredicto:** se corre con `run_evaluation.py` en el repositorio del
  orquestador y se copia su `results_raw.jsonl` a `data/`.
- **Reanudación:** los tres scripts de `eval_system/` son reanudables; si se
  interrumpen, al volver a lanzarlos saltan los correos ya guardados. En los
  de modo explicación, los correos que fallan van a un archivo
  `*_errores.jsonl` y se reintentan solos.
- **Prueba rápida:** todos aceptan `--limite N`. `eval_rspamd_external.py`
  acepta además `--dry-run` (datos simulados, sin llamar a Rspamd) y
  `--umbral`.
- **Tiempos:** Rspamd tarda unos 6 minutos en los 1,000 correos. El modo
  explicación tarda alrededor de dos horas por cada 100, porque VirusTotal
  está limitado a 4 consultas por minuto.
- **Regenerar `eval_external.csv` cambia el conjunto:** el `Date` sintético
  de los correos TREC toma la fecha del día en que se genera.

## Limitaciones conocidas

- **Entradas distintas.** El sistema LLM+MCP recibe solo el cuerpo (`body`)
  y Rspamd el correo con headers (`raw_text`). La comparación no es sobre
  exactamente la misma entrada.
- **Headers reconstruidos en TREC.** Los legítimos no tienen `Content-Type`,
  `Received` ni firmas. Rspamd puntúa en buena parte por estructura: marca
  como phishing el 99 % de los legítimos con caracteres no ASCII en el
  cuerpo (96 de 97), frente al 14.9 % del resto. Una parte importante de sus
  falsos positivos se debe probablemente a la reconstrucción y no al
  contenido; su FPR sobre correo con headers completos sería menor.
- **Fecha sintética.** El `Date` de los correos TREC es la fecha en que se
  generó el CSV. `eval_rspamd_external.py` lo reescribe con la fecha actual
  al enviar; sin eso, Rspamd penaliza los 500 legítimos con `DATE_IN_PAST`
  y los falsos positivos suben de 156 a 272.
- **Umbral de Rspamd.** Se clasifica como phishing con score ≥ 6.0. Hay
  correos con score exactamente 6.0, así que usar `> 6` da resultados
  distintos (ver la sección siguiente).
- **VirusTotal no aportó señal.** En los 1,000 correos del modo veredicto no
  devolvió ningún veredicto malicioso (1,568 `clean`, 144 consultas con
  error). La detección del LLM descansa en el texto y el arquetipo.
- **Etiquetas de TREC.** Al menos 4 de los 18 falsos positivos del LLM
  parecen, por su asunto, spam real etiquetado como legítimo.
- **Muestras pequeñas.** En las submuestras de 100, uno o dos correos mueven
  las métricas entre 1 y 2 puntos.

## Baselines anteriores (YARA, palabras clave, Rspamd)

Antes de esta evaluación se midieron tres baselines basados en reglas sobre
el mismo `eval_external.csv`:

| Baseline | Accuracy | Precision | Recall | F1 | AUC-ROC | MCC | FNR |
| --- | --- | --- | --- | --- | --- | --- | --- |
| YARA, regla única | 0.4990 | 0.3333 | 0.0020 | 0.0040 | 0.4990 | -0.0183 | 0.9980 |
| Palabras clave (SpamAssassin) | 0.5430 | 0.7471 | 0.1300 | 0.2215 | 0.5436 | 0.1526 | 0.8700 |
| Rspamd (corrida anterior) | 0.8230 | 0.7899 | 0.8800 | 0.8325 | 0.8394 | 0.6502 | 0.1200 |

- **YARA y palabras clave** fallan por la misma razón: coincidencia de
  patrones fijos que no cubre la variabilidad léxica del phishing real. La
  regla YARA solo se activó en 3 de los 1,000 correos y el filtro de
  palabras clave deja pasar el 87 % del phishing.
- **Rspamd, corrida anterior vs. actual.** La fila de esta tabla usaba el
  criterio `score > 6` (117 falsos positivos). La corrida actual usa
  `score ≥ 6.0`, que es como Rspamd aplica la acción `add header`, y da 156
  falsos positivos. El Recall y el AUC-ROC son prácticamente iguales en
  ambas (0.880 vs. 0.882 y 0.839 en las dos).

Los scripts, las reglas (`yara_rules/`, `keyword_rules/`) y los JSON de
`results/` de estos baselines se eliminaron del repo en el commit `0907577`.
Se pueden recuperar del commit anterior, por ejemplo con
`git show 57eee82:experiments/results/baselines_summary.json`.

## Archivos no versionados

- `external_eval/eval_external.csv` — se regenera con
  `build_eval_external.py`.
- `external_eval/phishing_pot/` — clon de terceros de unos 600 MB; se
  obtiene con `git clone https://github.com/rf-peixoto/phishing_pot.git`.
