#!/usr/bin/env python3
"""Re-evaluacion de Rspamd sobre el conjunto externo
(experiments/external_eval/eval_external.csv: 1,000 correos, 500 phishing de
Phishing Pot + 500 legitimos de TREC 2007), guardando un resultado por
correo en el MISMO formato que results_raw.jsonl del orquestador LLM (repo
phishing-detection-orchestrator, experiments/eval_system/run_evaluation.py),
para comparar ambos sistemas en el mismo notebook.

QUE HACE
--------
Para cada fila del CSV (columnas: id, label, raw_text) envia raw_text (el
correo con sus headers SMTP) a Rspamd por HTTP (POST /checkv2) y registra el
score crudo, la accion, la clasificacion segun un umbral de score y el score
normalizado a [0,1] como puntaje_riesgo.

Es CHECKPOINTEADO Y REANUDABLE igual que run_evaluation.py: la fuente de
verdad de que correos ya se procesaron es rspamd_results_raw.jsonl.

COMO USARLO
-----------
    python eval_rspamd_external.py
    python eval_rspamd_external.py --umbral 5.0
    python eval_rspamd_external.py --url http://127.0.0.1:11333
    python eval_rspamd_external.py --limite 20   # para probar rapido
    python eval_rspamd_external.py --dry-run     # sin llamar a Rspamd

ARCHIVOS QUE GENERA (en este mismo directorio, experiments/eval_system/)
-----------------------------------------------------------------------
- rspamd_results_raw.jsonl   Un objeto JSON por linea, uno por correo.
- rspamd_metrics_final.json  Metricas agregadas de todo lo acumulado.

Con --dry-run los mismos archivos se escriben con sufijo "_dryrun" para
nunca pisar el progreso de una corrida real.
"""

from __future__ import annotations

import argparse
import csv
import email.utils
import json
import math
import random
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

# Algunos correos (Phishing Pot, .eml completos) superan el limite por
# defecto del modulo csv. min(...) porque en Windows el 'long' de C es de 32
# bits: pasar sys.maxsize directo revienta con OverflowError.
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))


# ==========================================================================
# Configuracion
# ==========================================================================

EVAL_SYSTEM_DIR = Path(__file__).resolve().parent
DEFAULT_INPUT_CSV = EVAL_SYSTEM_DIR.parent / "external_eval" / "eval_external.csv"
DATASET_NOMBRE = "experiments/external_eval/eval_external.csv"

# 127.0.0.1 y no "localhost": en Windows "localhost" resuelve primero a ::1
# (IPv6), Rspamd solo escucha en IPv4 y cada conexion pierde ~2 s en el
# reintento. Rspamd cierra la conexion tras cada respuesta, asi que se paga
# en todos los correos.
DEFAULT_URL = "http://127.0.0.1:11333"
UMBRAL_DEFAULT = 6.0
SCORE_TOPE = 20.0  # tope tipico de Rspamd, para normalizar el score a [0,1]
TIMEOUT_HTTP_S = 10
PROGRESO_CADA_N_CORREOS = 50

# Los correos TREC de eval_external.csv traen un header Date SINTETICO (la
# fecha en que build_eval_external.py genero el CSV, no la del correo). Si
# se evalua dias despues, Rspamd penaliza los 500 legitimos con DATE_IN_PAST
# (+1.0) solo por la antiguedad del CSV. Se reescribe ese Date con la fecha
# actual al enviar, para que el resultado no dependa del dia de la corrida.
# Phishing Pot no se toca: sus fechas son las reales del .eml.
PREFIJO_ID_FECHA_SINTETICA = "trec_2007_"
_RE_HEADER_DATE = re.compile(r"^Date:[^\r\n]*", re.MULTILINE)
_RE_FIN_HEADERS = re.compile(r"\r?\n\r?\n")


# ==========================================================================
# Lectura del CSV y de resultados previos (checkpoint)
# ==========================================================================


def leer_csv(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for columna in ("id", "label", "raw_text"):
            if columna not in (reader.fieldnames or []):
                raise ValueError(f"El CSV de entrada no tiene la columna requerida '{columna}'")
        return [
            {"id": row["id"], "label": int(row["label"]), "raw_text": row["raw_text"]}
            for row in reader
        ]


def cargar_resultados_previos(results_path: Path) -> list[dict[str, Any]]:
    """La fuente de verdad de que correos ya se completaron es el propio
    JSONL (una linea por correo ya procesado)."""
    if not results_path.exists():
        return []
    resultados = []
    with results_path.open("r", encoding="utf-8") as f:
        for linea in f:
            linea = linea.strip()
            if not linea:
                continue
            try:
                obj = json.loads(linea)
                obj["id"]
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
            resultados.append(obj)
    return resultados


def preguntar_si_reanudar(n_completados: int) -> bool:
    print(f"\nSe encontro un checkpoint con {n_completados} correos ya completados.")
    respuesta = input("¿Reanudar desde donde quedo? [S/n]: ").strip().lower()
    return respuesta in ("", "s", "si", "sí", "y", "yes")


# ==========================================================================
# Resultado por correo (mismo schema que CorreoResultado.to_dict() de
# run_evaluation.py, mas rspamd_score y rspamd_action)
# ==========================================================================


def construir_resultado(
    id_: str, label_real: int, score: float | None, action: str | None,
    umbral: float, tiempo_ms: int, error: str | None,
) -> dict[str, Any]:
    if score is None:
        clasificacion = None
        puntaje_riesgo = None
    else:
        clasificacion = "phishing" if score >= umbral else "legitimo"
        puntaje_riesgo = min(1.0, max(0.0, score / SCORE_TOPE))
    return {
        "id": id_,
        "label_real": label_real,
        "clasificacion": clasificacion,
        "puntaje_riesgo": puntaje_riesgo,
        "arquetipo_id": None,
        "arquetipo_label": None,
        "vt_indicadores": [],
        "vt_resultados": {},
        "input_tokens": 0,
        "output_tokens": 0,
        "costo_usd": 0.0,
        "tiempo_ms": tiempo_ms,
        "error": error,
        "rspamd_score": score,
        "rspamd_action": action,
    }


# ==========================================================================
# Llamada a Rspamd (real) y simulacion (--dry-run)
# ==========================================================================


def refrescar_fecha_sintetica(raw_text: str) -> str:
    """Reemplaza el header Date (solo en el bloque de headers, no en el
    cuerpo) por la fecha actual."""
    m = _RE_HEADER_DATE.search(raw_text)
    fin_headers = _RE_FIN_HEADERS.search(raw_text)
    if m is None or (fin_headers is not None and m.start() > fin_headers.start()):
        return raw_text
    fecha = f"Date: {email.utils.formatdate(localtime=False)}"
    return raw_text[: m.start()] + fecha + raw_text[m.end():]


def consultar_rspamd(session: requests.Session, url: str, fila: dict[str, Any], umbral: float) -> dict[str, Any]:
    """Envia el correo crudo a /checkv2. Si la llamada falla, el error queda
    registrado en el resultado y la evaluacion sigue con el siguiente."""
    score: float | None = None
    action: str | None = None
    error: str | None = None
    raw_text = fila["raw_text"]
    if fila["id"].startswith(PREFIJO_ID_FECHA_SINTETICA):
        raw_text = refrescar_fecha_sintetica(raw_text)
    t0 = time.monotonic()
    try:
        respuesta = session.post(
            f"{url.rstrip('/')}/checkv2",
            data=raw_text.encode("utf-8"),
            headers={"Content-Type": "message/rfc2822"},
            timeout=TIMEOUT_HTTP_S,
        )
        respuesta.raise_for_status()
        data = respuesta.json()
        score = float(data["score"])
        action = str(data.get("action", ""))
    except requests.exceptions.RequestException as exc:
        error = f"{type(exc).__name__}: {exc}"
    except (ValueError, KeyError, TypeError) as exc:
        error = f"Respuesta invalida de Rspamd ({type(exc).__name__}: {exc})"
    tiempo_ms = int((time.monotonic() - t0) * 1000)
    return construir_resultado(fila["id"], fila["label"], score, action, umbral, tiempo_ms, error)


def resultado_simulado(fila: dict[str, Any], umbral: float) -> dict[str, Any]:
    """Genera un resultado plausible pero inventado, para --dry-run. No llama
    a Rspamd. Determinista por id, para que dos dry-runs den lo mismo."""
    rng = random.Random(fila["id"])
    score = round(rng.gauss(9.0, 4.0) if fila["label"] == 1 else rng.gauss(1.5, 3.0), 2)
    if score >= 15.0:
        action = "reject"
    elif score >= 6.0:
        action = "add header"
    elif score >= 4.0:
        action = "greylist"
    else:
        action = "no action"
    return construir_resultado(fila["id"], fila["label"], score, action, umbral, rng.randint(5, 40), None)


# ==========================================================================
# Metricas (mismos calculos que calcular_metricas() de run_evaluation.py)
# ==========================================================================


def _auc_roc(y_true: list[int], scores: list[float]) -> float | None:
    """AUC-ROC via suma de rangos (equivalente al estadistico de
    Mann-Whitney), sin numpy ni scikit-learn."""
    n_pos = sum(y_true)
    n_neg = len(y_true) - n_pos
    if n_pos == 0 or n_neg == 0:
        return None
    combinado = sorted(zip(scores, y_true), key=lambda par: par[0])
    n = len(combinado)
    suma_rangos_pos = 0.0
    i = 0
    while i < n:
        j = i
        while j < n and combinado[j][0] == combinado[i][0]:
            j += 1
        rango_promedio = (i + 1 + j) / 2.0  # rangos 1-indexados, empates promediados
        for k in range(i, j):
            if combinado[k][1] == 1:
                suma_rangos_pos += rango_promedio
        i = j
    return (suma_rangos_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def calcular_metricas(resultados: list[dict[str, Any]], umbral: float, inicio: datetime, fin: datetime) -> dict[str, Any]:
    validos = [
        r for r in resultados
        if r.get("error") is None and r.get("label_real") is not None and r.get("clasificacion") is not None
    ]

    tp = sum(1 for r in validos if r["clasificacion"] == "phishing" and r["label_real"] == 1)
    tn = sum(1 for r in validos if r["clasificacion"] == "legitimo" and r["label_real"] == 0)
    fp = sum(1 for r in validos if r["clasificacion"] == "phishing" and r["label_real"] == 0)
    fn = sum(1 for r in validos if r["clasificacion"] == "legitimo" and r["label_real"] == 1)

    n = tp + tn + fp + fn
    accuracy = (tp + tn) / n if n else None
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)) if (precision and recall and (precision + recall) > 0) else None
    fnr = fn / (fn + tp) if (fn + tp) else None

    denom_mcc = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn - fp * fn) / denom_mcc) if denom_mcc else None

    con_score = [r for r in validos if r.get("puntaje_riesgo") is not None]
    auc = _auc_roc([r["label_real"] for r in con_score], [r["puntaje_riesgo"] for r in con_score]) if con_score else None

    return {
        "herramienta": "rspamd",
        "dataset": DATASET_NOMBRE,
        "umbral_score": umbral,
        "timestamp_inicio": inicio.isoformat(),
        "timestamp_fin": fin.isoformat(),
        "tiempo_total_segundos": round((fin - inicio).total_seconds(), 1),
        "n_correos_total": len(resultados),
        "n_correos_validos_para_metricas": n,
        "n_correos_con_error": sum(1 for r in resultados if r.get("error") is not None),
        "matriz_confusion": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "auc_roc": auc,
        "mcc": mcc,
        "fnr": fnr,
        "costo_total_usd": 0.0,
        "notas": [
            "Clasificacion: phishing si rspamd_score >= umbral_score (mismo criterio con el que Rspamd aplica 'add header').",
            "El header Date sintetico de los correos TREC se reescribe con la fecha actual al enviar, para evitar la penalizacion DATE_IN_PAST por la antiguedad del CSV.",
        ],
    }


# ==========================================================================
# Bucle principal
# ==========================================================================


def _imprimir_progreso(
    idx: int, total_pendientes: int, ya_completados_antes: int,
    resultados_acumulados: list[dict[str, Any]], tiempos_ms_esta_corrida: list[int],
) -> None:
    validos = [r for r in resultados_acumulados if r.get("error") is None and r.get("clasificacion") is not None]
    correctos = sum(1 for r in validos if (r["clasificacion"] == "phishing") == (r["label_real"] == 1))
    errores = sum(1 for r in resultados_acumulados if r.get("error") is not None)
    accuracy = (correctos / len(validos)) if validos else 0.0
    tiempo_prom = (sum(tiempos_ms_esta_corrida) / len(tiempos_ms_esta_corrida)) if tiempos_ms_esta_corrida else 0.0

    print(f"[{idx}/{total_pendientes}] (+{ya_completados_antes} de corridas previas) "
          f"accuracy acumulada: {accuracy:.4f} ({correctos}/{len(validos)}) | "
          f"errores: {errores} | tiempo promedio/correo: {tiempo_prom:.0f} ms")


def correr(args: argparse.Namespace) -> None:
    sufijo = "_dryrun" if args.dry_run else ""
    results_path = EVAL_SYSTEM_DIR / f"rspamd_results_raw{sufijo}.jsonl"
    metrics_path = EVAL_SYSTEM_DIR / f"rspamd_metrics_final{sufijo}.json"

    filas = leer_csv(args.input)

    # --- Checkpoint: reanudar o empezar de cero ---
    if args.dry_run:
        # Los datos simulados no son progreso real: siempre se regeneran.
        print("[--dry-run] Generando datos simulados, sin llamar a Rspamd.\n")
        resultados_previos: list[dict[str, Any]] = []
        results_path.unlink(missing_ok=True)
    else:
        resultados_previos = cargar_resultados_previos(results_path)
        if resultados_previos:
            reanudar = args.resume
            if reanudar is None:
                reanudar = preguntar_si_reanudar(len(resultados_previos))
            if not reanudar:
                print(f"Empezando de cero: se descarta {results_path.name}")
                resultados_previos = []
                results_path.unlink(missing_ok=True)

    ids_completados = {r["id"] for r in resultados_previos}
    filas_pendientes = [f for f in filas if f["id"] not in ids_completados]
    if args.limite is not None:
        filas_pendientes = filas_pendientes[: args.limite]

    print(f"Correos en el CSV: {len(filas)} | ya completados: {len(ids_completados)} | "
          f"a procesar esta corrida: {len(filas_pendientes)}")

    # --- Envio de cada correo a Rspamd, escribiendo el JSONL en tiempo real ---
    inicio_corrida = datetime.now(timezone.utc)
    resultados_nuevos: list[dict[str, Any]] = []
    tiempos_ms_esta_corrida: list[int] = []

    if filas_pendientes:
        with results_path.open("a", encoding="utf-8") as results_file, requests.Session() as session:
            try:
                for idx, fila in enumerate(filas_pendientes, start=1):
                    if args.dry_run:
                        resultado = resultado_simulado(fila, args.umbral)
                    else:
                        resultado = consultar_rspamd(session, args.url, fila, args.umbral)

                    resultados_nuevos.append(resultado)
                    tiempos_ms_esta_corrida.append(resultado["tiempo_ms"])
                    results_file.write(json.dumps(resultado, ensure_ascii=False) + "\n")
                    results_file.flush()

                    if idx % PROGRESO_CADA_N_CORREOS == 0 or idx == len(filas_pendientes):
                        _imprimir_progreso(
                            idx, len(filas_pendientes), len(ids_completados),
                            resultados_previos + resultados_nuevos, tiempos_ms_esta_corrida,
                        )
            except KeyboardInterrupt:
                print("\nInterrumpido por el usuario. Progreso guardado hasta el ultimo correo completado.")
    else:
        print("Nada por procesar; se recalculan las metricas con lo ya guardado.")

    # --- Metricas agregadas sobre todo lo acumulado (previo + esta corrida) ---
    fin_corrida = datetime.now(timezone.utc)
    todos_los_resultados = resultados_previos + resultados_nuevos
    metricas = calcular_metricas(todos_los_resultados, args.umbral, inicio_corrida, fin_corrida)
    metrics_path.write_text(json.dumps(metricas, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\nResultados por correo: {results_path}")
    print(f"Métricas finales guardadas en: {metrics_path}")
    print(json.dumps(metricas, indent=2, ensure_ascii=False))


# ==========================================================================
# CLI
# ==========================================================================


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT_CSV, help="CSV de entrada (id, label, raw_text)")
    parser.add_argument("--url", default=DEFAULT_URL, help=f"URL base de Rspamd (default: {DEFAULT_URL})")
    parser.add_argument("--umbral", type=float, default=UMBRAL_DEFAULT,
                        help=f"Score de Rspamd a partir del cual se clasifica como phishing (default: {UMBRAL_DEFAULT})")
    parser.add_argument("--limite", type=int, default=None, help="Procesar a lo sumo N filas nuevas en esta corrida")
    parser.add_argument("--dry-run", action="store_true", help="No llama a Rspamd; genera datos simulados")
    resume_group = parser.add_mutually_exclusive_group()
    resume_group.add_argument("--resume", dest="resume", action="store_true", default=None, help="Reanudar sin preguntar")
    resume_group.add_argument("--no-resume", dest="resume", action="store_false", help="Empezar de cero sin preguntar")
    return parser.parse_args()


def main() -> None:
    correr(parse_args())


if __name__ == "__main__":
    main()
