#!/usr/bin/env python3
"""Evaluacion del orquestador en modo EXPLICACION (todos los servidores MCP)
sobre la submuestra de 100 correos (experiments/external_eval/eval_external_100.csv:
50 phishing de Phishing Pot + 50 legitimos de TREC 2007).

QUE HACE
--------
Para cada correo escribe su texto en un .txt temporal y ejecuta el CLI del
orquestador como subproceso (un proceso por correo, igual que
run_casos_estudio.py del repo phishing-detection-orchestrator):

    python -m phishing_orchestrator.cli analizar --mode explicacion --archivo <tmp.txt>

El JSON que imprime el CLI se parsea y se guarda una linea por correo en
results_explicacion_100.jsonl, con el mismo esquema que results_raw.jsonl
(evaluacion en modo veredicto) mas: senales_count, senales, explicacion,
herramientas_invocadas, rspamd_score y rspamd_action (estos dos por lookup
de id en rspamd_results_raw.jsonl).

Campos que el CLI NO expone y por tanto no se pueden llenar igual que en
results_raw.jsonl:
- input_tokens, output_tokens, costo_usd: quedan en null (desconocidos).
- vt_indicadores, vt_resultados: quedan vacios; que herramientas de
  VirusTotal se llamaron esta en herramientas_invocadas.
- arquetipo_id: se extrae del texto de las senales del servidor archetype
  ("arquetipo 13"); arquetipo_label se resuelve con el mapa id -> label de
  results_raw.jsonl. Si no se puede, quedan en null.

Es REANUDABLE: los correos que ya estan en el JSONL se saltan. Los que
fallan NO se escriben en el JSONL (van a results_explicacion_100_errores.jsonl),
asi que se reintentan al relanzar.

Cada correo usa la API real de Anthropic y los cuatro servidores MCP
(tipicamente 30-60 s y varios centavos por correo).

USO
---
    python run_eval_explicacion_100.py
    python run_eval_explicacion_100.py --limite 2     # probar con 2 correos
    python run_eval_explicacion_100.py --orquestador "C:\\ruta\\phishing-detection-orchestrator"
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

EVAL_SYSTEM_DIR = Path(__file__).resolve().parent
EXPERIMENTS_DIR = EVAL_SYSTEM_DIR.parent
REPO_ROOT = EXPERIMENTS_DIR.parent

# Mismo limite que run_evaluation.py: hay correos con body mas largo que el
# maximo por defecto del modulo csv, y en Windows sys.maxsize desborda.
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))


# ==========================================================================
# Configuracion
# ==========================================================================

DEFAULT_INPUT_CSV = EXPERIMENTS_DIR / "external_eval" / "eval_external_100.csv"
DEFAULT_OUTPUT = EVAL_SYSTEM_DIR / "results_explicacion_100.jsonl"
DEFAULT_ORQUESTADOR = REPO_ROOT.parent / "phishing-detection-orchestrator"
RSPAMD_RESULTS = EVAL_SYSTEM_DIR / "rspamd_results_raw.jsonl"

# results_raw.jsonl del modo veredicto: solo se usa para el mapa
# arquetipo_id -> arquetipo_label. Se busca en este repo y en el orquestador.
CANDIDATOS_RESULTS_RAW = [
    EXPERIMENTS_DIR / "data" / "results_raw.jsonl",
    REPO_ROOT / "data" / "results_raw.jsonl",
    DEFAULT_ORQUESTADOR / "experiments" / "eval_system" / "results_raw.jsonl",
]

MODO = "explicacion"
TIMEOUT_DEFAULT_S = 900  # VirusTotal va limitado a 4 llamadas/min: un correo con muchas URLs pasa de 5 min
RE_ARQUETIPO_ID = re.compile(r"arquetipo\s*#?\s*(\d+)", re.IGNORECASE)
# Textos con los que VirusTotal avisa de cuota agotada (plan gratuito: 4 consultas
# por minuto y 500 al dia). Son las mismas claves que usa batch.py del orquestador.
CLAVES_CUOTA_VT = ("quota", "rate limit", "too many requests", "daily", "exceeded", "limit")
# Ante un error de cuota se espera y se reintenta una vez, para distinguir el
# limite por minuto (se recupera solo) de la cuota diaria (hay que parar).
ESPERA_CUOTA_VT_S = 90


# ==========================================================================
# Lectura de entradas y de resultados previos
# ==========================================================================


def leer_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    filas = []
    with path.open("r", encoding="utf-8") as f:
        for linea in f:
            linea = linea.strip()
            if not linea:
                continue
            try:
                filas.append(json.loads(linea))
            except json.JSONDecodeError:
                continue
    return filas


def leer_csv(path: Path, columna_texto: str) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for columna in ("id", "label", columna_texto):
            if columna not in (reader.fieldnames or []):
                raise ValueError(f"El CSV de entrada no tiene la columna requerida '{columna}'")
        return [{"id": row["id"], "label": int(row["label"]), "texto": row[columna_texto]} for row in reader]


def cargar_lookup_rspamd(path: Path) -> dict[str, dict[str, Any]]:
    return {r["id"]: r for r in leer_jsonl(path) if "id" in r}


def cargar_mapa_arquetipos() -> dict[int, str]:
    """arquetipo_id -> arquetipo_label, tomado de la evaluacion en modo veredicto."""
    for path in CANDIDATOS_RESULTS_RAW:
        mapa = {
            int(r["arquetipo_id"]): r["arquetipo_label"]
            for r in leer_jsonl(path)
            if r.get("arquetipo_id") is not None and r.get("arquetipo_label")
        }
        if mapa:
            return mapa
    return {}


# ==========================================================================
# Ejecucion del orquestador (un subproceso por correo)
# ==========================================================================


def python_del_orquestador(orquestador: Path) -> str:
    """El orquestador necesita sus propias dependencias (anthropic, mcp):
    se usa el Python de su .venv si existe; si no, el actual."""
    for candidato in (orquestador / ".venv" / "Scripts" / "python.exe", orquestador / ".venv" / "bin" / "python"):
        if candidato.exists():
            return str(candidato)
    return sys.executable


def ejecutar_explicacion(
    texto: str, id_: str, tmp_dir: Path, orquestador: Path, python: str, timeout_s: int,
) -> tuple[bool, str, str]:
    """Corre el CLI en modo explicacion sobre un correo. Devuelve
    (ok, stdout, stderr); no lanza excepciones por fallos del subproceso."""
    nombre_seguro = re.sub(r"[^\w.-]", "_", id_)
    tmp_path = tmp_dir / f"{nombre_seguro}.txt"
    tmp_path.write_text(texto, encoding="utf-8")

    # PYTHONUTF8: sin esto, en Windows el stdout redirigido del subproceso
    # usa cp1252 y el print del JSON revienta con caracteres fuera de esa tabla.
    env = {**os.environ, "PYTHONUTF8": "1"}
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(orquestador / "src"), env.get("PYTHONPATH")]))

    comando = [python, "-m", "phishing_orchestrator.cli", "analizar", "--mode", MODO, "--archivo", str(tmp_path)]
    try:
        proceso = subprocess.run(
            comando, cwd=orquestador, env=env, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout_s,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
        stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", "replace")
        return False, stdout, f"{stderr}\nTIMEOUT: el analisis supero {timeout_s} s"
    except OSError as exc:
        return False, "", f"No se pudo lanzar el orquestador: {exc}"
    finally:
        tmp_path.unlink(missing_ok=True)

    return proceso.returncode == 0, proceso.stdout, proceso.stderr


def detalle_error(stdout: str, stderr: str) -> str:
    """Resume el fallo en una linea. Los errores del orquestador salen por
    stdout como {"error": ...}; el resto (config, traceback) por stderr."""
    try:
        return str(json.loads(stdout)["error"])[:300]
    except (json.JSONDecodeError, KeyError, TypeError):
        pass
    lineas = [linea for linea in (stderr or stdout).strip().splitlines() if linea.strip()]
    return lineas[-1][:300] if lineas else "sin detalle"


# ==========================================================================
# Parseo de la salida del CLI -> fila del JSONL
# ==========================================================================


def extraer_arquetipo(senales: list[dict[str, Any]], mapa_arquetipos: dict[int, str]) -> tuple[int | None, str | None]:
    for senal in senales:
        if str(senal.get("servidor", "")).lower() != "archetype":
            continue
        m = RE_ARQUETIPO_ID.search(f"{senal.get('descripcion', '')} {senal.get('evidencia', '')}")
        if m:
            arquetipo_id = int(m.group(1))
            return arquetipo_id, mapa_arquetipos.get(arquetipo_id)
    return None, None


def construir_fila(
    fila: dict[str, Any], stdout: str, tiempo_ms: int,
    rspamd: dict[str, dict[str, Any]], mapa_arquetipos: dict[int, str],
) -> dict[str, Any]:
    """Convierte el JSON del CLI (OrchestratorRunResult) al esquema de
    results_raw.jsonl mas los campos del modo explicacion. Lanza ValueError
    si la salida no tiene la forma esperada."""
    try:
        salida = json.loads(stdout)
        resultado = salida["resultado"]
        clasificacion = resultado["clasificacion"]
        puntaje_riesgo = float(resultado["puntaje_riesgo"])
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"Salida del CLI no parseable ({type(exc).__name__}: {exc})") from exc
    if clasificacion not in ("phishing", "legitimo"):
        raise ValueError(f"clasificacion inesperada: {clasificacion!r}")

    senales = resultado.get("senales") or []
    arquetipo_id, arquetipo_label = extraer_arquetipo(senales, mapa_arquetipos)
    r = rspamd.get(fila["id"], {})

    return {
        "id": fila["id"],
        "label_real": fila["label"],
        "clasificacion": clasificacion,
        "puntaje_riesgo": puntaje_riesgo,
        "arquetipo_id": arquetipo_id,
        "arquetipo_label": arquetipo_label,
        "vt_indicadores": [],
        "vt_resultados": {},
        "input_tokens": None,
        "output_tokens": None,
        "costo_usd": None,
        "tiempo_ms": tiempo_ms,
        "error": None,
        "rspamd_score": r.get("rspamd_score"),
        "rspamd_action": r.get("rspamd_action"),
        "senales_count": len(senales),
        "senales": senales,
        "explicacion": resultado.get("explicacion"),
        "herramientas_invocadas": salida.get("herramientas_invocadas") or [],
    }


def cuota_virustotal_agotada(resultado: dict[str, Any]) -> bool:
    """True si alguna consulta a VirusTotal de este correo fallo por cuota."""
    for llamada in resultado["herramientas_invocadas"]:
        if llamada.get("servidor") != "virustotal" or llamada.get("ok"):
            continue
        error = str(llamada.get("error") or "").lower()
        if any(clave in error for clave in CLAVES_CUOTA_VT):
            return True
    return False


# ==========================================================================
# Metricas rapidas
# ==========================================================================


def imprimir_metricas(resultados: list[dict[str, Any]]) -> None:
    tp = sum(1 for r in resultados if r["clasificacion"] == "phishing" and r["label_real"] == 1)
    tn = sum(1 for r in resultados if r["clasificacion"] == "legitimo" and r["label_real"] == 0)
    fp = sum(1 for r in resultados if r["clasificacion"] == "phishing" and r["label_real"] == 0)
    fn = sum(1 for r in resultados if r["clasificacion"] == "legitimo" and r["label_real"] == 1)
    n = tp + tn + fp + fn

    def fmt(valor: float | None) -> str:
        return "N/D" if valor is None else f"{valor:.4f}"

    accuracy = (tp + tn) / n if n else None
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)) if (precision and recall) else None

    print(f"\n=== Métricas rápidas (modo {MODO}, {n} correos) ===")
    print(f"TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"Accuracy:  {fmt(accuracy)}")
    print(f"Precision: {fmt(precision)}")
    print(f"Recall:    {fmt(recall)}")
    print(f"F1:        {fmt(f1)}")


# ==========================================================================
# Bucle principal
# ==========================================================================


def correr(args: argparse.Namespace) -> int:
    if not args.input.exists():
        print(f"ERROR: no se encontro {args.input}. Generalo con experiments/external_eval/build_eval_external_100.py")
        return 1
    if not (args.orquestador / "src" / "phishing_orchestrator").exists():
        print(f"ERROR: no se encontro el orquestador en {args.orquestador} (usa --orquestador)")
        return 1

    filas = leer_csv(args.input, args.columna_texto)
    errores_path = args.output.with_name(f"{args.output.stem}_errores.jsonl")

    # --- Reanudacion: los ids ya presentes en el JSONL se saltan ---
    resultados = [r for r in leer_jsonl(args.output) if "id" in r]
    ids_completados = {r["id"] for r in resultados}
    pendientes = [f for f in filas if f["id"] not in ids_completados]
    if args.limite is not None:
        pendientes = pendientes[: args.limite]

    rspamd = cargar_lookup_rspamd(RSPAMD_RESULTS)
    mapa_arquetipos = cargar_mapa_arquetipos()
    python = python_del_orquestador(args.orquestador)

    print(f"Correos en el CSV: {len(filas)} | ya completados: {len(ids_completados)} | a procesar: {len(pendientes)}")
    print(f"Orquestador: {args.orquestador}\nPython:      {python}")
    if not rspamd:
        print(f"AVISO: no se encontro {RSPAMD_RESULTS.name}; rspamd_score y rspamd_action quedaran en null.")
    if not mapa_arquetipos:
        print("AVISO: no se encontro results_raw.jsonl; arquetipo_label quedara en null.")

    n_fallidos = 0
    cuota_agotada = False
    inicio_total = time.monotonic()

    if pendientes:
        with tempfile.TemporaryDirectory(prefix="eval_explicacion_") as tmp, \
                args.output.open("a", encoding="utf-8") as out, \
                errores_path.open("a", encoding="utf-8") as out_errores:
            try:
                for i, fila in enumerate(pendientes, start=1):
                    prefijo = f"[{i}/{len(pendientes)}] {fila['id']}"
                    real = "phishing" if fila["label"] == 1 else "legitimo"

                    for intento in (1, 2):
                        t0 = time.monotonic()
                        ok, stdout, stderr = ejecutar_explicacion(
                            fila["texto"], fila["id"], Path(tmp), args.orquestador, python, args.timeout,
                        )
                        tiempo_ms = int((time.monotonic() - t0) * 1000)

                        error = None
                        if ok:
                            try:
                                resultado = construir_fila(fila, stdout, tiempo_ms, rspamd, mapa_arquetipos)
                            except ValueError as exc:
                                error = str(exc)
                        else:
                            error = detalle_error(stdout, stderr)

                        if error is not None or not cuota_virustotal_agotada(resultado) or intento == 2:
                            break
                        print(f"{prefijo}: VirusTotal respondio con error de cuota; se espera "
                              f"{ESPERA_CUOTA_VT_S} s y se reintenta.", flush=True)
                        time.sleep(ESPERA_CUOTA_VT_S)

                    if error is not None:
                        # No se escribe en el JSONL principal: asi el correo se reintenta al relanzar.
                        n_fallidos += 1
                        registro = {"id": fila["id"], "label_real": fila["label"], "tiempo_ms": tiempo_ms,
                                    "error": error, "stdout": stdout[-2000:], "stderr": stderr[-2000:]}
                        out_errores.write(json.dumps(registro, ensure_ascii=False) + "\n")
                        out_errores.flush()
                        print(f"{prefijo}: ERROR tras {tiempo_ms / 1000:.1f} s: {error}", flush=True)
                        continue

                    if cuota_virustotal_agotada(resultado):
                        # No se guarda: el correo se evaluo sin VirusTotal y debe repetirse con cuota.
                        cuota_agotada = True
                        print(f"{prefijo}: cuota diaria de VirusTotal agotada. Se detiene la corrida sin "
                              "guardar este correo.", flush=True)
                        break

                    resultados.append(resultado)
                    out.write(json.dumps(resultado, ensure_ascii=False) + "\n")
                    out.flush()
                    acierto = "OK " if resultado["clasificacion"] == real else "MAL"
                    print(
                        f"{prefijo}: {tiempo_ms / 1000:5.1f} s | real={real:<8} pred={resultado['clasificacion']:<8} "
                        f"{acierto} | puntaje={resultado['puntaje_riesgo']:.2f} | señales={resultado['senales_count']}",
                        flush=True,
                    )
            except KeyboardInterrupt:
                print("\nInterrumpido. Los correos ya guardados se conservan; al relanzar se saltan.")
    else:
        print("Nada por procesar.")

    total = time.monotonic() - inicio_total
    print(f"\nTerminado en {total:.0f} s: {len(resultados)} de {len(filas)} correos con resultado, "
          f"{n_fallidos} fallidos en esta corrida.")
    print(f"Resultados: {args.output}")
    if n_fallidos:
        print(f"Errores:    {errores_path} (los correos fallidos se reintentan al relanzar)")
    elif errores_path.exists() and errores_path.stat().st_size == 0:
        errores_path.unlink()

    if resultados:
        imprimir_metricas(resultados)
    if cuota_agotada:
        print(f"\nSe agoto la cuota diaria de VirusTotal: faltan {len(filas) - len(resultados)} correos. "
              "Relanzar el mismo comando cuando se renueve (00:00 UTC) para continuar.")
    return 1 if n_fallidos else 0


# ==========================================================================
# CLI
# ==========================================================================


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT_CSV, help="CSV de entrada (eval_external_100.csv)")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="JSONL de resultados")
    parser.add_argument("--columna-texto", default="body", help="Columna con el texto del correo (la misma que uso run_evaluation.py)")
    parser.add_argument("--orquestador", type=Path, default=DEFAULT_ORQUESTADOR, help="Raiz del repo phishing-detection-orchestrator")
    parser.add_argument("--timeout", type=int, default=TIMEOUT_DEFAULT_S, help="Segundos maximos por correo")
    parser.add_argument("--limite", type=int, default=None, help="Procesar a lo sumo N correos nuevos en esta corrida")
    return parser.parse_args()


def main() -> None:
    sys.exit(correr(parse_args()))


if __name__ == "__main__":
    main()
