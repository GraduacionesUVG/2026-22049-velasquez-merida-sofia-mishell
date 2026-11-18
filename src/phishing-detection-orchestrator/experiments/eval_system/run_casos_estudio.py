#!/usr/bin/env python
"""Casos de estudio cualitativos: corre el modo explicacion del orquestador
sobre un punado de correos elegidos a partir de la evaluacion en lote.

Lee results_raw.jsonl (evaluacion en modo veredicto) y selecciona:

- 3 TP con mayor puntaje_riesgo y arquetipos distintos entre si.
- 2 FN (label_real=1, clasificacion=legitimo) con mayor puntaje_riesgo.
- 2 FP (label_real=0, clasificacion=phishing) con menor puntaje_riesgo.
- 1 correo con la mayor cantidad de vt_indicadores (que no este ya elegido).

Para cada uno toma el texto desde eval_external.csv, lo escribe en un .txt
temporal y ejecuta "phishing-orchestrator analizar --mode explicacion
--archivo <tmp>.txt" como subproceso (un proceso por correo, igual que si se
corriera a mano). El stdout se guarda en casos_estudio/caso_<id>.txt y al
final queda casos_estudio/index.json con un resumen por caso.

Cada llamada usa la API real de Anthropic y los cuatro servidores MCP
(tipicamente 30-60 s por correo). Los casos que ya salieron bien se saltan,
asi que el script se puede relanzar tras un fallo sin volver a pagarlos. Si
un caso falla, lo que el orquestador haya impreso se guarda igual en
caso_<id>.txt y el diagnostico en caso_<id>.error.txt; ese caso se reintenta
al relanzar.

USO
---
    # Seleccion automatica (~8 correos)
    python run_casos_estudio.py

    # Ver la seleccion sin ejecutar nada (no gasta tokens)
    python run_casos_estudio.py --solo-seleccion

    # IDs especificos
    python run_casos_estudio.py --ids trec_2007_438,phishing_pot_sample-1189

    # Volver a correr casos que ya tienen salida
    python run_casos_estudio.py --forzar
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

_ORCHESTRATOR_ROOT = Path(__file__).resolve().parents[2]
EVAL_SYSTEM_DIR = Path(__file__).resolve().parent

# Mismo limite que run_evaluation.py: hay correos con body mas largo que el
# maximo por defecto del modulo csv, y en Windows sys.maxsize desborda.
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

DEFAULT_RESULTS = EVAL_SYSTEM_DIR / "results_raw.jsonl"
DEFAULT_INPUT_CSV = (
    _ORCHESTRATOR_ROOT.parent
    / "Trabajo-de-Graduacion"
    / "experiments"
    / "external_eval"
    / "eval_external.csv"
)
DEFAULT_OUTPUT_DIR = EVAL_SYSTEM_DIR / "casos_estudio"

N_TP, N_FN, N_FP = 3, 2, 2
TIMEOUT_DEFAULT_S = 300

# Se invoca el mismo entry point que el script de consola
# "phishing-orchestrator" (phishing_orchestrator.cli:main), pero via
# "python -m": el .exe que genera uv para el script de consola puede fallar
# al lanzarse como subproceso desde una ruta con tildes (ver la nota del
# servidor knowledge en config/mcp_servers.yaml).
COMANDO_ORQUESTADOR = [sys.executable, "-m", "phishing_orchestrator.cli"]


# ==========================================================================
# Seleccion de casos
# ==========================================================================


def cargar_resultados(path: Path) -> list[dict[str, Any]]:
    resultados = []
    with path.open("r", encoding="utf-8") as f:
        for linea in f:
            if linea.strip():
                resultados.append(json.loads(linea))
    return resultados


def _categoria(r: dict[str, Any]) -> str:
    """TP/FN/FP/TN segun label_real y la clasificacion del modo veredicto."""
    if r.get("clasificacion") not in ("phishing", "legitimo") or r.get("label_real") not in (0, 1):
        return "N/D"
    predicho_phishing = r["clasificacion"] == "phishing"
    if r["label_real"] == 1:
        return "TP" if predicho_phishing else "FN"
    return "FP" if predicho_phishing else "TN"


def seleccionar_casos(resultados: list[dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
    """Devuelve [(categoria, resultado)] con la seleccion automatica.

    Los empates de puntaje se resuelven por el orden de results_raw.jsonl
    (sorted es estable), asi que la seleccion es reproducible.
    """
    validos = [r for r in resultados if not r.get("error") and r.get("puntaje_riesgo") is not None]
    por_categoria: dict[str, list[dict[str, Any]]] = {"TP": [], "FN": [], "FP": []}
    for r in validos:
        categoria = _categoria(r)
        if categoria in por_categoria:
            por_categoria[categoria].append(r)

    seleccion: list[tuple[str, dict[str, Any]]] = []

    arquetipos_usados: set[str] = set()
    for r in sorted(por_categoria["TP"], key=lambda r: -r["puntaje_riesgo"]):
        arquetipo = r.get("arquetipo_label")
        if arquetipo is None or arquetipo in arquetipos_usados:
            continue
        arquetipos_usados.add(arquetipo)
        seleccion.append(("TP", r))
        if len(arquetipos_usados) == N_TP:
            break

    for r in sorted(por_categoria["FN"], key=lambda r: -r["puntaje_riesgo"])[:N_FN]:
        seleccion.append(("FN", r))

    for r in sorted(por_categoria["FP"], key=lambda r: r["puntaje_riesgo"])[:N_FP]:
        seleccion.append(("FP", r))

    ya_elegidos = {r["id"] for _, r in seleccion}
    candidatos_vt = [r for r in validos if r["id"] not in ya_elegidos and r.get("vt_indicadores")]
    if candidatos_vt:
        seleccion.append(("VT", max(candidatos_vt, key=lambda r: len(r["vt_indicadores"]))))

    return seleccion


def casos_por_ids(ids: list[str], resultados: list[dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
    """Para --ids: la categoria se deriva del resultado en modo veredicto, si existe."""
    por_id = {r["id"]: r for r in resultados}
    casos = []
    for id_ in ids:
        r = por_id.get(id_)
        if r is None:
            print(f"AVISO: '{id_}' no esta en results_raw.jsonl; se corre igual, sin datos del modo veredicto.")
            r = {"id": id_}
        casos.append((_categoria(r), r))
    return casos


# ==========================================================================
# Texto de los correos
# ==========================================================================


def leer_textos(path: Path, ids: set[str], columna_id: str, columna_texto: str) -> dict[str, str]:
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for columna in (columna_id, columna_texto):
            if columna not in (reader.fieldnames or []):
                raise ValueError(f"El CSV de entrada no tiene la columna requerida '{columna}'")
        return {row[columna_id]: row[columna_texto] for row in reader if row[columna_id] in ids}


# ==========================================================================
# Ejecucion
# ==========================================================================


def _nombre_seguro(id_: str) -> str:
    return re.sub(r"[^\w.-]", "_", id_)


def ejecutar_explicacion(texto: str, id_: str, tmp_dir: Path, timeout_s: int) -> tuple[bool, str, str]:
    """Corre el orquestador en modo explicacion sobre un correo.

    Devuelve (ok, stdout, stderr). No lanza excepciones por fallos del
    subproceso: un caso fallido no debe tumbar los demas.
    """
    tmp_path = tmp_dir / f"{_nombre_seguro(id_)}.txt"
    tmp_path.write_text(texto, encoding="utf-8")

    # PYTHONUTF8: sin esto, en Windows el stdout redirigido del subproceso
    # usa cp1252 y el print del JSON revienta con caracteres fuera de esa tabla.
    env = {**os.environ, "PYTHONUTF8": "1"}
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(_ORCHESTRATOR_ROOT / "src"), env.get("PYTHONPATH")]))

    comando = [*COMANDO_ORQUESTADOR, "analizar", "--mode", "explicacion", "--archivo", str(tmp_path)]
    try:
        proceso = subprocess.run(
            comando,
            cwd=_ORCHESTRATOR_ROOT,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
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


def _detalle_error(stdout: str, stderr: str) -> str:
    """Resume el fallo en una linea. Los errores del orquestador salen por
    stdout como {"error": ...}; el resto (config, traceback) por stderr,
    mezclado con los logs, asi que de ahi se toma la ultima linea."""
    try:
        return str(json.loads(stdout)["error"])[:300]
    except (json.JSONDecodeError, KeyError, TypeError):
        pass
    lineas = [linea for linea in (stderr or stdout).strip().splitlines() if linea.strip()]
    return lineas[-1][:300] if lineas else "sin detalle"


def cargar_index(path: Path) -> dict[str, dict[str, Any]]:
    """Indice de corridas anteriores, por id, para no perderlo al correr solo algunos casos con --ids."""
    try:
        return {e["id"]: e for e in json.loads(path.read_text(encoding="utf-8"))}
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        return {}


def escribir_index(path: Path, index: dict[str, dict[str, Any]]) -> None:
    path.write_text(json.dumps(list(index.values()), ensure_ascii=False, indent=2), encoding="utf-8")


def correr(args: argparse.Namespace) -> int:
    resultados = cargar_resultados(args.results) if args.results.exists() else []
    if args.ids:
        casos = casos_por_ids(args.ids, resultados)
    else:
        if not resultados:
            print(f"ERROR: no se encontro {args.results} (o esta vacio); no hay de donde seleccionar casos.")
            return 1
        casos = seleccionar_casos(resultados)

    print(f"Casos seleccionados: {len(casos)}")
    for categoria, r in casos:
        puntaje = r.get("puntaje_riesgo")
        print(
            f"  {categoria:<3} {r['id']:<32} puntaje={'N/D' if puntaje is None else f'{puntaje:.2f}'} "
            f"VT={len(r.get('vt_indicadores') or [])} arquetipo={r.get('arquetipo_label') or '(sin arquetipo)'}"
        )
    if args.solo_seleccion:
        return 0

    if not args.input.exists():
        print(f"ERROR: no se encontro el CSV de correos: {args.input}")
        return 1
    try:
        textos = leer_textos(args.input, {r["id"] for _, r in casos}, args.columna_id, args.columna_texto)
    except ValueError as exc:
        print(f"ERROR: {exc}")
        return 1

    args.output_dir.mkdir(parents=True, exist_ok=True)
    index_path = args.output_dir / "index.json"
    index = cargar_index(index_path)
    n_fallidos = 0
    inicio_total = time.monotonic()

    with tempfile.TemporaryDirectory(prefix="casos_estudio_") as tmp:
        for i, (categoria, r) in enumerate(casos, start=1):
            id_ = r["id"]
            prefijo = f"[{i}/{len(casos)}] {categoria} {id_}"
            salida_path = args.output_dir / f"caso_{_nombre_seguro(id_)}.txt"
            entrada = {
                "id": id_,
                "categoria": categoria,
                "arquetipo": r.get("arquetipo_label"),
                "puntaje_veredicto": r.get("puntaje_riesgo"),
                "path_explicacion": salida_path.relative_to(EVAL_SYSTEM_DIR).as_posix()
                if salida_path.is_relative_to(EVAL_SYSTEM_DIR)
                else str(salida_path),
            }

            error_path = salida_path.with_suffix(".error.txt")

            # Un caso cuenta como hecho solo si tiene salida y no dejo archivo de error.
            if salida_path.exists() and not error_path.exists() and not args.forzar:
                print(f"{prefijo}: ya existe {salida_path.name}, se salta (usa --forzar para repetirlo)")
            elif id_ not in textos:
                print(f"{prefijo}: ERROR, el id no esta en {args.input.name}")
                entrada.update(path_explicacion=None, error=f"id no encontrado en {args.input.name}")
                n_fallidos += 1
            else:
                print(f"{prefijo}: ejecutando modo explicacion...", flush=True)
                inicio = time.monotonic()
                ok, stdout, stderr = ejecutar_explicacion(textos[id_], id_, Path(tmp), args.timeout)
                duracion = time.monotonic() - inicio
                # El stdout se guarda tal cual, sin validarlo, tambien cuando
                # el analisis falla: si el modelo respondio algo, queda legible.
                hay_contenido = bool(stdout.strip())
                if hay_contenido:
                    salida_path.write_text(stdout, encoding="utf-8")
                else:
                    salida_path.unlink(missing_ok=True)

                if ok:
                    error_path.unlink(missing_ok=True)
                    print(f"{prefijo}: listo en {duracion:.1f} s -> {salida_path.name}")
                else:
                    # El archivo de error marca el caso como fallido para que
                    # se reintente al relanzar, aunque ya tenga salida guardada.
                    error_path.write_text(f"--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}", encoding="utf-8")
                    detalle = _detalle_error(stdout, stderr)
                    guardado = f"respuesta guardada en {salida_path.name}, " if hay_contenido else ""
                    print(f"{prefijo}: ERROR tras {duracion:.1f} s: {detalle} ({guardado}detalle en {error_path.name})")
                    entrada["error"] = detalle
                    if not hay_contenido:
                        entrada["path_explicacion"] = None
                    n_fallidos += 1

            index[id_] = entrada
            # Se reescribe en cada caso para no perder el indice si se interrumpe la corrida.
            escribir_index(index_path, index)

    total = time.monotonic() - inicio_total
    print(f"\nTerminado en {total:.0f} s: {len(casos) - n_fallidos} de {len(casos)} casos con explicacion, {n_fallidos} con error.")
    print(f"Indice: {index_path}")
    return 1 if n_fallidos else 0


# ==========================================================================
# CLI
# ==========================================================================


def _lista_ids(valor: str) -> list[str]:
    ids = [v.strip() for v in valor.split(",") if v.strip()]
    if not ids:
        raise argparse.ArgumentTypeError("--ids necesita al menos un id")
    return list(dict.fromkeys(ids))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ids", type=_lista_ids, default=None, help="IDs separados por comas; reemplaza la seleccion automatica")
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS, help="results_raw.jsonl de la evaluacion en modo veredicto")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT_CSV, help="CSV con el texto de los correos (eval_external.csv)")
    parser.add_argument("--columna-id", default="id")
    parser.add_argument("--columna-texto", default="body", help="Columna con el texto del correo (la misma que uso run_evaluation.py)")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--timeout", type=int, default=TIMEOUT_DEFAULT_S, help="Segundos maximos por correo")
    parser.add_argument("--forzar", action="store_true", help="Repite los casos que ya tienen archivo de salida")
    parser.add_argument("--solo-seleccion", action="store_true", help="Muestra los casos elegidos y termina, sin gastar tokens")
    return parser.parse_args()


def main() -> None:
    try:
        sys.exit(correr(parse_args()))
    except KeyboardInterrupt:
        print("\nInterrumpido. Los casos ya guardados se conservan; al relanzar se saltan.")
        sys.exit(130)


if __name__ == "__main__":
    main()
