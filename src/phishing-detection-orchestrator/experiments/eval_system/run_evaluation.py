#!/usr/bin/env python3
"""Evaluacion en lote del orquestador (modo veredicto, archetype+virustotal)
sobre un CSV externo de correos etiquetados (pensado para
experiments/external_eval/eval_external.csv del repo de la tesis: 1,000
correos, 500 phishing de Phishing Pot + 500 legitimos de TREC 2007).

QUE HACE
--------
Para cada fila del CSV de entrada (columnas por defecto: id, body, label),
llama al orquestador real (phishing_orchestrator.orchestrator.run_analysis,
modo "veredicto", solo servidores MCP archetype + virustotal -- ver
experiments/README.md del repo de la tesis para el porque de esa eleccion),
y registra: clasificacion, puntaje de riesgo, arquetipo asignado, que
indicadores de red se consultaron contra VirusTotal y con que resultado,
tokens de entrada/salida reales de la API de Anthropic, costo estimado
(precios de Claude Haiku 4.5: $1.00/M input, $5.00/M output) y tiempo por
correo.

Es CHECKPOINTEADO Y REANUDABLE: si se interrumpe (Ctrl+C, se agota la cuota
diaria de VirusTotal, un corte de red), correr el script de nuevo continua
donde quedo, sin repetir correos ya completados.

COMO USARLO
-----------
    # Primera corrida (o reanudar una interrumpida; pregunta si hay
    # checkpoint previo, salvo que se pase --resume o --no-resume)
    python run_evaluation.py

    # Probar el script sin gastar tokens ni tocar VirusTotal/Anthropic:
    # procesa 5 filas con datos simulados, ejercitando todo el pipeline de
    # logging/checkpoint/JSONL/metricas.
    python run_evaluation.py --dry-run

    # Limitar cuantas filas NUEVAS procesa esta corrida (utils para probar)
    python run_evaluation.py --limite 20

    # Usar otro CSV de entrada / otras columnas
    python run_evaluation.py --input otro.csv --columna-texto text_clean --columna-label label --columna-id id

Requiere las mismas variables de entorno que el resto del orquestador (ver
README.md del proyecto: ANTHROPIC_API_KEY, VIRUSTOTAL_API_KEY,
PATTERN_ARCHETYPE_MCP_PATH, etc. en .env). --dry-run no las necesita.

ARCHIVOS QUE GENERA (todos en este mismo directorio, experiments/eval_system/)
--------------------------------------------------------------------------
- checkpoint.json       Estado minimo para reanudar (contador de llamadas a
                         VirusTotal "de hoy" y su fecha; la lista de correos
                         ya completados se deriva de results_raw.jsonl, no
                         se duplica aqui, para que ambos archivos no puedan
                         quedar desincronizados entre si).
- evaluation.log         Un bloque de lineas por correo (ver formato abajo),
                         agregado en tiempo real, no solo al terminar.
- evaluation_errors.log  Subconjunto del anterior: solo las lineas de error.
- results_raw.jsonl      Un objeto JSON por linea, uno por correo procesado
                         (ver schema en CorreoResultado.to_dict()).
- metrics_final.json     Metricas agregadas de toda la corrida acumulada
                         hasta el momento (se reescribe cada vez que el
                         script termina, incluyendo al reanudar).

Con --dry-run, los mismos archivos se escriben con sufijo "_dryrun" (ej.
checkpoint_dryrun.json) para nunca pisar el progreso de una corrida real.

FORMATO DE evaluation.log POR CORREO
-------------------------------------
    [TIMESTAMP] [ID] Iniciando analisis
    [TIMESTAMP] [ID] Arquetipo: #X - Label
    [TIMESTAMP] [ID] VT: N indicadores encontrados, consultando...
    [TIMESTAMP] [ID] VT: dominio.com -> score X (clean/malicious)
    [TIMESTAMP] [ID] Clasificacion: phishing/legitimo | Score: 0.XX
    [TIMESTAMP] [ID] Tokens: input=X output=X costo=$X
    [TIMESTAMP] [ID] Completado en Xs
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import logging
import math
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# --- Hacer importable el paquete del orquestador (src/phishing_orchestrator)
# sin necesidad de instalar el proyecto en modo editable para correr este
# script suelto desde experiments/eval_system/. ---
_ORCHESTRATOR_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ORCHESTRATOR_ROOT / "src"))

# Algunos correos de eval_external.csv (body largo, ej. Phishing Pot)
# superan el limite por defecto del modulo csv (131072 caracteres por
# campo). min(...) porque en Windows el 'long' de C es de 32 bits: pasar
# sys.maxsize directo (64 bits) revienta con OverflowError.
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

from anthropic import AsyncAnthropic  # noqa: E402

from phishing_orchestrator import config  # noqa: E402
from phishing_orchestrator.batch import _is_probable_quota_error  # noqa: E402
from phishing_orchestrator.extraction import extract_network_indicators  # noqa: E402
from phishing_orchestrator.mcp_client import MCPClientManager  # noqa: E402
from phishing_orchestrator.orchestrator import OrchestratorError, run_analysis  # noqa: E402

# ==========================================================================
# Configuracion
# ==========================================================================

EVAL_SYSTEM_DIR = Path(__file__).resolve().parent

DEFAULT_INPUT_CSV = (
    _ORCHESTRATOR_ROOT.parent
    / "Trabajo-de-Graduacion"
    / "experiments"
    / "external_eval"
    / "eval_external.csv"
)

# Precios reales de Claude Haiku 4.5 (input/output por millon de tokens).
PRECIO_INPUT_POR_M = 1.00
PRECIO_OUTPUT_POR_M = 5.00

# Cuota diaria "nominal" del plan gratuito de VirusTotal, solo para mostrar
# "usadas/limite" en el resumen de progreso -- el script NO puede leer la
# cuota real restante desde la API (VirusTotal no la expone via este MCP),
# asi que este numero es el contador de llamadas hechas por este script
# hoy, no una lectura oficial de VT. El limite por minuto (4/min) ya se
# respeta automaticamente dentro de MCPClientManager, no hace falta nada
# aqui para eso.
VT_CUOTA_DIARIA_NOMINAL = 500

PROGRESO_CADA_N_CORREOS = 10

MODO = "veredicto"
SERVIDORES_MCP = ("archetype", "virustotal")
MAX_ITERATIONS_DEFAULT = 4


# ==========================================================================
# Resultado por correo
# ==========================================================================


@dataclass
class CorreoResultado:
    id: str
    label_real: int | None
    clasificacion: str | None
    puntaje_riesgo: float | None
    arquetipo_id: int | None
    arquetipo_label: str | None
    vt_indicadores: list[str] = field(default_factory=list)
    vt_resultados: dict[str, str] = field(default_factory=dict)
    input_tokens: int = 0
    output_tokens: int = 0
    costo_usd: float = 0.0
    tiempo_ms: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ==========================================================================
# Envoltorios para capturar datos reales que el orquestador no expone en su
# resultado estructurado final (OrchestratorRunResult no incluye el payload
# de cada tool call, solo si tuvo exito -- ver schemas.ToolInvocation). Se
# usan tanto en corridas reales como (con datos fabricados) en --dry-run.
# ==========================================================================


class UsageTrackingAnthropic:
    """Envuelve AsyncAnthropic para acumular tokens reales de la API por
    correo, sin modificar phishing_orchestrator.orchestrator."""

    def __init__(self, real_client: AsyncAnthropic) -> None:
        self._real = real_client
        self.messages = self
        self.total_input_tokens = 0
        self.total_output_tokens = 0

    async def create(self, **kwargs: Any) -> Any:
        response = await self._real.messages.create(**kwargs)
        self.total_input_tokens += response.usage.input_tokens
        self.total_output_tokens += response.usage.output_tokens
        return response

    def reset(self) -> None:
        self.total_input_tokens = 0
        self.total_output_tokens = 0


class ResultCapturingMCPClient:
    """Envuelve MCPClientManager para capturar, ademas de si cada tool call
    tuvo exito (lo unico que guarda el orquestador), el contenido real de
    las respuestas de archetype y virustotal -- necesario para poblar
    arquetipo_id/arquetipo_label/vt_resultados en CorreoResultado."""

    def __init__(self, real_client: MCPClientManager) -> None:
        self._real = real_client
        self.archetype_result: dict[str, Any] | None = None
        self.vt_resultados: dict[str, str] = {}
        self.vt_error: str | None = None

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    async def call_tool(self, qualified_name: str, arguments: dict[str, Any], **kwargs: Any) -> Any:
        result = await self._real.call_tool(qualified_name, arguments, **kwargs)

        if qualified_name == "archetype__classify_archetype" and result.ok:
            self.archetype_result = result.data

        elif qualified_name.startswith("virustotal__"):
            objetivo = arguments.get("url") or arguments.get("domain") or arguments.get("ip") or qualified_name
            if result.ok:
                veredicto_vt = _resumir_veredicto_vt(result.data)
                self.vt_resultados[objetivo] = veredicto_vt
            else:
                self.vt_resultados[objetivo] = f"error: {result.error}"
                if result.error and _is_probable_quota_error(result.error):
                    self.vt_error = result.error

        return result

    def reset(self) -> None:
        self.archetype_result = None
        self.vt_resultados = {}
        self.vt_error = None


def _resumir_veredicto_vt(data: Any) -> str:
    """Reduce la respuesta cruda de VirusTotal a 'clean' o 'malicious (N)',
    para el log y para vt_resultados. VT no tiene un campo unico de
    veredicto; se deriva de last_analysis_stats, igual que hace cualquier
    integracion tipica de VT."""
    try:
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
        return f"malicious ({malicious})" if malicious > 0 else "clean"
    except (KeyError, TypeError, ValueError):
        return "clean"  # respuesta con forma inesperada: no se puede afirmar riesgo, se reporta neutro


# ==========================================================================
# Logging
# ==========================================================================


def configurar_logging(log_path: Path, errors_log_path: Path) -> logging.Logger:
    logger = logging.getLogger("eval_system")
    logger.setLevel(logging.INFO)
    logger.propagate = False  # no duplicar en el logger raiz / consola

    formatter = logging.Formatter("[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    handler_general = logging.FileHandler(log_path, encoding="utf-8")
    handler_general.setLevel(logging.INFO)
    handler_general.setFormatter(formatter)
    logger.addHandler(handler_general)

    handler_errores = logging.FileHandler(errors_log_path, encoding="utf-8")
    handler_errores.setLevel(logging.ERROR)
    handler_errores.setFormatter(formatter)
    logger.addHandler(handler_errores)

    return logger


# ==========================================================================
# Checkpoint
# ==========================================================================


def cargar_ids_completados(results_path: Path) -> set[str]:
    """La fuente de verdad de que correos ya se completaron es
    results_raw.jsonl (una linea por correo ya procesado), no checkpoint.json
    -- asi los dos archivos no se pueden desincronizar entre si."""
    if not results_path.exists():
        return set()
    ids: set[str] = set()
    with results_path.open("r", encoding="utf-8") as f:
        for linea in f:
            linea = linea.strip()
            if not linea:
                continue
            try:
                ids.add(json.loads(linea)["id"])
            except (json.JSONDecodeError, KeyError):
                continue
    return ids


def cargar_checkpoint(checkpoint_path: Path) -> dict[str, Any]:
    if not checkpoint_path.exists():
        return {}
    try:
        return json.loads(checkpoint_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def guardar_checkpoint(checkpoint_path: Path, estado: dict[str, Any]) -> None:
    checkpoint_path.write_text(json.dumps(estado, indent=2, ensure_ascii=False), encoding="utf-8")


def vt_calls_hoy(checkpoint: dict[str, Any]) -> int:
    """Contador de llamadas a VT hechas por ESTE script hoy (no una lectura
    real de cuota de VT, ver aviso junto a VT_CUOTA_DIARIA_NOMINAL). Se
    reinicia solo si cambio la fecha desde la ultima actualizacion."""
    hoy = datetime.now().strftime("%Y-%m-%d")
    if checkpoint.get("vt_calls_fecha") != hoy:
        return 0
    return int(checkpoint.get("vt_calls_hoy", 0))


def preguntar_si_reanudar(n_completados: int) -> bool:
    print(f"\nSe encontro un checkpoint con {n_completados} correos ya completados.")
    respuesta = input("¿Reanudar desde donde quedo? [S/n]: ").strip().lower()
    return respuesta in ("", "s", "si", "sí", "y", "yes")


# ==========================================================================
# Metricas
# ==========================================================================


def _auc_roc(y_true: list[int], scores: list[float]) -> float | None:
    """AUC-ROC via suma de rangos (equivalente al estadistico de
    Mann-Whitney). Implementado a mano para no agregar numpy/scikit-learn
    como dependencia solo para esta metrica."""
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


def _git_commit_hash() -> str:
    try:
        salida = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=_ORCHESTRATOR_ROOT,
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        return salida.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return "desconocido (no se pudo leer con git rev-parse HEAD)"


def calcular_metricas(resultados: list[CorreoResultado], inicio: datetime, fin: datetime) -> dict[str, Any]:
    validos = [r for r in resultados if r.error is None and r.label_real is not None and r.clasificacion is not None]

    tp = sum(1 for r in validos if r.clasificacion == "phishing" and r.label_real == 1)
    tn = sum(1 for r in validos if r.clasificacion == "legitimo" and r.label_real == 0)
    fp = sum(1 for r in validos if r.clasificacion == "phishing" and r.label_real == 0)
    fn = sum(1 for r in validos if r.clasificacion == "legitimo" and r.label_real == 1)

    n = tp + tn + fp + fn
    accuracy = (tp + tn) / n if n else None
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)) if (precision and recall and (precision + recall) > 0) else None
    fnr = fn / (fn + tp) if (fn + tp) else None

    denom_mcc = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn - fp * fn) / denom_mcc) if denom_mcc else None

    con_score = [r for r in validos if r.puntaje_riesgo is not None]
    auc = _auc_roc([r.label_real for r in con_score], [r.puntaje_riesgo for r in con_score]) if con_score else None

    phishing_reales = [r for r in resultados if r.label_real == 1]
    con_arquetipo = sum(1 for r in phishing_reales if r.arquetipo_id is not None)
    cobertura_arquetipo = (con_arquetipo / len(phishing_reales)) if phishing_reales else None

    return {
        "timestamp_inicio": inicio.isoformat(),
        "timestamp_fin": fin.isoformat(),
        "tiempo_total_segundos": round((fin - inicio).total_seconds(), 1),
        "git_commit_hash": _git_commit_hash(),
        "n_correos_total": len(resultados),
        "n_correos_validos_para_metricas": n,
        "n_correos_con_error": sum(1 for r in resultados if r.error is not None),
        "matriz_confusion": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "auc_roc": auc,
        "mcc": mcc,
        "fnr": fnr,
        "cobertura_senales_ingenieria_social": {
            "descripcion": "%% de correos phishing (label_real=1) donde el arquetipo se pudo asignar (arquetipo_id != None)",
            "n_phishing_reales": len(phishing_reales),
            "n_con_arquetipo_asignado": con_arquetipo,
            "cobertura": cobertura_arquetipo,
        },
        "costo_total_usd": round(sum(r.costo_usd for r in resultados), 6),
        "tokens_input_total": sum(r.input_tokens for r in resultados),
        "tokens_output_total": sum(r.output_tokens for r in resultados),
    }


# ==========================================================================
# Dry-run: fabrica resultados sin tocar Anthropic, MCP ni VirusTotal
# ==========================================================================


def resultado_simulado(id_: str, label_real: int, texto: str) -> CorreoResultado:
    """Genera un CorreoResultado con datos plausibles pero inventados, para
    --dry-run. No llama a ningun servicio real. Los "indicadores VT" se
    calculan con la funcion REAL de extraction.py (es local y gratis, no
    hace ninguna llamada de red) para que el ejemplo de log sea realista."""
    indicadores = extract_network_indicators(texto)
    objetivos = (indicadores.urls + indicadores.domains + indicadores.ips)[:3]  # tope solo para el ejemplo
    vt_resultados = {obj: ("malicious (2)" if label_real == 1 else "clean") for obj in objetivos}

    return CorreoResultado(
        id=id_,
        label_real=label_real,
        clasificacion="phishing" if label_real == 1 else "legitimo",
        puntaje_riesgo=0.87 if label_real == 1 else 0.08,
        arquetipo_id=13 if label_real == 1 else 3,
        arquetipo_label=(
            "Phishing de verificacion y suspension de cuenta (SIMULADO)"
            if label_real == 1
            else "Correo administrativo/tecnico sin senales de phishing (SIMULADO)"
        ),
        vt_indicadores=objetivos,
        vt_resultados=vt_resultados,
        input_tokens=9500,
        output_tokens=650,
        costo_usd=round((9500 / 1e6) * PRECIO_INPUT_POR_M + (650 / 1e6) * PRECIO_OUTPUT_POR_M, 6),
        tiempo_ms=1200,
        error=None,
    )


# ==========================================================================
# Procesamiento de un correo (corrida real)
# ==========================================================================


async def procesar_correo_real(
    id_: str,
    texto: str,
    label_real: int | None,
    mcp_client: ResultCapturingMCPClient,
    anthropic_client: UsageTrackingAnthropic,
    settings: config.OrchestratorSettings,
    statuses: dict[str, str],
    logger: logging.Logger,
    max_iterations: int,
) -> CorreoResultado:
    t0 = time.monotonic()
    logger.info(f"[{id_}] Iniciando análisis")

    anthropic_client.reset()
    mcp_client.reset()

    indicadores = extract_network_indicators(texto)
    n_indicadores = len(indicadores.urls) + len(indicadores.domains) + len(indicadores.ips)
    if n_indicadores > 0:
        logger.info(f"[{id_}] VT: {n_indicadores} indicadores encontrados, consultando...")

    error: str | None = None
    clasificacion: str | None = None
    puntaje: float | None = None

    try:
        resultado = await run_analysis(
            email_text=texto,
            mode=MODO,
            mcp_client=mcp_client,
            anthropic_client=anthropic_client,
            settings=settings,
            max_iterations=max_iterations,
            connection_statuses=statuses,
        )
        clasificacion = resultado.resultado.clasificacion.value
        puntaje = resultado.resultado.puntaje_riesgo
    except OrchestratorError as exc:
        error = str(exc)
        logger.error(f"[{id_}] ERROR: {error}")

    if mcp_client.archetype_result:
        d = mcp_client.archetype_result
        logger.info(f"[{id_}] Arquetipo: #{d.get('archetype_id')} - {d.get('label')}")

    for objetivo, veredicto_vt in mcp_client.vt_resultados.items():
        logger.info(f"[{id_}] VT: {objetivo} → {veredicto_vt}")

    if error is None:
        logger.info(f"[{id_}] Clasificación: {clasificacion} | Score: {puntaje:.2f}")

    input_tok = anthropic_client.total_input_tokens
    output_tok = anthropic_client.total_output_tokens
    costo = (input_tok / 1e6) * PRECIO_INPUT_POR_M + (output_tok / 1e6) * PRECIO_OUTPUT_POR_M
    logger.info(f"[{id_}] Tokens: input={input_tok} output={output_tok} costo=${costo:.5f}")

    tiempo_ms = int((time.monotonic() - t0) * 1000)
    if error is None:
        logger.info(f"[{id_}] ✓ Completado en {tiempo_ms / 1000:.1f}s")

    return CorreoResultado(
        id=id_,
        label_real=label_real,
        clasificacion=clasificacion,
        puntaje_riesgo=puntaje,
        arquetipo_id=(mcp_client.archetype_result or {}).get("archetype_id"),
        arquetipo_label=(mcp_client.archetype_result or {}).get("label"),
        vt_indicadores=list(mcp_client.vt_resultados.keys()),
        vt_resultados=dict(mcp_client.vt_resultados),
        input_tokens=input_tok,
        output_tokens=output_tok,
        costo_usd=round(costo, 6),
        tiempo_ms=tiempo_ms,
        error=error,
    )


# ==========================================================================
# Loop principal
# ==========================================================================


async def correr(args: argparse.Namespace) -> None:
    sufijo = "_dryrun" if args.dry_run else ""
    checkpoint_path = EVAL_SYSTEM_DIR / f"checkpoint{sufijo}.json"
    log_path = EVAL_SYSTEM_DIR / f"evaluation{sufijo}.log"
    errors_log_path = EVAL_SYSTEM_DIR / f"evaluation_errors{sufijo}.log"
    results_path = EVAL_SYSTEM_DIR / f"results_raw{sufijo}.jsonl"
    metrics_path = EVAL_SYSTEM_DIR / f"metrics_final{sufijo}.json"

    logger = configurar_logging(log_path, errors_log_path)

    filas = leer_csv(args.input, args.columna_id, args.columna_texto, args.columna_label)
    if args.dry_run:
        filas = filas[:5]
        print(f"[--dry-run] Usando {len(filas)} correos de ejemplo, sin llamar a Anthropic/VirusTotal.\n")

    ids_completados = cargar_ids_completados(results_path)
    checkpoint = cargar_checkpoint(checkpoint_path)

    if ids_completados and not args.dry_run:
        reanudar = True
        if args.resume is None:
            reanudar = preguntar_si_reanudar(len(ids_completados))
        elif args.resume is False:
            reanudar = False
        if not reanudar:
            print("No se reanuda: results_raw.jsonl existente se conserva, pero esta corrida no lo reutiliza "
                  "para saltar filas (podria generar IDs duplicados en el archivo). Bórralo o muévelo si "
                  "quieres empezar limpio.")
            ids_completados = set()

    filas_pendientes = [f for f in filas if f["id"] not in ids_completados]
    if args.limite is not None:
        filas_pendientes = filas_pendientes[: args.limite]

    print(f"Correos en el CSV: {len(filas)} | ya completados: {len(ids_completados)} | "
          f"a procesar esta corrida: {len(filas_pendientes)}")

    if not filas_pendientes:
        print("Nada por hacer.")
        return

    # --- Conexion (real) o simulacion (--dry-run) ---
    inicio_corrida = datetime.now(timezone.utc)
    resultados_previos = cargar_resultados_previos(results_path) if not args.dry_run else []
    tiempos_esta_corrida: list[float] = []

    async def procesar_y_guardar(fila: dict[str, str], mcp_client=None, anthropic_client=None, settings=None, statuses=None, max_iterations=None) -> CorreoResultado:
        if args.dry_run:
            await asyncio.sleep(0.05)  # simula latencia minima, para que el resumen de progreso tenga sentido
            r = resultado_simulado(fila["id"], fila["label"], fila["texto"])
            for linea in (
                f"[{r.id}] Iniciando análisis",
                f"[{r.id}] Arquetipo: #{r.arquetipo_id} - {r.arquetipo_label}",
                f"[{r.id}] VT: {len(r.vt_indicadores)} indicadores encontrados, consultando..." if r.vt_indicadores else None,
                *[f"[{r.id}] VT: {obj} → {v}" for obj, v in r.vt_resultados.items()],
                f"[{r.id}] Clasificación: {r.clasificacion} | Score: {r.puntaje_riesgo:.2f}",
                f"[{r.id}] Tokens: input={r.input_tokens} output={r.output_tokens} costo=${r.costo_usd:.5f}",
                f"[{r.id}] ✓ Completado en {r.tiempo_ms / 1000:.1f}s (SIMULADO)",
            ):
                if linea:
                    logger.info(linea)
            return r
        return await procesar_correo_real(
            fila["id"], fila["texto"], fila["label"], mcp_client, anthropic_client,
            settings, statuses, logger, max_iterations or args.max_iterations,
        )

    resultados_nuevos: list[CorreoResultado] = []

    with results_path.open("a", encoding="utf-8") as results_file:

        async def loop_correos(mcp_client=None, anthropic_client=None, settings=None, statuses=None) -> None:
            for idx, fila in enumerate(filas_pendientes, start=1):
                t0 = time.monotonic()
                resultado = await procesar_y_guardar(fila, mcp_client, anthropic_client, settings, statuses)
                tiempos_esta_corrida.append(time.monotonic() - t0)

                resultados_nuevos.append(resultado)
                results_file.write(json.dumps(resultado.to_dict(), ensure_ascii=False, default=str) + "\n")
                results_file.flush()

                if not args.dry_run and mcp_client is not None:
                    n_vt_indicadores = len(resultado.vt_indicadores)
                    _actualizar_checkpoint(checkpoint_path, checkpoint, vt_calls_contador_delta=n_vt_indicadores)

                if not args.dry_run and mcp_client is not None and mcp_client.vt_error is not None:
                    logger.error(f"[{resultado.id}] Cuota de VirusTotal agotada (probable): {mcp_client.vt_error}")
                    print("\nCuota VT agotada. Reanudar mañana con: python run_evaluation.py")
                    return

                if idx % PROGRESO_CADA_N_CORREOS == 0 or idx == len(filas_pendientes):
                    if args.dry_run:
                        vt_hoy = sum(len(r.vt_indicadores) for r in resultados_nuevos)
                    else:
                        vt_hoy = vt_calls_hoy(checkpoint)
                    _imprimir_progreso(
                        idx, len(filas_pendientes), len(ids_completados),
                        resultados_previos + resultados_nuevos, tiempos_esta_corrida, vt_hoy,
                    )

        if args.dry_run:
            await loop_correos()
        else:
            settings = config.load_orchestrator_settings()
            all_servers, _ = config.load_server_configs()
            server_configs = {k: v for k, v in all_servers.items() if k in SERVIDORES_MCP}
            config.validate_selected_servers(server_configs)

            real_anthropic = AsyncAnthropic(api_key=settings.anthropic_api_key)
            anthropic_client = UsageTrackingAnthropic(real_anthropic)

            async with MCPClientManager(server_configs) as real_mcp_client:
                statuses = await real_mcp_client.connect_all()
                print("Servidores MCP conectados:", statuses)
                mcp_client = ResultCapturingMCPClient(real_mcp_client)

                try:
                    await loop_correos(mcp_client, anthropic_client, settings, statuses)
                except KeyboardInterrupt:
                    print("\nInterrumpido por el usuario. Progreso guardado hasta el ultimo correo completado.")

    fin_corrida = datetime.now(timezone.utc)
    todos_los_resultados = resultados_previos + resultados_nuevos
    metricas = calcular_metricas(todos_los_resultados, inicio_corrida, fin_corrida)
    metrics_path.write_text(json.dumps(metricas, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    print(f"\nMétricas finales guardadas en: {metrics_path}")
    print(json.dumps(metricas, indent=2, ensure_ascii=False, default=str))


def _actualizar_checkpoint(checkpoint_path: Path, checkpoint: dict[str, Any], vt_calls_contador_delta: int) -> None:
    hoy = datetime.now().strftime("%Y-%m-%d")
    base = checkpoint if checkpoint.get("vt_calls_fecha") == hoy else {}
    nuevo_contador = int(base.get("vt_calls_hoy", 0)) + vt_calls_contador_delta
    checkpoint.clear()
    checkpoint.update({
        "vt_calls_fecha": hoy,
        "vt_calls_hoy": nuevo_contador,
        "ultima_actualizacion": datetime.now(timezone.utc).isoformat(),
    })
    guardar_checkpoint(checkpoint_path, checkpoint)


def _imprimir_progreso(
    idx: int, total_pendientes: int, ya_completados_antes: int,
    resultados_acumulados: list[CorreoResultado], tiempos_esta_corrida: list[float],
    vt_calls_hoy_actual: int,
) -> None:
    validos = [r for r in resultados_acumulados if r.error is None and r.label_real is not None]
    correctos = sum(
        1 for r in validos
        if (r.clasificacion == "phishing") == (r.label_real == 1)
    )
    costo_acumulado = sum(r.costo_usd for r in resultados_acumulados)
    tiempo_prom = (sum(tiempos_esta_corrida) / len(tiempos_esta_corrida)) if tiempos_esta_corrida else 0.0
    restantes = total_pendientes - idx
    estimado_restante_s = restantes * tiempo_prom

    print(f"\n=== Progreso: {idx}/{total_pendientes} (+{ya_completados_antes} de corridas previas) ===")
    print(f"Correctos hasta ahora: {correctos}/{len(validos)}")
    print(f"Costo acumulado: ${costo_acumulado:.2f}")
    print(f"Tiempo promedio/correo: {tiempo_prom:.0f}s")
    print(f"VT calls usadas hoy: {vt_calls_hoy_actual}/{VT_CUOTA_DIARIA_NOMINAL} "
          f"(contador propio del script, no una lectura oficial de VT -- ver comentario junto a "
          f"VT_CUOTA_DIARIA_NOMINAL)")
    print(f"Estimado restante: ~{estimado_restante_s / 3600:.1f} horas")


def cargar_resultados_previos(results_path: Path) -> list[CorreoResultado]:
    if not results_path.exists():
        return []
    resultados = []
    with results_path.open("r", encoding="utf-8") as f:
        for linea in f:
            linea = linea.strip()
            if not linea:
                continue
            try:
                resultados.append(CorreoResultado(**json.loads(linea)))
            except (json.JSONDecodeError, TypeError):
                continue
    return resultados


def leer_csv(path: Path, columna_id: str, columna_texto: str, columna_label: str) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for columna in (columna_id, columna_texto, columna_label):
            if columna not in (reader.fieldnames or []):
                raise ValueError(f"El CSV de entrada no tiene la columna requerida '{columna}'")
        filas = []
        for row in reader:
            filas.append({
                "id": row[columna_id],
                "texto": row[columna_texto],
                "label": int(row[columna_label]),
            })
    return filas


# ==========================================================================
# CLI
# ==========================================================================


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT_CSV, help="CSV de entrada")
    parser.add_argument("--columna-id", default="id")
    parser.add_argument("--columna-texto", default="body")
    parser.add_argument("--columna-label", default="label")
    parser.add_argument("--limite", type=int, default=None, help="Procesar a lo sumo N filas nuevas en esta corrida")
    parser.add_argument("--max-iterations", type=int, default=MAX_ITERATIONS_DEFAULT)
    parser.add_argument("--dry-run", action="store_true", help="Procesa 5 correos con datos simulados, sin gastar tokens")
    resume_group = parser.add_mutually_exclusive_group()
    resume_group.add_argument("--resume", dest="resume", action="store_true", default=None, help="Reanudar sin preguntar")
    resume_group.add_argument("--no-resume", dest="resume", action="store_false", help="Empezar de cero sin preguntar")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not args.dry_run:
        config.load_environment()
    asyncio.run(correr(args))


if __name__ == "__main__":
    main()
