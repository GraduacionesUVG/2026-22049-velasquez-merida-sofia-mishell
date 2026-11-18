"""Modo veredicto por lote: procesa un CSV completo con checkpoint reanudable.

Diseno acordado para la evaluacion del conjunto de retencion:
- Cada fila del CSV de salida corresponde a una fila del CSV de entrada,
  identificada por su posicion (fila_idx), no por un hash del texto.
- Despues de procesar cada correo se reescribe el CSV de salida completo con
  el estado acumulado en memoria. Para un conjunto de este tamano esto es
  practicamente instantaneo y evita duplicados al reintentar filas.
- Al reanudar una corrida: las filas ya completadas (con VirusTotal en ok o
  no_aplica) se saltan. Las filas en pendiente_cuota se reintentan siempre,
  porque no se procesaron por falta de cupo, no por un problema del correo.
  Las filas fallidas NO se reintentan automaticamente: solo si se pasa
  --reintentar-fallidos, para no entrar en un bucle gastando recursos en un
  correo problematico y para poder inspeccionar la falla antes de reintentar.
- VirusTotal devuelve el mismo texto de error para distintos tipos de fallo
  (no expone el codigo HTTP ni el codigo de error de VT a traves de MCP), asi
  que la deteccion de cuota agotada es por palabras clave en el mensaje.
"""

from __future__ import annotations

import csv
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
from anthropic import AsyncAnthropic

from phishing_orchestrator.config import OrchestratorSettings, ServerConfig
from phishing_orchestrator.mcp_client import MCPClientManager
from phishing_orchestrator.orchestrator import OrchestratorError, run_analysis
from phishing_orchestrator.schemas import BatchRowResult, EstadoFila, VirusTotalEstado

logger = logging.getLogger(__name__)

_QUOTA_KEYWORDS = ("quota", "rate limit", "too many requests", "daily", "exceeded", "limit")

_CSV_FIELDNAMES = list(BatchRowResult.model_fields.keys())


def _is_probable_quota_error(message: str) -> bool:
    """Heuristica insensible a mayusculas para detectar cuota/rate limit agotados.

    El servidor de VirusTotal (@burtthecoder/mcp-virustotal via fastmcp) solo
    expone el mensaje de texto del error, no el status HTTP ni el codigo de
    VT, asi que no hay forma de distinguir esto de forma estructurada. Se
    revisan varias variantes porque la redaccion del error puede cambiar.
    """
    lowered = message.lower()
    return any(keyword in lowered for keyword in _QUOTA_KEYWORDS)


def _normalize_label(value: Any) -> bool | None:
    """Normaliza la columna label (1 = phishing, 0 = legitimo) a booleano."""
    if value is None or value == "":
        return None
    try:
        return bool(int(float(value)))
    except (TypeError, ValueError):
        return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _empty_strings_to_none(row: dict[str, Any]) -> dict[str, Any]:
    return {k: (v if v not in ("", None) else None) for k, v in row.items()}


def load_existing_results(output_path: Path) -> dict[int, BatchRowResult]:
    """Lee un CSV de resultados previo, si existe, indexado por fila_idx."""
    if not output_path.exists():
        return {}

    results: dict[int, BatchRowResult] = {}
    with output_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for raw_row in reader:
            row = BatchRowResult.model_validate(_empty_strings_to_none(raw_row))
            results[row.fila_idx] = row
    return results


def write_results(output_path: Path, results: dict[int, BatchRowResult]) -> None:
    """Reescribe el CSV de salida completo, ordenado por fila_idx."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_CSV_FIELDNAMES)
        writer.writeheader()
        for fila_idx in sorted(results.keys()):
            writer.writerow(results[fila_idx].model_dump(mode="json"))


def _needs_processing(existing: BatchRowResult | None, reintentar_fallidos: bool) -> bool:
    if existing is None:
        return True
    if existing.estado_fila == EstadoFila.FALLIDO:
        return reintentar_fallidos
    # completado: solo hace falta reprocesar si VT quedo pendiente por cuota.
    return existing.virustotal_estado == VirusTotalEstado.PENDIENTE_CUOTA


def _classify_virustotal_estado(
    resultado_herramientas: list[Any],
    virustotal_habilitado: bool,
    se_forzo_exclusion_por_cuota: bool,
) -> tuple[VirusTotalEstado, bool]:
    """Determina el estado de VT para la fila y si se detecto cuota agotada.

    Devuelve (estado, cuota_agotada_detectada_ahora).
    """
    if not virustotal_habilitado:
        return VirusTotalEstado.NO_HABILITADO, False

    invocaciones_vt = [inv for inv in resultado_herramientas if inv.servidor == "virustotal"]

    if not invocaciones_vt:
        if se_forzo_exclusion_por_cuota:
            return VirusTotalEstado.PENDIENTE_CUOTA, False
        return VirusTotalEstado.NO_APLICA, False

    if any(inv.ok for inv in invocaciones_vt):
        return VirusTotalEstado.OK, False

    errores = [inv.error or "" for inv in invocaciones_vt]
    if any(_is_probable_quota_error(err) for err in errores):
        return VirusTotalEstado.PENDIENTE_CUOTA, True

    return VirusTotalEstado.ERROR, False


@dataclass
class BatchMetrics:
    total_filas: int = 0
    completadas: int = 0
    fallidas: int = 0
    pendientes_cuota: int = 0
    evaluadas_para_metricas: int = 0
    sin_etiqueta_valida: int = 0
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def accuracy(self) -> float | None:
        total = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / total if total else None

    @property
    def precision(self) -> float | None:
        denom = self.tp + self.fp
        return self.tp / denom if denom else None

    @property
    def recall(self) -> float | None:
        denom = self.tp + self.fn
        return self.tp / denom if denom else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if not p or not r or (p + r) == 0:
            return None
        return 2 * p * r / (p + r)

    def as_dict(self) -> dict[str, Any]:
        return {
            "total_filas": self.total_filas,
            "completadas": self.completadas,
            "fallidas": self.fallidas,
            "pendientes_cuota": self.pendientes_cuota,
            "evaluadas_para_metricas": self.evaluadas_para_metricas,
            "sin_etiqueta_valida": self.sin_etiqueta_valida,
            "matriz_confusion": {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn},
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
        }


def compute_metrics(results: dict[int, BatchRowResult]) -> BatchMetrics:
    metrics = BatchMetrics(total_filas=len(results))
    for row in results.values():
        if row.estado_fila == EstadoFila.FALLIDO:
            metrics.fallidas += 1
            continue

        metrics.completadas += 1
        if row.virustotal_estado == VirusTotalEstado.PENDIENTE_CUOTA:
            metrics.pendientes_cuota += 1

        real = _normalize_label(row.label)
        if real is None or row.clasificacion is None:
            metrics.sin_etiqueta_valida += 1
            continue

        metrics.evaluadas_para_metricas += 1
        pred_phishing = row.clasificacion.value == "phishing"
        if pred_phishing and real:
            metrics.tp += 1
        elif pred_phishing and not real:
            metrics.fp += 1
        elif not pred_phishing and real:
            metrics.fn += 1
        else:
            metrics.tn += 1

    return metrics


@dataclass
class BatchConfig:
    input_path: Path
    output_path: Path
    text_column: str = "text_clean"
    label_column: str = "label"
    reintentar_fallidos: bool = False
    limite: int | None = None
    max_iterations: int = 4


async def run_batch(
    config: BatchConfig,
    server_configs: dict[str, ServerConfig],
    settings: OrchestratorSettings,
    anthropic_client: AsyncAnthropic | None = None,
) -> BatchMetrics:
    """Procesa el CSV de entrada fila por fila con checkpoint reanudable.

    anthropic_client es inyectable para pruebas (evita golpear la API real);
    en uso normal se omite y se construye uno a partir de settings.
    """
    df = pd.read_csv(config.input_path)
    for column in (config.text_column, config.label_column):
        if column not in df.columns:
            raise ValueError(f"El CSV de entrada no tiene la columna requerida '{column}'")

    results = load_existing_results(config.output_path)
    virustotal_habilitado = "virustotal" in server_configs
    virustotal_quota_agotada = any(
        row.virustotal_estado == VirusTotalEstado.PENDIENTE_CUOTA for row in results.values()
    )

    anthropic_client = anthropic_client or AsyncAnthropic(api_key=settings.anthropic_api_key)

    procesadas_esta_corrida = 0
    async with MCPClientManager(server_configs) as mcp_client:
        statuses = await mcp_client.connect_all()
        for server_id, status in statuses.items():
            if status != "ok":
                logger.warning("Servidor MCP '%s' no disponible: %s", server_id, status)

        try:
            for raw_idx, row in df.reset_index(drop=True).iterrows():
                fila_idx = int(raw_idx)
                existing = results.get(fila_idx)
                if not _needs_processing(existing, config.reintentar_fallidos):
                    continue
                if config.limite is not None and procesadas_esta_corrida >= config.limite:
                    break

                email_text = str(row[config.text_column])
                label_value = row[config.label_column]

                force_exclude = {"virustotal"} if virustotal_quota_agotada else None

                try:
                    resultado = await run_analysis(
                        email_text=email_text,
                        mode="veredicto",
                        mcp_client=mcp_client,
                        anthropic_client=anthropic_client,
                        settings=settings,
                        max_iterations=config.max_iterations,
                        connection_statuses=statuses,
                        force_exclude_server_ids=force_exclude,
                    )
                except OrchestratorError as exc:
                    logger.warning("Fila %d fallo: %s", fila_idx, exc)
                    results[fila_idx] = BatchRowResult(
                        fila_idx=fila_idx,
                        label=str(label_value),
                        clasificacion=None,
                        puntaje_riesgo=None,
                        virustotal_estado=VirusTotalEstado.NO_EVALUADO,
                        estado_fila=EstadoFila.FALLIDO,
                        error=str(exc),
                        timestamp=_now_iso(),
                    )
                else:
                    vt_estado, cuota_detectada = _classify_virustotal_estado(
                        resultado.herramientas_invocadas, virustotal_habilitado, force_exclude is not None
                    )
                    if cuota_detectada:
                        virustotal_quota_agotada = True
                        logger.warning(
                            "Cuota de VirusTotal agotada detectada en fila %d; se deja de "
                            "ofrecer VirusTotal para el resto de esta corrida.",
                            fila_idx,
                        )

                    results[fila_idx] = BatchRowResult(
                        fila_idx=fila_idx,
                        label=str(label_value),
                        clasificacion=resultado.resultado.clasificacion,
                        puntaje_riesgo=resultado.resultado.puntaje_riesgo,
                        virustotal_estado=vt_estado,
                        estado_fila=EstadoFila.COMPLETADO,
                        error=None,
                        timestamp=_now_iso(),
                    )

                procesadas_esta_corrida += 1
                write_results(config.output_path, results)
        except KeyboardInterrupt:
            logger.warning("Interrumpido por el usuario. Resultados guardados hasta la ultima fila procesada.")

    write_results(config.output_path, results)
    return compute_metrics(results)
