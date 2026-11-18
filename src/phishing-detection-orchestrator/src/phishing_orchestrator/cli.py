"""Interfaz de linea de comandos del orquestador.

Expone dos subcomandos:
- "analizar": un correo individual, en modo veredicto o explicacion.
- "lote": el CSV del conjunto de retencion en modo veredicto, con checkpoint
  reanudable y analisis de ablation via --mcp.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from anthropic import AsyncAnthropic

from phishing_orchestrator import config
from phishing_orchestrator.batch import BatchConfig, run_batch
from phishing_orchestrator.mcp_client import MCPClientManager
from phishing_orchestrator.orchestrator import OrchestratorError, run_analysis

logger = logging.getLogger(__name__)


def _parse_mcp_list(value: str | None, mode_defaults: dict[str, list[str]], mode: str, valid_ids: set[str]) -> list[str]:
    """Interpreta el flag --mcp: lista separada por comas, "none", o el default del modo."""
    if value is None:
        return list(mode_defaults.get(mode, []))

    normalized = value.strip()
    if normalized.lower() == "none":
        return []

    ids = [v.strip() for v in normalized.split(",") if v.strip()]
    invalid = set(ids) - valid_ids
    if invalid:
        raise SystemExit(
            f"Servidores MCP desconocidos en --mcp: {', '.join(sorted(invalid))}. "
            f"Validos: {', '.join(sorted(valid_ids))}."
        )
    return ids


def _read_email_text(args: argparse.Namespace) -> str:
    if args.archivo:
        return Path(args.archivo).read_text(encoding="utf-8")
    if args.texto:
        return args.texto
    if not sys.stdin.isatty():
        return sys.stdin.read()
    raise SystemExit("Debes pasar --archivo, --texto, o el correo por stdin.")


async def _run_analizar(args: argparse.Namespace) -> None:
    config.load_environment()
    servers, mode_defaults = config.load_server_configs()
    enabled_ids = _parse_mcp_list(args.mcp, mode_defaults, args.mode, set(servers.keys()))
    subset = {sid: servers[sid] for sid in enabled_ids}
    config.validate_selected_servers(subset)
    email_text = _read_email_text(args)

    settings = config.load_orchestrator_settings()
    anthropic_client = AsyncAnthropic(api_key=settings.anthropic_api_key)

    async with MCPClientManager(subset) as mcp_client:
        statuses = await mcp_client.connect_all()
        for server_id, status in statuses.items():
            if status != "ok":
                logger.warning("Servidor MCP '%s' no disponible: %s", server_id, status)

        try:
            resultado = await run_analysis(
                email_text=email_text,
                mode=args.mode,
                mcp_client=mcp_client,
                anthropic_client=anthropic_client,
                settings=settings,
                connection_statuses=statuses,
            )
        except OrchestratorError as exc:
            salida_error = {"error": str(exc)}
            if exc.raw_output is not None:
                # Lo que el modelo entrego aunque no cumpla el schema, para no perder la explicacion.
                salida_error["respuesta_cruda"] = exc.raw_output
            print(json.dumps(salida_error, ensure_ascii=False, indent=2, default=str))
            raise SystemExit(1) from exc

    salida_json = resultado.model_dump_json(indent=2)
    if args.salida:
        Path(args.salida).write_text(salida_json, encoding="utf-8")
        print(f"Resultado guardado en {args.salida}")
    else:
        print(salida_json)


async def _run_lote(args: argparse.Namespace) -> None:
    config.load_environment()
    servers, mode_defaults = config.load_server_configs()
    enabled_ids = _parse_mcp_list(args.mcp, mode_defaults, "veredicto", set(servers.keys()))
    subset = {sid: servers[sid] for sid in enabled_ids}
    config.validate_selected_servers(subset)
    settings = config.load_orchestrator_settings()

    batch_config = BatchConfig(
        input_path=Path(args.input),
        output_path=Path(args.output),
        text_column=args.columna_texto,
        label_column=args.columna_label,
        reintentar_fallidos=args.reintentar_fallidos,
        limite=args.limite,
        max_iterations=args.max_iteraciones,
    )

    metrics = await run_batch(batch_config, subset, settings)
    print(json.dumps(metrics.as_dict(), ensure_ascii=False, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing-orchestrator",
        description="Orquestador MCP para deteccion explicable de phishing.",
    )
    subparsers = parser.add_subparsers(dest="comando", required=True)

    analizar = subparsers.add_parser("analizar", help="Analiza un correo individual (modo veredicto o explicacion).")
    analizar.add_argument("--mode", choices=["veredicto", "explicacion"], default="explicacion")
    entrada = analizar.add_mutually_exclusive_group()
    entrada.add_argument("--archivo", help="Ruta a un archivo de texto con el correo a analizar.")
    entrada.add_argument("--texto", help="Texto del correo directamente en la linea de comandos.")
    analizar.add_argument(
        "--mcp",
        help=(
            "Lista separada por comas de servidores MCP a habilitar "
            "(knowledge,archetype,coherence,virustotal), o 'none' para "
            "ninguno (orquestador solo). Si se omite, se usan los defaults "
            "del modo definidos en config/mcp_servers.yaml."
        ),
    )
    analizar.add_argument("--salida", help="Archivo donde guardar el resultado en JSON (si se omite, se imprime en stdout).")
    analizar.set_defaults(func=_run_analizar)

    lote = subparsers.add_parser(
        "lote", help="Procesa un CSV completo en modo veredicto, con checkpoint reanudable."
    )
    lote.add_argument("--input", required=True, help="CSV de entrada con las columnas de texto y label.")
    lote.add_argument("--output", required=True, help="CSV de resultados. Si ya existe, la corrida se reanuda.")
    lote.add_argument("--columna-texto", default="text_clean", help="Nombre de la columna con el texto del correo.")
    lote.add_argument("--columna-label", default="label", help="Nombre de la columna con la etiqueta real (1=phishing, 0=legitimo).")
    lote.add_argument(
        "--mcp",
        help=(
            "Lista separada por comas de servidores MCP a habilitar, o 'none'. "
            "Sirve para el analisis de ablation (ej. 'archetype' para medir solo "
            "el aporte de arquetipos, o 'archetype,coherence' para sumar coherencia). "
            "Si se omite, se usan los defaults de modo veredicto de config/mcp_servers.yaml "
            "(archetype, knowledge, virustotal; coherence NO se incluye salvo que se pida)."
        ),
    )
    lote.add_argument(
        "--reintentar-fallidos",
        action="store_true",
        help=(
            "Ademas de las filas pendientes por cuota (que siempre se reintentan), "
            "reintenta tambien las filas que fallaron por completo en una corrida anterior."
        ),
    )
    lote.add_argument("--limite", type=int, default=None, help="Procesa a lo sumo N filas nuevas en esta corrida (util para pruebas).")
    lote.add_argument(
        "--max-iteraciones",
        type=int,
        default=4,
        help="Maximo de iteraciones del loop agentico por correo (default 4, mas bajo que en modo explicacion por costo).",
    )
    lote.set_defaults(func=_run_lote)

    return parser


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    parser = build_parser()
    args = parser.parse_args()
    asyncio.run(args.func(args))


if __name__ == "__main__":
    main()
