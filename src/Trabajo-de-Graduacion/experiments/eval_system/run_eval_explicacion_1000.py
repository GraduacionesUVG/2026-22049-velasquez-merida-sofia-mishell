#!/usr/bin/env python3
"""Evaluacion en modo explicacion de los 1,000 correos de
experiments/external_eval/eval_external.csv, reutilizando los 200 que ya
estan evaluados.

Es run_eval_explicacion_100.py con otra entrada y otra salida: mismo CLI del
orquestador, mismo modelo, prompt y servidores MCP, y mismo esquema de salida.

    Entrada: experiments/external_eval/eval_external.csv
    Salida:  experiments/eval_system/results_explicacion_1000.jsonl

La primera vez, la salida se crea con los 200 resultados de
results_explicacion_100.jsonl y results_explicacion_101_200.jsonl (que no se
modifican). Como la corrida es reanudable, esos 200 se saltan y solo se
evaluan los 800 restantes.

La cuota gratuita de VirusTotal es de 500 consultas al dia. Cuando se agota,
la corrida se detiene sola, imprime las metricas acumuladas y se reanuda al
dia siguiente con el mismo comando.

USO
---
    python run_eval_explicacion_1000.py              # hasta agotar la cuota de VirusTotal
    python run_eval_explicacion_1000.py --limite 2   # probar con 2 correos
"""

import run_eval_explicacion_100 as base

LOTES_PREVIOS = [
    base.EVAL_SYSTEM_DIR / "results_explicacion_100.jsonl",
    base.EVAL_SYSTEM_DIR / "results_explicacion_101_200.jsonl",
]

base.DEFAULT_INPUT_CSV = base.EXPERIMENTS_DIR / "external_eval" / "eval_external.csv"
base.DEFAULT_OUTPUT = base.EVAL_SYSTEM_DIR / "results_explicacion_1000.jsonl"


def sembrar_con_lotes_previos() -> None:
    """Crea la salida con los resultados de los lotes previos, si aun no existe."""
    if base.DEFAULT_OUTPUT.exists():
        return
    lineas = [linea for ruta in LOTES_PREVIOS for linea in ruta.read_text(encoding="utf-8").splitlines() if linea.strip()]
    base.DEFAULT_OUTPUT.write_text("\n".join(lineas) + "\n", encoding="utf-8", newline="\n")
    print(f"Creado {base.DEFAULT_OUTPUT.name} con {len(lineas)} resultados de los lotes previos.")


if __name__ == "__main__":
    sembrar_con_lotes_previos()
    base.main()
