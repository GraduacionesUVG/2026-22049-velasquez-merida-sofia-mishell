#!/usr/bin/env python3
"""Evaluacion en modo explicacion de los 100 correos NUEVOS de la submuestra
ampliada (experiments/external_eval/eval_external_101_200.csv).

Es run_eval_explicacion_100.py con otra entrada y otra salida: mismo CLI del
orquestador, mismo modelo, prompt y servidores MCP, mismo esquema de salida
y misma reanudacion (los ids que ya estan en el JSONL de salida se saltan).

    Entrada: experiments/external_eval/eval_external_101_200.csv
    Salida:  experiments/eval_system/results_explicacion_101_200.jsonl

No toca results_explicacion_100.jsonl.

USO
---
    python run_eval_explicacion_101_200.py
    python run_eval_explicacion_101_200.py --limite 2   # probar con 2 correos
"""

import run_eval_explicacion_100 as base

base.DEFAULT_INPUT_CSV = base.EXPERIMENTS_DIR / "external_eval" / "eval_external_101_200.csv"
base.DEFAULT_OUTPUT = base.EVAL_SYSTEM_DIR / "results_explicacion_101_200.jsonl"

if __name__ == "__main__":
    base.main()
