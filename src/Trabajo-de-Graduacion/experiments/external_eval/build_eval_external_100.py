"""Construye una submuestra estratificada de eval_external.csv
(experiments/external_eval/eval_external_100.csv): 50 phishing + 50 legitimos.

Se usa para evaluar el orquestador en modo explicacion (todos los MCP), que
es demasiado costoso para correr sobre los 1,000 correos completos. Las
columnas son las mismas que las de eval_external.csv (ver
build_eval_external.py): id, label, subject, sender, body, raw_text, source.
"""
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
IN_PATH = BASE_DIR / "eval_external.csv"
OUT_PATH = BASE_DIR / "eval_external_100.csv"

N_POR_CLASE = 50
SEED = 42


def main() -> None:
    # keep_default_na=False: subject/sender vacios se quedan como "" en vez
    # de NaN, para que el CSV de salida sea identico en formato al de entrada.
    df = pd.read_csv(IN_PATH, encoding="utf-8", keep_default_na=False)
    print(f"Leido: {IN_PATH} ({len(df)} filas)")

    # Muestreo estratificado por clase; sort_index conserva el orden original
    # (phishing primero, luego legitimos).
    muestra = df.groupby("label", group_keys=False).sample(n=N_POR_CLASE, random_state=SEED).sort_index()

    muestra.to_csv(OUT_PATH, index=False, encoding="utf-8")
    print(f"Guardado: {OUT_PATH} ({len(muestra)} filas)")

    print("\n=== Distribución por clase ===")
    print(muestra["label"].map({1: "phishing (1)", 0: "legitimo (0)"}).value_counts().to_string())

    print("\n=== Distribución por fuente ===")
    print(muestra["source"].value_counts().to_string())

    print("\n=== Clase x fuente ===")
    print(muestra.groupby(["label", "source"]).size().to_string())


if __name__ == "__main__":
    main()
