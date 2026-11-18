"""Amplia la submuestra de evaluacion de 100 a 200 correos:

- eval_external_200.csv      Los 100 de eval_external_100.csv (identicos y en
                             el mismo orden) seguidos de 100 correos nuevos.
- eval_external_101_200.csv  Solo los 100 nuevos (50 phishing + 50 legitimos).

build_eval_external_100.py tomo los 50 primeros correos de cada clase de un
muestreo estratificado con random_state=42. Aqui se repite ese mismo muestreo
pidiendo 100 por clase: los 50 primeros de cada clase son los de
eval_external_100.csv y los 50 siguientes son los nuevos. El script verifica
esa coincidencia y se detiene si no se cumple.
"""
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
IN_PATH = BASE_DIR / "eval_external.csv"
PRIMEROS_100_PATH = BASE_DIR / "eval_external_100.csv"
OUT_200_PATH = BASE_DIR / "eval_external_200.csv"
OUT_NUEVOS_PATH = BASE_DIR / "eval_external_101_200.csv"

N_POR_CLASE_ORIGINAL = 50
N_POR_CLASE_TOTAL = 100
SEED = 42


def main() -> None:
    # keep_default_na=False: mismo criterio que build_eval_external_100.py
    df = pd.read_csv(IN_PATH, encoding="utf-8", keep_default_na=False)
    primeros_100 = pd.read_csv(PRIMEROS_100_PATH, encoding="utf-8", keep_default_na=False)
    print(f"Leido: {IN_PATH.name} ({len(df)} filas) y {PRIMEROS_100_PATH.name} ({len(primeros_100)} filas)")

    # Mismo muestreo que el original, pero con 100 por clase. Dentro de cada
    # clase las filas salen en el orden aleatorio del muestreo.
    muestra = df.groupby("label", group_keys=False).sample(n=N_POR_CLASE_TOTAL, random_state=SEED)
    posicion = muestra.groupby("label").cumcount()
    reproducidos = muestra[posicion < N_POR_CLASE_ORIGINAL].sort_index()
    nuevos = muestra[posicion >= N_POR_CLASE_ORIGINAL].sort_index()

    # Verificacion: los primeros 50 por clase deben ser exactamente eval_external_100.csv
    if list(reproducidos["id"]) != list(primeros_100["id"]):
        raise SystemExit(
            "ERROR: el muestreo no reproduce eval_external_100.csv (ids u orden distintos). "
            "No se genero ningun archivo."
        )
    if not reproducidos.reset_index(drop=True).equals(primeros_100):
        raise SystemExit("ERROR: los ids coinciden pero el contenido de las filas no. No se genero ningun archivo.")
    if set(nuevos["id"]) & set(primeros_100["id"]):
        raise SystemExit("ERROR: hay correos nuevos que ya estaban en eval_external_100.csv.")
    print("Verificado: los primeros 100 coinciden con eval_external_100.csv (mismos ids, orden y contenido).")

    df_200 = pd.concat([reproducidos, nuevos])
    df_200.to_csv(OUT_200_PATH, index=False, encoding="utf-8")
    nuevos.to_csv(OUT_NUEVOS_PATH, index=False, encoding="utf-8")
    print(f"Guardado: {OUT_200_PATH} ({len(df_200)} filas)")
    print(f"Guardado: {OUT_NUEVOS_PATH} ({len(nuevos)} filas)")

    for nombre, tabla in [("los 100 nuevos", nuevos), ("los 200", df_200)]:
        print(f"\n=== Clase x fuente en {nombre} ===")
        print(tabla.groupby(["label", "source"]).size().to_string())


if __name__ == "__main__":
    main()
