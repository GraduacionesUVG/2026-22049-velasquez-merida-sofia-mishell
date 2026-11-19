#!/usr/bin/env python3
"""Recalcula localmente la similitud coseno entre cada correo de
eval_external.csv y el centroide de su arquetipo.

POR QUE HACE FALTA
------------------
El servidor pattern-archetype-MCP calcula la similitud en
ArchetypeStore.classify_from_embedding (src/pattern_analysis_mcp/archetypes.py)
y la devuelve en el campo "similarity" de classify_archetype, pero ni
run_evaluation.py (modo veredicto) ni el CLI del modo explicacion la
guardaron: results_raw solo conserva arquetipo_id y arquetipo_label, y
evaluation.log solo registra el id y la etiqueta.

QUE HACE
--------
Importa el ArchetypeStore del propio servidor (mismo modelo all-MiniLM-L6-v2,
misma normalizacion L2, mismo KMeans y mismos centroides) y lo aplica a la
columna `body` de cada correo, que es el texto que recibio el orquestador.
No llama al LLM ni a VirusTotal.

Limite: en las corridas originales el texto que llego a classify_archetype
lo escribio el LLM como argumento de la herramienta, y pudo recortarlo o
alterarlo. Por eso el arquetipo recalculado no siempre coincide con el
registrado; el notebook evaluacion_objetivo_2.ipynb mide esa concordancia.

SALIDAS (no modifica ningun archivo existente)
-------
    arquetipo_similitud_recalculada.csv   una fila por correo: arquetipo que asigna
                                          KMeans, su similitud, el segundo mas
                                          similar y la similitud con los 15
                                          centroides (sim_c0 ... sim_c14)
    arquetipo_similitud_referencia.csv    distribucion de la similitud de los
                                          correos de construccion de cada arquetipo

USO (con el Python del servidor de arquetipos, que tiene sentence-transformers)
---
    "..\\..\\..\\pattern-archetype-MCP\\.venv\\Scripts\\python.exe" calcular_similitud_arquetipos.py
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

EVAL_SYSTEM_DIR = Path(__file__).resolve().parent
EXPERIMENTS_DIR = EVAL_SYSTEM_DIR.parent
REPO_ROOT = EXPERIMENTS_DIR.parent

DEFAULT_INPUT_CSV = EXPERIMENTS_DIR / "external_eval" / "eval_external.csv"
DEFAULT_MCP = REPO_ROOT.parent / "pattern-archetype-MCP"
OUT_CORREOS = EVAL_SYSTEM_DIR / "arquetipo_similitud_recalculada.csv"
OUT_REFERENCIA = EVAL_SYSTEM_DIR / "arquetipo_similitud_referencia.csv"

PERCENTILES = (1, 5, 10, 25, 50, 75, 90, 95)

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT_CSV)
    parser.add_argument("--mcp", type=Path, default=DEFAULT_MCP, help="Raiz del repo pattern-archetype-MCP")
    parser.add_argument("--columna-texto", default="body")
    args = parser.parse_args()

    sys.path.insert(0, str(args.mcp / "src"))
    import numpy as np
    from pattern_analysis_mcp.archetypes import store  # mismo codigo que usa el servidor

    with args.input.open(encoding="utf-8", newline="") as f:
        filas = [(r["id"], int(r["label"]), r[args.columna_texto]) for r in csv.DictReader(f)]
    print(f"Correos: {len(filas)} | modelo: {store.meta.get('modelo_embedding')} | arquetipos: {len(store.archetypes)}")

    # Mismos parametros que ArchetypeStore.embed, pero en lote
    vectores = store.modelo.encode([t for _, _, t in filas], normalize_embeddings=True,
                                   convert_to_numpy=True, batch_size=32, show_progress_bar=True)
    centroides = store._centroides_normalizados
    asignado = store.kmeans.predict(vectores)  # igual que classify_from_embedding
    similitudes = vectores @ centroides.T
    orden = np.argsort(-similitudes, axis=1)

    with OUT_CORREOS.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "label", "arquetipo_id_recalc", "arquetipo_label_recalc", "similitud_recalc",
                    "segundo_arquetipo_id", "similitud_segundo", "margen", "n_palabras_body"]
                   + [f"sim_c{j}" for j in range(centroides.shape[0])])
        for i, (id_, label, texto) in enumerate(filas):
            a = int(asignado[i])
            # segundo arquetipo mas similar, distinto del asignado
            b = int(next(j for j in orden[i] if j != a))
            w.writerow([id_, label, a, store.archetypes[a]["label"], f"{similitudes[i, a]:.6f}",
                        b, f"{similitudes[i, b]:.6f}", f"{similitudes[i, a] - similitudes[i, b]:.6f}",
                        len(texto.split())] + [f"{v:.6f}" for v in similitudes[i]])
    print(f"Guardado: {OUT_CORREOS}")

    # Referencia: similitud de los correos de phishing con los que se construyo cada arquetipo
    ruta_emb = args.mcp / "artifacts" / "embeddings_phishing_full.npy"
    emb = np.load(ruta_emb)
    etiquetas = store.kmeans.predict(emb) if not hasattr(store.kmeans, "labels_") or len(store.kmeans.labels_) != len(emb) \
        else store.kmeans.labels_
    sim_ref = np.einsum("ij,ij->i", emb, centroides[etiquetas])
    with OUT_REFERENCIA.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["arquetipo_id", "arquetipo_label", "emocion_dominante", "tactica", "n_construccion",
                    "sim_media", "sim_std"] + [f"sim_p{p}" for p in PERCENTILES])
        for a in sorted(store.archetypes):
            s = sim_ref[etiquetas == a]
            perfil = store.archetypes[a]
            w.writerow([a, perfil["label"], perfil["dominant_emotion"], perfil["social_engineering_tactic"], len(s),
                        f"{s.mean():.6f}", f"{s.std():.6f}"] + [f"{np.percentile(s, p):.6f}" for p in PERCENTILES])
    print(f"Guardado: {OUT_REFERENCIA} ({len(emb)} correos de construccion, norma media {np.linalg.norm(emb, axis=1).mean():.4f})")


if __name__ == "__main__":
    main()
