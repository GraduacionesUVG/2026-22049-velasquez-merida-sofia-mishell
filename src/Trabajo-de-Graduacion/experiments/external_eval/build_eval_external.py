"""Construye el conjunto de evaluacion externo (experiments/external_eval/eval_external.csv):
- Phishing: correos reales de Phishing Pot (github.com/rf-peixoto/phishing_pot), parseados con email.parser
- Legitimo: muestra de TREC 2007 (ham, label==0), via kagglehub

Ninguno de los dos fue visto durante la construccion del corpus de entrenamiento
(01_preparacion_corpus.ipynb usa Enron/CEAS/Ling-Spam/Nazario/Nigerian Fraud/SpamAssassin)
ni durante el diseno de los baselines rule-based (YARA/SpamAssassin/Rspamd).
"""
import csv
import email.utils
import html as html_module
import re
import sys
from email import policy
from email.parser import BytesParser
from pathlib import Path

import pandas as pd

RE_TAG = re.compile(r"<[^>]+>")


def html_a_texto(contenido: str) -> str:
    """Convierte HTML a texto plano legible (mismo criterio que limpiar_texto()
    en 01_preparacion_corpus.ipynb: unescape + strip de tags + colapsar espacios)."""
    texto = html_module.unescape(contenido)
    texto = RE_TAG.sub(" ", texto)
    return re.sub(r"\s+", " ", texto).strip()

BASE_DIR = Path(__file__).resolve().parent
PHISHING_POT_DIR = BASE_DIR / "phishing_pot" / "email"
OUT_PATH = BASE_DIR / "eval_external.csv"

N_POR_CLASE = 500
SEED = 42

TREC_CSV = Path(
    r"C:\Users\50250\.cache\kagglehub\datasets\imdeepmind\preprocessed-trec-2007-public-corpus-dataset\versions\1\processed_data.csv"
)

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))


def extraer_texto_plano(msg) -> str:
    """Extrae el cuerpo como texto plano legible de un mensaje email.message.EmailMessage.

    Prefiere text/plain; si el mensaje solo trae text/html (comun en phishing:
    ~62% de los EML de Phishing Pot son HTML de una sola parte, sin
    alternativa text/plain), convierte el HTML a texto en vez de guardar el
    marcado crudo.
    """
    parte = msg.get_body(preferencelist=("plain", "html")) if msg.is_multipart() else msg
    if parte is None:
        return ""
    try:
        contenido = parte.get_content()
    except Exception:
        return ""
    if not isinstance(contenido, str):
        return ""
    if parte.get_content_type() == "text/html":
        return html_a_texto(contenido)
    return contenido.strip()


def parsear_phishing_pot(directorio: Path, limite: int) -> tuple[list[dict], int, int]:
    archivos = sorted(directorio.glob("*.eml"))
    filas = []
    ok, fallidos = 0, 0
    for archivo in archivos:
        if len(filas) >= limite:
            break
        try:
            with open(archivo, "rb") as f:
                msg = BytesParser(policy=policy.default).parse(f)

            raw_text = archivo.read_text(encoding="utf-8", errors="replace")
            body = extraer_texto_plano(msg).strip()

            if not body:
                fallidos += 1
                continue

            filas.append({
                "id": f"phishing_pot_{archivo.stem}",
                "label": 1,
                "subject": str(msg.get("Subject", "")),
                "sender": str(msg.get("From", "")),
                "body": body,
                "raw_text": raw_text,
                "source": "phishing_pot",
            })
            ok += 1
        except Exception:
            fallidos += 1
            continue
    return filas, ok, fallidos


def muestrear_trec_ham(csv_path: Path, n: int, seed: int) -> list[dict]:
    df = pd.read_csv(csv_path)
    ham = df[(df["label"] == 0) & df["message"].notna()].copy()
    muestra = ham.sample(n=n, random_state=seed)

    filas = []
    for i, row in muestra.reset_index(drop=True).iterrows():
        subject = "" if pd.isna(row["subject"]) else str(row["subject"])
        sender = "" if pd.isna(row["email_from"]) else str(row["email_from"])
        destinatario = "" if pd.isna(row["email_to"]) else str(row["email_to"])
        body = str(row["message"])

        # Date y Message-ID sinteticos: el dataset TREC no trae fecha real, y
        # sin estos dos headers Rspamd penaliza el 100% de los correos por
        # "estructura incompleta" (MISSING_DATE, MISSING_MID) independiente
        # del contenido -- mismo artefacto ya diagnosticado en el piloto
        # sobre val.csv (ver baseline_rspamd.py).
        fecha = email.utils.formatdate(localtime=False)
        raw_text = (
            f"From: {sender}\r\nTo: {destinatario}\r\nSubject: {subject}\r\n"
            f"Date: {fecha}\r\nMessage-ID: <trec2007-{i}@example.com>\r\n\r\n{body}"
        )

        filas.append({
            "id": f"trec_2007_{i}",
            "label": 0,
            "subject": subject,
            "sender": sender,
            "body": body,
            "raw_text": raw_text,
            "source": "trec_2007",
        })
    return filas


def main() -> None:
    print("Parseando Phishing Pot...")
    filas_phishing, ok, fallidos = parsear_phishing_pot(PHISHING_POT_DIR, limite=N_POR_CLASE)
    print(f"  EML parseados correctamente: {ok}")
    print(f"  EML fallidos/sin body de texto plano (descartados): {fallidos}")

    print("Muestreando TREC 2007 (ham)...")
    filas_legitimo = muestrear_trec_ham(TREC_CSV, n=N_POR_CLASE, seed=SEED)
    print(f"  Correos legítimos muestreados: {len(filas_legitimo)}")

    todas = filas_phishing + filas_legitimo
    df_final = pd.DataFrame(todas, columns=["id", "label", "subject", "sender", "body", "raw_text", "source"])

    df_final.to_csv(OUT_PATH, index=False, encoding="utf-8")
    print(f"\nGuardado: {OUT_PATH} ({len(df_final)} filas)")

    # --- Estadisticas ---
    print("\n=== Estadísticas ===")
    print(df_final.groupby(["label", "source"]).size())

    df_final["len_body"] = df_final["body"].astype(str).str.len()
    print("\nLongitud promedio del body por clase (caracteres):")
    print(df_final.groupby("label")["len_body"].mean().round(1))

    print("\n=== Ejemplos ===")
    for label, nombre in [(1, "Phishing"), (0, "Legítimo")]:
        sub = df_final[df_final["label"] == label].head(2)
        print(f"\n--- {nombre} ---")
        for _, row in sub.iterrows():
            print(f"  id: {row['id']}")
            print(f"  subject: {row['subject'][:120]!r}")
            print(f"  body[:200]: {str(row['body'])[:200]!r}")
            print()


if __name__ == "__main__":
    main()
