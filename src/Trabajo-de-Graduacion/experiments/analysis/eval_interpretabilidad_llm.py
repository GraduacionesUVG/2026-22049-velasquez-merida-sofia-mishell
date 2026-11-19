"""Evalua la interpretabilidad de las explicaciones del prototipo usando un LLM como juez.

Lee eval_system/results_explicacion_1000.jsonl y, para cada registro, pide a Claude Haiku 4.5 que
juzgue la explicacion (veredicto justificado, senales concretas, comprensibilidad, ingenieria social).
El resultado se guarda de forma incremental en eval_system/eval_interpretabilidad_juez.jsonl, con
todos los campos del registro original mas los 5 campos del juez. Es reanudable: los ids ya
evaluados se saltean y los que quedaron con "juez_error" se vuelven a intentar.

Uso (requiere ANTHROPIC_API_KEY en el entorno o en el .env de la raiz del repo):
    python experiments/analysis/eval_interpretabilidad_llm.py
    python experiments/analysis/eval_interpretabilidad_llm.py --limit 20   # prueba corta
"""
import argparse
import json
import os
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import anthropic

BASE = Path(__file__).resolve().parents[1]  # carpeta experiments/
RUTA_ENTRADA = BASE / "eval_system" / "results_explicacion_1000.jsonl"
RUTA_SALIDA = BASE / "eval_system" / "eval_interpretabilidad_juez.jsonl"

MODELO = "claude-haiku-4-5"
TEMPERATURA = 0
MAX_TOKENS = 200
TAM_LOTE = 10
PAUSA_LOTE_S = 1
MAX_INTENTOS_PARSEO = 3

CAMPOS_BOOL = ["justifica_veredicto", "cita_senales_concretas", "ingenieria_social_identificada"]
CAMPOS_JUEZ = CAMPOS_BOOL + ["comprensible_no_tecnico", "razon_breve"]

SYSTEM_PROMPT = (
    "Eres un evaluador de explicaciones de un sistema de detección de phishing. "
    "Evalúa si la explicación es interpretable para un usuario final."
)

PLANTILLA_USUARIO = """Evalúa la siguiente explicación generada por el sistema.

Clasificación: {clasificacion}
Puntaje de riesgo: {puntaje_riesgo}
Arquetipo identificado: {arquetipo_label}

Señales reportadas:
{senales}

Explicación:
\"\"\"
{explicacion}
\"\"\"

Responde únicamente con un objeto JSON, sin texto adicional ni bloques de código, con exactamente estos campos:
{{
  "justifica_veredicto": true/false,  // la explicación respalda la clasificación dada
  "cita_senales_concretas": true/false,  // menciona señales específicas del correo, no genéricas
  "comprensible_no_tecnico": 1-5 usando esta rúbrica:
    1 = solo jerga técnica, un usuario común no podría entender nada
    2 = hay algo de explicación pero predomina la jerga; el usuario quedaría confundido
    3 = el usuario entiende que el correo es sospechoso pero no exactamente por qué
    4 = el usuario entiende con claridad por qué el correo es peligroso, aunque haya algún término técnico aislado
    5 = cualquier persona puede leer esto, entender la amenaza concreta y saber qué hacer — sin necesitar contexto previo de seguridad
  "ingenieria_social_identificada": true/false,  // nombra tácticas de ingeniería social concretas
  "razon_breve": "string de máximo 20 palabras explicando el puntaje"
}}"""


def cargar_jsonl(ruta):
    with open(ruta, encoding="utf-8") as f:
        return [json.loads(linea) for linea in f if linea.strip()]


def construir_prompt(registro):
    senales = "\n".join(f"- {s.get('descripcion', '')}" for s in registro.get("senales") or [])
    return PLANTILLA_USUARIO.format(
        clasificacion=registro.get("clasificacion"),
        puntaje_riesgo=registro.get("puntaje_riesgo"),
        arquetipo_label=registro.get("arquetipo_label") or "ninguno",
        senales=senales or "(ninguna)",
        explicacion=registro.get("explicacion") or "",
    )


def parsear_respuesta(texto):
    """Extrae y valida el JSON del juez. Lanza ValueError si no cumple el esquema."""
    inicio, fin = texto.find("{"), texto.rfind("}")
    if inicio == -1 or fin <= inicio:
        raise ValueError("la respuesta no contiene un objeto JSON")
    datos = json.loads(texto[inicio:fin + 1])
    if not isinstance(datos, dict):
        raise ValueError("la respuesta no es un objeto JSON")

    faltantes = [c for c in CAMPOS_JUEZ if c not in datos]
    if faltantes:
        raise ValueError(f"faltan campos: {faltantes}")
    for campo in CAMPOS_BOOL:
        if not isinstance(datos[campo], bool):
            raise ValueError(f"{campo} no es booleano: {datos[campo]!r}")
    puntaje = datos["comprensible_no_tecnico"]
    if isinstance(puntaje, bool) or not isinstance(puntaje, int) or not 1 <= puntaje <= 5:
        raise ValueError(f"comprensible_no_tecnico fuera de 1-5: {puntaje!r}")
    if not isinstance(datos["razon_breve"], str):
        raise ValueError("razon_breve no es string")
    return {c: datos[c] for c in CAMPOS_JUEZ}


def evaluar(cliente, registro):
    """Devuelve los campos del juez, o {"juez_error": ...} si no se obtuvo un JSON valido."""
    mensajes = [{"role": "user", "content": construir_prompt(registro)}]
    ultimo_error = None
    for _ in range(MAX_INTENTOS_PARSEO):
        try:
            # El SDK 1.x ya no acepta temperature como argumento; Haiku 4.5 sí la honra vía extra_body
            respuesta = cliente.messages.create(
                model=MODELO, max_tokens=MAX_TOKENS, system=SYSTEM_PROMPT, messages=mensajes,
                extra_body={"temperature": TEMPERATURA},
            )
        except anthropic.APIError as e:
            # El SDK ya reintento los errores transitorios (429, 5xx, conexion)
            return {"juez_error": f"{type(e).__name__}: {e}"}

        texto = "".join(b.text for b in respuesta.content if b.type == "text")
        try:
            return parsear_respuesta(texto)
        except (json.JSONDecodeError, ValueError) as e:
            ultimo_error = f"{type(e).__name__}: {e} | respuesta: {texto[:200]!r}"
            # Con temperature 0 repetir el mismo prompt daria la misma salida: se le muestra el fallo
            mensajes = mensajes[:1] + [
                {"role": "assistant", "content": texto or "(vacío)"},
                {"role": "user", "content": f"Tu respuesta no es válida ({e}). Responde solo con el objeto JSON pedido."},
            ]
    return {"juez_error": ultimo_error}


def cargar_procesados():
    """Ids ya evaluados. Los registros con juez_error se quitan del archivo para reintentarlos."""
    if not RUTA_SALIDA.exists():
        return set()
    previos = cargar_jsonl(RUTA_SALIDA)
    correctos = [r for r in previos if not r.get("juez_error")]
    if len(correctos) < len(previos):
        with open(RUTA_SALIDA, "w", encoding="utf-8") as f:
            for r in correctos:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"Se reintentarán {len(previos) - len(correctos)} registros que tenían juez_error.")
    return {r["id"] for r in correctos}


def imprimir_resumen():
    filas = cargar_jsonl(RUTA_SALIDA) if RUTA_SALIDA.exists() else []
    validas = [r for r in filas if not r.get("juez_error")]
    print(f"\n=== Resumen ({RUTA_SALIDA.name}) ===")
    print(f"Registros: {len(filas)} | evaluados: {len(validas)} | con juez_error: {len(filas) - len(validas)}")
    if not validas:
        return
    for campo in CAMPOS_BOOL:
        n = sum(r[campo] for r in validas)
        print(f"  {campo}: {100 * n / len(validas):.1f} % true ({n}/{len(validas)})")
    distribucion = Counter(r["comprensible_no_tecnico"] for r in validas)
    media = sum(r["comprensible_no_tecnico"] for r in validas) / len(validas)
    print(f"  comprensible_no_tecnico (media = {media:.2f}):")
    for puntaje in range(1, 6):
        n = distribucion.get(puntaje, 0)
        print(f"    {puntaje}: {n} ({100 * n / len(validas):.1f} %)")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--limit", type=int, default=None, help="evaluar solo los primeros N pendientes (prueba)")
    args = parser.parse_args()

    if not os.environ.get("ANTHROPIC_API_KEY"):
        try:  # respaldo: .env de la raiz del repo
            from dotenv import load_dotenv
            load_dotenv(BASE.parent / ".env")
        except ImportError:
            pass
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("Falta ANTHROPIC_API_KEY en el entorno.")

    registros = cargar_jsonl(RUTA_ENTRADA)
    procesados = cargar_procesados()
    pendientes = [r for r in registros if r["id"] not in procesados]
    if args.limit is not None:
        pendientes = pendientes[:args.limit]
    print(f"Total: {len(registros)} | ya evaluados: {len(procesados)} | a evaluar ahora: {len(pendientes)}")

    cliente = anthropic.Anthropic(max_retries=5)
    errores = 0
    with ThreadPoolExecutor(max_workers=TAM_LOTE) as pool:
        for i in range(0, len(pendientes), TAM_LOTE):
            lote = pendientes[i:i + TAM_LOTE]
            resultados = list(pool.map(lambda r: evaluar(cliente, r), lote))
            # Guardado incremental: un lote completo por escritura
            with open(RUTA_SALIDA, "a", encoding="utf-8") as f:
                for registro, juez in zip(lote, resultados):
                    f.write(json.dumps({**registro, **juez}, ensure_ascii=False) + "\n")
            errores += sum("juez_error" in j for j in resultados)
            print(f"  {min(i + TAM_LOTE, len(pendientes))}/{len(pendientes)} (errores: {errores})", flush=True)
            if i + TAM_LOTE < len(pendientes):
                time.sleep(PAUSA_LOTE_S)

    imprimir_resumen()


if __name__ == "__main__":
    main()
