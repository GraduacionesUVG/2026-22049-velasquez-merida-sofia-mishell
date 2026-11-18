"""Interfaz web local (Streamlit) del orquestador de deteccion de phishing.

Dos pestanas que comparten el mismo reporte explicativo por correo:

1. "Correos evaluados": lista los correos de results_explicacion_1000.jsonl
   (evaluacion final en modo explicacion) y, al elegir uno, muestra el
   reporte de lo que el sistema respondio para ese correo: veredicto, por
   que y evidencia de cada servidor MCP.
2. "Analisis en vivo": arranca los servidores MCP una sola vez al abrir la
   app, los mantiene conectados y analiza correos escritos a mano, en modo
   veredicto o explicacion, llamando al orquestador real
   (phishing_orchestrator.orchestrator.run_analysis) dentro de este proceso.
   Muestra el mismo reporte y agrega cada analisis a analisis_en_vivo.jsonl.

El analisis en vivo usa la API real de Anthropic: cada clic gasta tokens.
Requiere el mismo .env que el resto del orquestador (ver README.md).
"""

from __future__ import annotations

import asyncio
import atexit
import html
import json
import re
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

EVAL_SYSTEM_DIR = Path(__file__).resolve().parent
_ORCHESTRATOR_ROOT = EVAL_SYSTEM_DIR.parents[1]
# Repo de la tesis (clonado junto a este): otros JSONL de resultados y el CSV
# con el texto original de los correos evaluados.
_TESIS_EXPERIMENTS = _ORCHESTRATOR_ROOT.parent / "Trabajo-de-Graduacion" / "experiments"
TESIS_EVAL_DIR = _TESIS_EXPERIMENTS / "eval_system"
CORREOS_CSV = _TESIS_EXPERIMENTS / "external_eval" / "eval_external.csv"
# Resultados finales de la evaluacion en modo explicacion (1,000 correos).
DATOS_FINALES_DIR = _ORCHESTRATOR_ROOT / "experiments" / "data final eval"

ARCHIVO_POR_DEFECTO = "results_explicacion_1000.jsonl"

# Cada analisis en vivo se agrega aqui, una linea JSON por correo.
HISTORIAL_PATH = EVAL_SYSTEM_DIR / "analisis_en_vivo.jsonl"
MODOS = {"explicacion": "Explicación", "veredicto": "Veredicto"}
# Mismos topes que el resto del proyecto: 6 en "analizar" (default del
# orquestador) y 4 en modo veredicto, como en "lote" y run_evaluation.py.
MAX_ITERACIONES = {"explicacion": 6, "veredicto": 4}
TIMEOUT_ANALISIS_S = 600
MAX_CARACTERES_CORREO = 6000

COLOR_ROJO, COLOR_VERDE, COLOR_AMARILLO, COLOR_GRIS = "#c0392b", "#1e8449", "#b7950b", "#566573"

# Como se presenta cada servidor MCP a quien lee el reporte: (icono, nombre, que aporta, color).
FUENTES = {
    "archetype": ("", "Patrón de ataque", "A qué tipo de ataque conocido se parece el correo.", "#8e44ad"),
    "coherence": ("", "Coherencia del mensaje", "Si el remitente, el asunto y el contenido encajan entre sí.", "#2471a3"),
    "knowledge": ("", "Tácticas de engaño", "Qué técnicas de persuasión o ingeniería social aparecen.", "#ca6f1e"),
    "virustotal": ("", "Reputación de enlaces", "Si los enlaces, dominios o IPs están reportados como maliciosos.", "#148f77"),
}

RESULTADO_EN_PALABRAS = {
    "TP": ("+", "El sistema acertó: era phishing y lo detectó."),
    "TN": ("+", "El sistema acertó: era un correo legítimo y lo dejó pasar."),
    "FP": ("-", "Falsa alarma: era un correo legítimo, pero el sistema lo marcó como phishing."),
    "FN": ("-", "No lo detectó: era phishing, pero el sistema lo consideró legítimo."),
}

# El orquestador y los envoltorios de run_evaluation.py (que capturan tokens,
# arquetipo y veredictos de VirusTotal, datos que run_analysis no devuelve)
# se importan de forma tolerante: si fallan, los reportes de correos ya
# evaluados siguen funcionando y la pestana en vivo explica que falta.
for _ruta in (str(_ORCHESTRATOR_ROOT / "src"), str(EVAL_SYSTEM_DIR)):
    if _ruta not in sys.path:
        sys.path.insert(0, _ruta)

try:
    from anthropic import AsyncAnthropic

    from phishing_orchestrator import config
    from phishing_orchestrator.mcp_client import MCPClientManager
    from phishing_orchestrator.orchestrator import OrchestratorError, run_analysis
    from run_evaluation import (
        PRECIO_INPUT_POR_M,
        PRECIO_OUTPUT_POR_M,
        ResultCapturingMCPClient,
        UsageTrackingAnthropic,
    )

    ERROR_IMPORT_ORQUESTADOR: str | None = None
except Exception as exc:  # noqa: BLE001 - cualquier fallo de import debe mostrarse en la UI, no tumbarla
    ERROR_IMPORT_ORQUESTADOR = f"{type(exc).__name__}: {exc}"


# ==========================================================================
# Utilidades de presentacion
# ==========================================================================


def na(valor: Any, formato: str | None = None) -> str:
    """Texto para mostrar un campo que puede faltar: 'N/A' si es None o no existe."""
    if valor is None or valor == "":
        return "N/A"
    try:
        return format(valor, formato) if formato else str(valor)
    except (TypeError, ValueError):
        return str(valor)


def a_float(valor: Any) -> float | None:
    try:
        return None if valor is None or isinstance(valor, bool) else float(valor)
    except (TypeError, ValueError):
        return None


def badge(texto: str, color: str) -> str:
    return (
        f'<span style="background:{color};color:white;border-radius:6px;font-weight:700;font-size:0.8rem;'
        f'padding:2px 9px;margin-right:6px;display:inline-block;">{html.escape(texto)}</span>'
    )


def etiqueta_real(fila: dict[str, Any]) -> int | None:
    try:
        valor = int(float(fila.get("label_real")))
    except (TypeError, ValueError):
        return None
    return valor if valor in (0, 1) else None


def resultado_confusion(fila: dict[str, Any]) -> str:
    """TP/TN/FP/FN segun label_real y el campo clasificacion; 'N/A' si falta alguno."""
    real, pred = etiqueta_real(fila), fila.get("clasificacion")
    if real is None or pred not in ("phishing", "legitimo"):
        return "N/A"
    if real == 1:
        return "TP" if pred == "phishing" else "FN"
    return "FP" if pred == "phishing" else "TN"


def id_corto(id_: Any) -> str:
    texto = str(id_)
    texto = texto.replace("phishing_pot_sample-", "pp-").replace("trec_2007_", "trec-")
    return texto if len(texto) <= 22 else "…" + texto[-21:]


def nivel_riesgo(puntaje: float | None) -> tuple[str, str]:
    """(texto, color): bajo < 0.3, medio 0.3-0.6, alto > 0.6."""
    if puntaje is None:
        return "Riesgo sin calcular", COLOR_GRIS
    if puntaje < 0.3:
        return "Riesgo bajo", COLOR_VERDE
    if puntaje <= 0.6:
        return "Riesgo medio", COLOR_AMARILLO
    return "Riesgo alto", COLOR_ROJO


# ==========================================================================
# Reporte explicativo de un correo (compartido por las dos pestanas)
# ==========================================================================


def _bloque_veredicto(fila: dict[str, Any]) -> None:
    """Tarjeta principal: que concluyo el sistema, en una frase, con el puntaje de riesgo."""
    clasificacion = fila.get("clasificacion")
    puntaje = a_float(fila.get("puntaje_riesgo"))
    riesgo, color_riesgo = nivel_riesgo(puntaje)

    if clasificacion == "phishing":
        icono, titulo, color = "!", "Este correo parece PHISHING", COLOR_ROJO
        consejo = "No abras sus enlaces ni adjuntos y no respondas con datos personales."
    elif clasificacion == "legitimo":
        icono, titulo, color = "", "Este correo parece LEGÍTIMO", COLOR_VERDE
        consejo = "El sistema no encontró señales suficientes de engaño."
    else:
        icono, titulo, color = "?", "El sistema no llegó a un veredicto", COLOR_GRIS
        consejo = "Revisa el detalle del error más abajo."

    ancho = 0.0 if puntaje is None else min(max(puntaje, 0.0), 1.0) * 100
    st.markdown(
        f"""
        <div style="border-left:8px solid {color};background:{color}22;border-radius:10px;padding:18px 22px;margin-bottom:10px;">
          <div style="display:flex;align-items:center;gap:16px;">
            <div style="font-size:2.8rem;line-height:1;">{icono}</div>
            <div>
              <div style="font-size:1.55rem;font-weight:800;">{titulo}</div>
              <div style="opacity:0.85;">{consejo}</div>
            </div>
          </div>
          <div style="margin-top:14px;">
            <div style="display:flex;justify-content:space-between;font-size:0.9rem;">
              <span><b style="color:{color_riesgo};">{riesgo}</b></span>
              <span>Puntaje de riesgo: <b>{na(puntaje, '.2f')}</b> de 1.00</span>
            </div>
            <div style="background:rgba(128,128,128,0.3);border-radius:8px;height:14px;overflow:hidden;">
              <div style="width:{ancho:.1f}%;background:{color_riesgo};height:100%;"></div>
            </div>
            <div style="display:flex;justify-content:space-between;font-size:0.7rem;opacity:0.7;">
              <span>0 · seguro que es legítimo</span><span>1 · seguro que es phishing</span>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _bloque_acierto(fila: dict[str, Any]) -> None:
    """Solo para correos de la evaluacion (con etiqueta real): si el sistema acerto o no, en palabras."""
    resultado = resultado_confusion(fila)
    if resultado == "N/A":
        return
    icono, frase = RESULTADO_EN_PALABRAS[resultado]
    with st.container(border=True):
        st.markdown(f"**{icono} ¿Acertó el sistema?**  \n{frase}")
        st.caption(f"Etiqueta real del correo: {'phishing' if etiqueta_real(fila) == 1 else 'legítimo'} · {resultado}")


def _bloque_explicacion(fila: dict[str, Any]) -> None:
    st.markdown("####  ¿Por qué?")
    if fila.get("explicacion"):
        st.markdown(
            f'<div style="background:rgba(128,128,128,0.12);border-radius:10px;padding:16px 20px;'
            f'line-height:1.6;font-size:1.02rem;">{html.escape(str(fila["explicacion"]))}</div>',
            unsafe_allow_html=True,
        )
    elif fila.get("modo") == "veredicto":
        st.info("El modo veredicto solo entrega la clasificación y el puntaje. Para ver el porqué, analiza el correo en modo explicación.")
    else:
        st.caption("Este resultado no incluye una explicación.")


def _tarjeta_senal(senal: Any, color: str) -> str:
    if not isinstance(senal, dict):
        senal = {"descripcion": str(senal)}
    evidencia = senal.get("evidencia")
    bloque_evidencia = (
        f'<div style="margin-top:6px;padding-left:10px;border-left:2px solid rgba(128,128,128,0.5);'
        f'font-size:0.9rem;opacity:0.85;"><b>Evidencia:</b> {html.escape(str(evidencia))}</div>'
        if evidencia else ""
    )
    return (
        f'<div style="border-left:5px solid {color};background:rgba(128,128,128,0.10);border-radius:8px;'
        f'padding:10px 14px;margin-bottom:10px;"><div style="font-weight:600;">'
        f'{html.escape(na(senal.get("descripcion")))}</div>{bloque_evidencia}</div>'
    )


def _bloque_evidencia(fila: dict[str, Any]) -> None:
    senales = fila.get("senales")
    if not (isinstance(senales, list) and senales):
        if fila.get("senales_count"):
            st.caption(f"El sistema registró {fila['senales_count']} señales, pero este archivo no trae el detalle.")
        return

    st.markdown(f"####  Evidencia encontrada ({len(senales)} señales)")
    st.caption("Cada señal viene de una fuente especializada. Ninguna decide por sí sola: el sistema las combina para llegar al veredicto.")

    por_fuente: dict[str, list[Any]] = {}
    for senal in senales:
        servidor = str(senal.get("servidor", "otra")).lower() if isinstance(senal, dict) else "otra"
        por_fuente.setdefault(servidor, []).append(senal)
    # Fuentes conocidas primero y en orden fijo; cualquier otra, al final.
    orden = [s for s in FUENTES if s in por_fuente] + [s for s in por_fuente if s not in FUENTES]

    pestanas = st.tabs([
        f"{FUENTES.get(s, ('📎', s.capitalize(), '', COLOR_GRIS))[0]} {FUENTES.get(s, ('', s.capitalize()))[1]} ({len(por_fuente[s])})"
        for s in orden
    ])
    for pestana, servidor in zip(pestanas, orden):
        _, _, aporta, color = FUENTES.get(servidor, ("📎", servidor, "", COLOR_GRIS))
        with pestana:
            if aporta:
                st.caption(f"{aporta} (servidor MCP `{servidor}`)")
            st.markdown("".join(_tarjeta_senal(s, color) for s in por_fuente[servidor]), unsafe_allow_html=True)


def _bloque_correo(correo: dict[str, Any] | None) -> None:
    if not correo or not any(correo.get(k) for k in ("sender", "subject", "body")):
        return
    with st.expander(" Ver el correo analizado"):
        st.markdown(f"**De:** {html.escape(na(correo.get('sender')))}  \n**Asunto:** {html.escape(na(correo.get('subject')))}")
        cuerpo = str(correo.get("body") or "")
        st.text(cuerpo[:MAX_CARACTERES_CORREO] or "(sin cuerpo)")
        if len(cuerpo) > MAX_CARACTERES_CORREO:
            st.caption(f"Se muestran los primeros {MAX_CARACTERES_CORREO:,} de {len(cuerpo):,} caracteres.")


def _bloque_detalles(fila: dict[str, Any]) -> None:
    with st.expander(" Detalles técnicos"):
        tokens_in, tokens_out = fila.get("input_tokens"), fila.get("output_tokens")
        hay_tokens = tokens_in is not None or tokens_out is not None
        c1, c2, c3 = st.columns(3)
        c1.metric("Tiempo de análisis", na(a_float(fila.get("tiempo_ms")) / 1000 if a_float(fila.get("tiempo_ms")) is not None else None, ".1f") + " s")
        c2.metric("Tokens usados", na((tokens_in or 0) + (tokens_out or 0) if hay_tokens else None, ","))
        c3.metric("Costo USD", na(a_float(fila.get("costo_usd")), ".4f"))
        if hay_tokens:
            st.caption(
                "El costo se estima con los precios de Claude Haiku 4.5 que usa run_evaluation.py y solo cuenta las "
                "llamadas del orquestador, no la llamada LLM interna del servidor coherence."
            )

        datos = {
            "ID": fila.get("id"),
            "Modo": fila.get("modo"),
            "Modelo orquestador": fila.get("modelo_orquestador"),
            "Servidores MCP usados": ", ".join(fila["servidores"]) if isinstance(fila.get("servidores"), dict) else None,
        }
        st.markdown("  \n".join(f"**{k}:** {v}" for k, v in datos.items() if v))

        if fila.get("arquetipo_label") or fila.get("arquetipo_id") is not None:
            st.markdown(f"**Arquetipo más parecido:** #{na(fila.get('arquetipo_id'))} — {na(fila.get('arquetipo_label'))}")

        indicadores = fila.get("vt_indicadores")
        if isinstance(indicadores, list) and indicadores:
            veredictos = fila.get("vt_resultados") if isinstance(fila.get("vt_resultados"), dict) else {}
            st.markdown(f"**Indicadores consultados en VirusTotal ({len(indicadores)}):**")
            st.markdown("\n".join(f"- `{ind}` → {na(veredictos.get(ind))}" for ind in indicadores))

        herramientas = fila.get("herramientas_invocadas")
        if isinstance(herramientas, list) and herramientas:
            st.markdown(f"**Herramientas MCP invocadas, en orden ({len(herramientas)}):**")
            st.dataframe(pd.DataFrame(herramientas), hide_index=True, width="stretch")


def mostrar_reporte(fila: dict[str, Any], correo: dict[str, Any] | None = None) -> None:
    """Reporte explicativo de un correo: veredicto, porque, evidencia y detalles.

    Sirve igual para una fila de un JSONL de evaluacion que para un analisis
    en vivo: cada bloque se muestra solo si la fila trae ese dato.
    """
    _bloque_veredicto(fila)
    if fila.get("error"):
        st.error(f"El análisis de este correo terminó con error: {fila['error']}")

    no_conectados = {s: d for s, d in fila["servidores"].items() if d != "ok"} if isinstance(fila.get("servidores"), dict) else {}
    if no_conectados:
        st.warning("Fuentes no disponibles en este análisis: " + "; ".join(f"{s} ({d})" for s, d in no_conectados.items()))

    _bloque_acierto(fila)
    _bloque_explicacion(fila)

    if fila.get("arquetipo_label"):
        st.markdown(
            f'🧩 **Tipo de ataque al que más se parece:** {html.escape(str(fila["arquetipo_label"]))}'
            '<br><span style="font-size:0.85rem;opacity:0.75;">Es una referencia, no una acusación: el sistema '
            "siempre busca el ataque conocido más parecido, también en correos legítimos.</span>",
            unsafe_allow_html=True,
        )

    _bloque_evidencia(fila)
    _bloque_correo(correo)
    _bloque_detalles(fila)


# ==========================================================================
# Pestana 1: correos evaluados
# ==========================================================================


@st.cache_data(show_spinner=False)
def parsear_jsonl(contenido: bytes) -> tuple[list[dict[str, Any]], int]:
    """Devuelve (filas, n_lineas_invalidas). Las lineas que no son un objeto JSON se cuentan y se saltan."""
    filas: list[dict[str, Any]] = []
    invalidas = 0
    for linea in contenido.decode("utf-8", errors="replace").splitlines():
        if not linea.strip():
            continue
        try:
            fila = json.loads(linea)
        except json.JSONDecodeError:
            invalidas += 1
            continue
        if isinstance(fila, dict):
            filas.append(fila)
        else:
            invalidas += 1
    return filas, invalidas


@st.cache_data(show_spinner=False)
def leer_archivo_local(ruta: str, _mtime: float) -> bytes:
    # _mtime solo participa en la clave de la cache, para releer si el archivo cambia.
    return Path(ruta).read_bytes()


@st.cache_data(show_spinner="Cargando el texto original de los correos...")
def cargar_correos(ruta: str, _mtime: float) -> dict[str, dict[str, str]]:
    """Remitente, asunto y cuerpo de cada correo evaluado, por id (los JSONL de resultados no traen el texto)."""
    tabla = pd.read_csv(ruta, usecols=["id", "sender", "subject", "body"], dtype=str).fillna("")
    return tabla.drop_duplicates("id").set_index("id").to_dict("index")


def correos_originales() -> dict[str, dict[str, str]]:
    if not CORREOS_CSV.exists():
        return {}
    try:
        return cargar_correos(str(CORREOS_CSV), CORREOS_CSV.stat().st_mtime)
    except Exception:  # noqa: BLE001 - el texto original es un extra; sin el, el reporte sigue funcionando
        return {}


def archivos_locales() -> dict[str, Path]:
    """JSONL disponibles en 'data final eval', en esta carpeta y en el repo de la tesis.

    El primero de la lista (el que se carga por defecto) es el archivo final
    de 1,000 correos en modo explicacion de 'data final eval', si existe.
    """
    encontrados: dict[str, Path] = {}
    for carpeta, origen in (
        (DATOS_FINALES_DIR, DATOS_FINALES_DIR.name),
        (EVAL_SYSTEM_DIR, EVAL_SYSTEM_DIR.name),
        (TESIS_EVAL_DIR, "Trabajo-de-Graduacion"),
    ):
        if carpeta.is_dir():
            for ruta in sorted(carpeta.glob("*.jsonl")):
                # La app es solo sobre el sistema propio: no se ofrecen los resultados del filtro externo.
                if "rspamd" in ruta.name.lower():
                    continue
                encontrados[f"{ruta.name}  ({origen})"] = ruta
    return dict(sorted(encontrados.items(), key=lambda kv: kv[1].name != ARCHIVO_POR_DEFECTO))


def pestana_evaluados() -> None:
    locales = archivos_locales()
    # El archivo final se carga solo; cambiarlo queda a un clic, fuera del camino.
    with st.expander(" Cambiar archivo de resultados"):
        subido = st.file_uploader("Subir un JSONL de resultados", type=["jsonl", "json"])
        etiqueta = st.selectbox("…o elegir uno detectado en el proyecto", list(locales)) if locales else None

    if subido is not None:
        contenido, origen = subido.getvalue(), subido.name
    elif etiqueta is not None:
        ruta = locales[etiqueta]
        contenido, origen = leer_archivo_local(str(ruta), ruta.stat().st_mtime), ruta.name
    else:
        st.info(
            f"No se encontró `{ARCHIVO_POR_DEFECTO}` en `{DATOS_FINALES_DIR}`. Colócalo ahí o sube un archivo "
            "JSONL de resultados en «Cambiar archivo de resultados»."
        )
        return

    filas, invalidas = parsear_jsonl(contenido)
    if not filas:
        st.error(f"`{origen}` no contiene ningún objeto JSON por línea.")
        return
    correos = correos_originales()

    resultados_todos = [resultado_confusion(f) for f in filas]
    aciertos = sum(r in ("TP", "TN") for r in resultados_todos)
    evaluables = sum(r != "N/A" for r in resultados_todos)
    resumen = f" El sistema acertó en {aciertos} de {evaluables}." if evaluables else ""
    aviso_invalidas = f" ({invalidas} líneas inválidas ignoradas.)" if invalidas else ""
    st.caption(f"**{len(filas)} correos** en `{origen}`.{resumen}{aviso_invalidas} Elige uno de la lista para ver su reporte.")

    col_lista, col_reporte = st.columns([35, 65], gap="large")

    with col_lista:
        f1, f2 = st.columns(2)
        clase = f1.selectbox("Clase real", ["Todos", "Phishing", "Legítimo"])
        acierto = f2.selectbox("¿Acertó el sistema?", ["Todos", "Aciertos", "Errores"])
        busqueda = st.text_input("Buscar por id o asunto").strip().lower()

        def coincide(fila: dict[str, Any], resultado: str) -> bool:
            if clase != "Todos" and etiqueta_real(fila) != (1 if clase == "Phishing" else 0):
                return False
            if acierto == "Aciertos" and resultado not in ("TP", "TN"):
                return False
            if acierto == "Errores" and resultado not in ("FP", "FN"):
                return False
            if busqueda:
                asunto = correos.get(str(fila.get("id")), {}).get("subject", "")
                return busqueda in str(fila.get("id", "")).lower() or busqueda in asunto.lower()
            return True

        filtradas = [(f, r) for f, r in zip(filas, resultados_todos) if coincide(f, r)]
        st.caption(f"{len(filtradas)} de {len(filas)} correos")

        if filtradas:
            lista = pd.DataFrame({
                " ": [f"{RESULTADO_EN_PALABRAS.get(r, ('❔',))[0]} {r}" for _, r in filtradas],
                "correo": [correos.get(str(f.get("id")), {}).get("subject") or id_corto(f.get("id", "N/A")) for f, _ in filtradas],
                "veredicto": [{"phishing": "Phishing", "legitimo": "Legítimo"}.get(f.get("clasificacion"), "N/A") for f, _ in filtradas],
                "riesgo": [na(a_float(f.get("puntaje_riesgo")), ".2f") for f, _ in filtradas],
            })
            evento = st.dataframe(
                lista,
                hide_index=True,
                width="stretch",
                height=560,
                on_select="rerun",
                selection_mode="single-row",
                # La clave incluye los filtros para que la seleccion no apunte a otra fila al cambiarlos.
                key=f"lista_{origen}_{clase}_{acierto}_{busqueda}",
            )
            seleccion = evento.selection.rows
            seleccionada = filtradas[seleccion[0]][0] if seleccion else filtradas[0][0]
        else:
            seleccionada = None

    with col_reporte:
        if seleccionada is None:
            st.info("Ningún correo coincide con los filtros.")
        else:
            correo = correos.get(str(seleccionada.get("id")))
            st.markdown(f"### {html.escape((correo or {}).get('subject') or str(seleccionada.get('id', 'N/A')))}")
            st.caption(f"ID: {na(seleccionada.get('id'))}" + (f" · De: {correo['sender']}" if correo and correo.get("sender") else ""))
            mostrar_reporte(seleccionada, correo)


# ==========================================================================
# Pestana 2: servicio MCP persistente
# ==========================================================================

_PATRON_TOOL = re.compile(r"@\w+\.tool\([^)]*\)\s*(?:@[^\n]*\s*)*(?:async\s+)?def\s+(\w+)")
_CARPETAS_IGNORADAS = {".venv", "venv", "node_modules", "tests", "__pycache__", ".git", "build", "dist"}


@st.cache_data(show_spinner=False)
def herramientas_en_codigo(cwd: str | None) -> list[str]:
    """Nombres de las funciones decoradas con @mcp.tool() en los .py del servidor (sin arrancarlo)."""
    if not cwd or not Path(cwd).is_dir():
        return []
    nombres: list[str] = []
    for ruta in Path(cwd).rglob("*.py"):
        if _CARPETAS_IGNORADAS.intersection(ruta.relative_to(cwd).parts):
            continue
        try:
            nombres.extend(_PATRON_TOOL.findall(ruta.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
    return list(dict.fromkeys(nombres))


class ServicioMCP:
    """Mantiene los servidores MCP arrancados y conectados entre analisis.

    Streamlit vuelve a ejecutar el script en cada interaccion, y una sesion
    MCP solo vive dentro del event loop (y la tarea) que la abrio. Por eso
    las conexiones viven en un hilo propio con su event loop: una corutina
    de larga vida abre el MCPClientManager y se queda esperando, y cada
    analisis se envia a ese mismo loop. Asi los servidores (y el modelo de
    embeddings de archetype) se cargan una sola vez por proceso de la app.
    """

    def __init__(self) -> None:
        # En Windows se fuerza ProactorEventLoop: los servidores MCP son
        # subprocesos y el loop selector no los soporta.
        self._loop = asyncio.ProactorEventLoop() if sys.platform == "win32" else asyncio.new_event_loop()
        threading.Thread(target=self._loop.run_forever, name="servicio-mcp", daemon=True).start()
        self.estado = "detenido"  # detenido | conectando | listo | error
        self.estados: dict[str, str] = {}
        self.herramientas: dict[str, list[str]] = {}
        self.error: str | None = None
        self.segundos_conexion: float | None = None
        self._cliente: Any = None
        self._anthropic: Any = None
        self._detener: asyncio.Event | None = None
        self._futuro: Any = None

    def iniciar(self, servidores: dict[str, Any]) -> None:
        """Arranca la conexion en segundo plano; no hace nada si ya esta conectando o lista."""
        if self.estado in ("conectando", "listo"):
            return
        self.estado, self.error = "conectando", None
        self._futuro = asyncio.run_coroutine_threadsafe(self._servir(servidores), self._loop)

    async def _servir(self, servidores: dict[str, Any]) -> None:
        self._detener = asyncio.Event()
        inicio = time.monotonic()
        try:
            async with MCPClientManager(servidores) as cliente:
                self.estados = await cliente.connect_all()
                herramientas: dict[str, list[str]] = {sid: [] for sid in servidores}
                for tool in cliente.get_anthropic_tools():
                    sid, nombre = tool["name"].split("__", 1)
                    herramientas[sid].append(nombre)
                self.herramientas = herramientas

                # Precalentamiento: archetype carga su modelo de embeddings en
                # la primera clasificacion (varios segundos). Se paga aqui,
                # una vez, y no dentro del primer analisis. Es local: no usa
                # ningun LLM ni gasta tokens.
                if cliente.is_connected("archetype"):
                    await cliente.call_tool("archetype__classify_archetype", {"email_text": "precalentamiento"})

                self._cliente = cliente
                self.segundos_conexion = time.monotonic() - inicio
                self.estado = "listo"
                await self._detener.wait()
        except Exception as exc:  # noqa: BLE001
            self.error = f"{type(exc).__name__}: {exc}"
            self.estado = "error"
        finally:
            self._cliente = None
            if self.estado != "error":
                self.estado = "detenido"

    def detener(self, espera_s: float = 30.0) -> None:
        """Cierra las sesiones y termina los subprocesos de los servidores."""
        if self._detener is not None and self._futuro is not None and not self._futuro.done():
            self._loop.call_soon_threadsafe(self._detener.set)
            try:
                self._futuro.result(timeout=espera_s)
            except Exception:  # noqa: BLE001 - al cerrar solo interesa no dejar la app colgada
                pass

    def analizar(self, email_text: str, modo: str, servidores_a_usar: list[str], settings: Any) -> dict[str, Any]:
        """Analiza un correo sobre las conexiones ya abiertas. Bloquea hasta tener el resultado."""
        if self.estado != "listo":
            raise RuntimeError("Los servidores MCP todavia no estan conectados.")
        futuro = asyncio.run_coroutine_threadsafe(
            self._analizar(email_text, modo, servidores_a_usar, settings), self._loop
        )
        return futuro.result(timeout=TIMEOUT_ANALISIS_S)

    async def _analizar(self, email_text: str, modo: str, servidores_a_usar: list[str], settings: Any) -> dict[str, Any]:
        # Un solo cliente HTTP de Anthropic para todos los analisis (reutiliza la conexion TLS).
        if self._anthropic is None:
            self._anthropic = AsyncAnthropic(api_key=settings.anthropic_api_key)
        cliente_anthropic = UsageTrackingAnthropic(self._anthropic)
        cliente_mcp = ResultCapturingMCPClient(self._cliente)

        # Todos los servidores siguen conectados; los que este analisis no
        # usa solo se ocultan al modelo, sin desconectarlos.
        conectados = set(self._cliente.connected_server_ids())
        excluir = conectados - set(servidores_a_usar)
        estados = {sid: self.estados.get(sid, "ok") for sid in servidores_a_usar}

        inicio = time.monotonic()
        corrida = await run_analysis(
            email_text=email_text,
            mode=modo,
            mcp_client=cliente_mcp,
            anthropic_client=cliente_anthropic,
            settings=settings,
            max_iterations=MAX_ITERACIONES[modo],
            connection_statuses=estados,
            force_exclude_server_ids=excluir,
        )
        tiempo_ms = int((time.monotonic() - inicio) * 1000)

        resultado = corrida.resultado.model_dump(mode="json")
        arquetipo = cliente_mcp.archetype_result if isinstance(cliente_mcp.archetype_result, dict) else {}
        tokens_in, tokens_out = cliente_anthropic.total_input_tokens, cliente_anthropic.total_output_tokens
        # Mismo esquema por correo que los JSONL de evaluacion, para reutilizar el reporte y el visor.
        fila = {
            "modo": modo,
            "clasificacion": resultado.get("clasificacion"),
            "puntaje_riesgo": resultado.get("puntaje_riesgo"),
            "arquetipo_id": arquetipo.get("archetype_id"),
            "arquetipo_label": arquetipo.get("label"),
            "vt_indicadores": list(cliente_mcp.vt_resultados.keys()),
            "vt_resultados": dict(cliente_mcp.vt_resultados),
            "input_tokens": tokens_in,
            "output_tokens": tokens_out,
            "costo_usd": round(tokens_in * PRECIO_INPUT_POR_M / 1e6 + tokens_out * PRECIO_OUTPUT_POR_M / 1e6, 6),
            "tiempo_ms": tiempo_ms,
            "error": None,
            "herramientas_invocadas": [h.model_dump(mode="json") for h in corrida.herramientas_invocadas],
            "modelo_orquestador": corrida.modelo_orquestador,
            "servidores": estados,
        }
        if modo == "explicacion":
            fila.update(
                senales_count=len(resultado.get("senales") or []),
                senales=resultado.get("senales", []),
                explicacion=resultado.get("explicacion"),
            )
        return fila


@st.cache_resource(show_spinner=False)
def obtener_servicio() -> ServicioMCP:
    """Una unica instancia por proceso de Streamlit, compartida entre reruns y pestanas del navegador."""
    servicio = ServicioMCP()
    atexit.register(servicio.detener, 10.0)  # no dejar subprocesos huerfanos al cerrar la app
    return servicio


def cargar_configuracion() -> dict[str, Any] | None:
    """Lee .env y config/mcp_servers.yaml. Si no se puede, explica donde va cada archivo y devuelve None."""
    if ERROR_IMPORT_ORQUESTADOR:
        st.info(
            "No se pudo importar el orquestador, así que no se puede leer la configuración MCP "
            f"(`{ERROR_IMPORT_ORQUESTADOR}`). Ejecuta la app con el entorno del proyecto: "
            "`uv run streamlit run experiments/eval_system/orchestrator_ui.py`."
        )
        return None
    try:
        config.load_environment()
        servidores, mode_defaults = config.load_server_configs()
    except Exception as exc:  # noqa: BLE001
        st.info(
            f"No se pudo leer la configuración MCP ({exc}). Este orquestador no usa `mcp_config.json`: la "
            f"definición de los servidores debe estar en `{config.DEFAULT_CONFIG_PATH}` y las rutas y API keys "
            f"en `{config.DEFAULT_ENV_PATH}` (copia `.env.example`)."
        )
        return None
    return {"servidores": servidores, "mode_defaults": mode_defaults}


def _tarjetas_servidores(configuracion: dict[str, Any]) -> None:
    servidores = configuracion["servidores"]
    servicio = obtener_servicio()

    # Solo se arrancan los servidores cuya carpeta existe; los demas se muestran como no disponibles.
    arrancables = {sid: cfg for sid, cfg in servidores.items() if not cfg.cwd or Path(cfg.cwd).is_dir()}
    servicio.iniciar(arrancables)

    if servicio.estado == "conectando":
        st.info("⏳ Arrancando y conectando los servidores MCP (solo ocurre una vez; el de arquetipos carga su modelo)...")
    elif servicio.estado == "listo":
        n_ok = sum(1 for e in servicio.estados.values() if e == "ok")
        st.success(
            f" {n_ok} de {len(servidores)} servidores conectados en {servicio.segundos_conexion:.0f} s. "
            "Se mantienen abiertos: cada análisis reutiliza estas conexiones."
        )
    elif servicio.estado == "error":
        st.error(f"No se pudieron arrancar los servidores: {servicio.error}")

    columnas = st.columns(len(servidores) or 1)
    for columna, (sid, cfg) in zip(columnas, servidores.items()):
        with columna.container(border=True):
            estado = servicio.estados.get(sid) if servicio.estado == "listo" else None
            if sid not in arrancables:
                insignia = badge("carpeta no encontrada", COLOR_ROJO)
            elif estado == "ok":
                insignia = badge("conectado", COLOR_VERDE)
            elif estado:
                insignia = badge("no conectó", COLOR_ROJO)
            else:
                insignia = badge(servicio.estado, COLOR_GRIS)
            st.markdown(f"**{sid}** &nbsp; {insignia}", unsafe_allow_html=True)
            if cfg.description:
                st.caption(cfg.description.strip())
            # Solo comando y argumentos: el bloque env del servidor lleva API keys y no se muestra.
            st.code(" ".join([cfg.command, *cfg.args]), language="bash")
            if cfg.cwd:
                st.caption(f"{'' if sid in arrancables else ' no existe:'} {cfg.cwd}")
            if estado and estado != "ok":
                st.warning(estado)

            if estado == "ok":
                nombres, fuente = servicio.herramientas.get(sid, []), "reportadas por el servidor"
            else:
                nombres, fuente = herramientas_en_codigo(cfg.cwd), "leídas del código (`@mcp.tool()`)"
            if nombres:
                with st.expander(f"Herramientas ({len(nombres)}), {fuente}"):
                    st.markdown("\n".join(f"- `{n}`" for n in nombres))
            elif not cfg.cwd:
                st.caption("Servidor de terceros sin código local: sus herramientas se conocen al conectar.")
            else:
                st.caption("No se encontraron decoradores `@mcp.tool()` en su código.")

    if servicio.estado in ("listo", "error") and st.button(" Reconectar servidores"):
        servicio.detener()
        servicio.estado = "detenido"
        st.rerun()

    # Cuando la conexion termina, se refresca la app completa para habilitar el formulario.
    if st.session_state.get("mcp_estado_visto") != servicio.estado:
        st.session_state["mcp_estado_visto"] = servicio.estado
        if servicio.estado != "conectando":
            st.rerun()


def seccion_servidores(configuracion: dict[str, Any] | None) -> None:
    st.subheader("A · Servidores MCP")
    if configuracion is None:
        return
    # Mientras conecta, esta seccion se refresca sola cada 2 s; ya conectada, deja de hacerlo.
    conectando = obtener_servicio().estado in ("detenido", "conectando")
    st.fragment(_tarjetas_servidores, run_every=2 if conectando else None)(configuracion)


# ==========================================================================
# Pestana 2: analisis en vivo e historial
# ==========================================================================


def construir_texto(email: dict[str, str]) -> str:
    """Texto que recibe el orquestador: encabezados (si se dieron) y cuerpo, como un correo plano."""
    encabezados = []
    if email.get("sender"):
        encabezados.append(f"From: {email['sender']}")
    if email.get("subject"):
        encabezados.append(f"Subject: {email['subject']}")
    return ("\n".join(encabezados) + "\n\n" if encabezados else "") + email.get("body", "")


def leer_historial() -> list[dict[str, Any]]:
    if not HISTORIAL_PATH.exists():
        return []
    # Se lee directo, sin la cache por fecha de modificacion: dos analisis
    # seguidos pueden caer en la misma marca de tiempo y el segundo no se veria.
    filas, _ = parsear_jsonl(HISTORIAL_PATH.read_bytes())
    return filas


def guardar_en_historial(registro: dict[str, Any]) -> None:
    """Agrega el analisis como una linea mas de analisis_en_vivo.jsonl (no reescribe los anteriores)."""
    with HISTORIAL_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(registro, ensure_ascii=False) + "\n")


def seccion_analisis(configuracion: dict[str, Any] | None) -> None:
    st.subheader("B · Analizar un correo")
    servicio = obtener_servicio() if configuracion is not None else None
    listo = servicio is not None and servicio.estado == "listo"

    modo = st.radio(
        "Modo de análisis",
        list(MODOS),
        format_func=MODOS.get,
        horizontal=True,
        help="Veredicto: solo clasificación y puntaje, más rápido y barato. Explicación: además señales con evidencia y explicación.",
    )

    servidores_a_usar: list[str] = []
    if listo:
        conectados = [sid for sid, e in servicio.estados.items() if e == "ok"]
        por_defecto = [sid for sid in configuracion["mode_defaults"].get(modo, []) if sid in conectados]
        servidores_a_usar = st.multiselect(
            "Servidores MCP a usar en este análisis",
            conectados,
            default=por_defecto,
            key=f"servidores_{modo}",  # cada modo recuerda su propia seleccion y arranca con sus defaults
            help="Por defecto, los del modo según config/mcp_servers.yaml. Menos servidores = menos tokens y menos tiempo. VirusTotal solo se consulta si el correo trae URLs, dominios o IPs.",
        )

    with st.form("form_analisis"):
        sender = st.text_input("Remitente (sender)", placeholder='"Soporte" <soporte@banco-ejemplo.com>')
        subject = st.text_input("Asunto (subject)")
        body = st.text_area("Cuerpo (body)", height=200)
        enviar = st.form_submit_button(f"▶ Analizar con modo {MODOS[modo].lower()}", type="primary", disabled=not listo)
    if not listo and configuracion is not None:
        st.caption("El botón se habilita cuando los servidores MCP terminan de conectar (sección A).")

    if enviar:
        email = {"sender": sender.strip(), "subject": subject.strip(), "body": body.strip()}
        if not email["body"]:
            st.warning("Escribe el cuerpo del correo antes de analizar.")
        else:
            with st.spinner(f"Analizando en modo {MODOS[modo].lower()}... (los servidores ya están conectados; el tiempo es el de Claude y las herramientas)"):
                try:
                    settings = config.load_orchestrator_settings()
                    fila = servicio.analizar(construir_texto(email), modo, servidores_a_usar, settings)
                except OrchestratorError as exc:
                    st.error(f"El orquestador no pudo completar el análisis: {exc}")
                    if exc.raw_output is not None:
                        with st.expander("Respuesta cruda del modelo"):
                            st.json(exc.raw_output)
                except Exception as exc:  # noqa: BLE001 - falta la API key, timeout, servicio caido, etc.
                    st.error(f"Error al analizar ({type(exc).__name__}): {exc}")
                else:
                    ahora = datetime.now()
                    registro = {
                        "id": f"vivo_{ahora:%Y%m%d_%H%M%S}_{ahora.microsecond // 1000:03d}",
                        "timestamp": ahora.isoformat(timespec="seconds"),
                        "label_real": None,
                        **email,
                        **fila,
                    }
                    guardar_en_historial(registro)
                    st.session_state["historial_seleccion"] = registro["id"]
                    st.toast(f"Análisis guardado en {HISTORIAL_PATH.name}")


def seccion_historial() -> None:
    historial = leer_historial()
    st.subheader(f"C · Reporte del análisis ({len(historial)} realizados)")
    if not historial:
        st.caption(f"Aquí aparecerá el reporte de cada correo que analices. Cada análisis se agrega como una línea a `{HISTORIAL_PATH}`.")
        return

    recientes = historial[::-1]  # el mas nuevo primero
    with st.expander(f" Análisis anteriores ({len(recientes)}): elige uno para volver a ver su reporte", expanded=len(recientes) > 1):
        tabla = pd.DataFrame({
            "fecha": [na(f.get("timestamp")).replace("T", " ") for f in recientes],
            "asunto": [na(f.get("subject")) for f in recientes],
            "modo": [na(f.get("modo")) for f in recientes],
            "veredicto": [{"phishing": "- Phishing", "legitimo": "+ Legítimo"}.get(f.get("clasificacion"), "N/A") for f in recientes],
            "riesgo": [na(a_float(f.get("puntaje_riesgo")), ".2f") for f in recientes],
            "segundos": [na(a_float(f.get("tiempo_ms")) / 1000 if a_float(f.get("tiempo_ms")) is not None else None, ".1f") for f in recientes],
        })
        evento = st.dataframe(
            tabla, hide_index=True, width="stretch", height=min(36 * len(recientes) + 40, 260),
            on_select="rerun", selection_mode="single-row", key=f"historial_{len(historial)}",
        )
        st.download_button(
            "⬇ Descargar analisis_en_vivo.jsonl",
            data=HISTORIAL_PATH.read_bytes(),
            file_name=HISTORIAL_PATH.name,
            mime="application/x-ndjson",
        )

    if evento.selection.rows:
        seleccionado = recientes[evento.selection.rows[0]]
        st.session_state["historial_seleccion"] = seleccionado.get("id")
    else:
        # Sin clic en la tabla: el analisis recien hecho, o el mas reciente.
        buscado = st.session_state.get("historial_seleccion")
        seleccionado = next((f for f in recientes if f.get("id") == buscado), recientes[0])

    st.markdown(f"### {html.escape(seleccionado.get('subject') or '(sin asunto)')}")
    st.caption(
        f"Analizado el {na(seleccionado.get('timestamp')).replace('T', ' a las ')} en modo {na(seleccionado.get('modo'))}"
        + (f" · De: {seleccionado['sender']}" if seleccionado.get("sender") else "")
    )
    mostrar_reporte(seleccionado, {k: seleccionado.get(k) for k in ("sender", "subject", "body")})


# ==========================================================================
# App
# ==========================================================================


def main() -> None:
    st.set_page_config(layout="wide", page_title="Phishing Detector UI")
    st.title("Phishing Detector UI")
    st.caption("Detección explicable de phishing: un modelo Claude coordina cuatro servidores MCP y explica su veredicto.")

    tab_evaluados, tab_vivo = st.tabs(["Correos evaluados", "Análisis en vivo"])
    with tab_evaluados:
        pestana_evaluados()
    with tab_vivo:
        configuracion = cargar_configuracion()
        seccion_servidores(configuracion)
        st.divider()
        seccion_analisis(configuracion)
        st.divider()
        seccion_historial()


main()

# Como ejecutar (desde la raiz del repo del orquestador):
#
#   uv sync --extra ui                # una sola vez (agrega los demas --extra que uses)
#   uv run streamlit run experiments/eval_system/orchestrator_ui.py
#
# o, con el entorno virtual ya activado y desde esta carpeta:
#
#   streamlit run orchestrator_ui.py
#
# Los servidores MCP se arrancan solos al abrir la app y quedan conectados
# hasta que se cierra (Ctrl+C en la terminal).
