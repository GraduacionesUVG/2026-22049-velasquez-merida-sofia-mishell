"""Modelos Pydantic para la salida estructurada y validada del orquestador.

El veredicto final (clasificacion y puntaje de riesgo) siempre lo emite el
orquestador. Los servidores MCP consultados no clasifican, solo aportan
evidencia; por eso ninguno de estos modelos representa la salida de un MCP
individual, sino la sintesis que hace el modelo orquestador.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Clasificacion(str, Enum):
    PHISHING = "phishing"
    LEGITIMO = "legitimo"


class VeredictoOutput(BaseModel):
    """Salida minima del modo veredicto: solo clasificacion y puntaje de riesgo."""

    clasificacion: Clasificacion
    puntaje_riesgo: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "Puntaje de riesgo de phishing entre 0 (legitimo con certeza) y "
            "1 (phishing con certeza)."
        ),
    )


class SenalDetectada(BaseModel):
    """Una senal individual aportada por uno de los servidores MCP consultados."""

    servidor: str = Field(
        description="Servidor MCP que aporto la senal: knowledge, archetype, coherence o virustotal."
    )
    descripcion: str = Field(description="Que se detecto, en lenguaje claro.")
    evidencia: str = Field(
        description=(
            "Cita o dato concreto que respalda la senal: texto literal del "
            "correo, o resultado devuelto por la herramienta MCP."
        )
    )


class ExplicacionOutput(VeredictoOutput):
    """Salida completa del modo explicacion: veredicto mas senales y explicacion."""

    senales: list[SenalDetectada] = Field(default_factory=list)
    explicacion: str = Field(
        description=(
            "Explicacion en lenguaje claro que integra los hallazgos de los "
            "servidores MCP consultados, con evidencia citada."
        )
    )


class ServerCallStatus(BaseModel):
    """Estado de conexion de un servidor MCP durante una corrida."""

    server_id: str
    connected: bool
    detail: str | None = None


class ToolInvocation(BaseModel):
    """Registro de una llamada a herramienta MCP hecha durante el analisis.

    Sirve para trazabilidad y para el analisis de ablation (que tanto se usa
    cada servidor segun el modo y la configuracion).
    """

    servidor: str
    herramienta: str
    ok: bool
    error: str | None = None


class OrchestratorRunResult(BaseModel):
    """Resultado completo de una corrida del orquestador sobre un correo."""

    modo: str
    modelo_orquestador: str
    servidores_habilitados: list[str]
    servidores_conectados: list[ServerCallStatus]
    herramientas_invocadas: list[ToolInvocation] = Field(default_factory=list)
    resultado: VeredictoOutput | ExplicacionOutput


class VirusTotalEstado(str, Enum):
    """Estado de la verificacion de VirusTotal para una fila del modo lote."""

    NO_HABILITADO = "no_habilitado"  # virustotal no estaba en el --mcp de esta corrida
    NO_EVALUADO = "no_evaluado"  # la fila fallo antes de saberse si aplicaba o no
    NO_APLICA = "no_aplica"  # habilitado, pero el correo no tenia URLs/dominios/IPs
    PENDIENTE_CUOTA = "pendiente_cuota"  # se intento pero la cuota de VT esta agotada
    OK = "ok"  # se consulto VT exitosamente al menos una vez
    ERROR = "error"  # fallo de VT no relacionado con cuota (ej. key invalida)


class EstadoFila(str, Enum):
    COMPLETADO = "completado"
    FALLIDO = "fallido"


class BatchRowResult(BaseModel):
    """Una fila del CSV de resultados del modo lote (veredicto)."""

    fila_idx: int
    label: str | None = None
    clasificacion: Clasificacion | None = None
    puntaje_riesgo: float | None = None
    virustotal_estado: VirusTotalEstado
    estado_fila: EstadoFila
    error: str | None = None
    timestamp: str
