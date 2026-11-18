"""
Esquema de salida del analisis de coherencia, validado con Pydantic.

Define las 6 categorias de incoherencia que este servidor audita y la forma
exacta del reporte que devuelve 'analyze_coherence'. Este mismo esquema es lo
que 'get_output_schema' expone al orquestador, para que sepa de antemano que
forma tendra la respuesta.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class IncoherenceCategory(str, Enum):
    """Las 6 categorias de incoherencia interna que este servidor audita."""

    SENDER_VS_CONTENT = "sender_vs_content"
    URGENCY_VS_CHANNEL = "urgency_vs_channel"
    SUBJECT_VS_BODY = "subject_vs_body"
    AUTHORITY_VS_EXECUTION = "authority_vs_execution"
    REQUEST_VS_CONTEXT = "request_vs_context"
    IDENTITY_CONSISTENCY = "identity_consistency"


# Descripcion en lenguaje claro de cada categoria, usada tanto en el prompt
# que se le da al LLM como en la herramienta 'list_incoherence_categories'.
CATEGORY_DESCRIPTIONS: dict[IncoherenceCategory, str] = {
    IncoherenceCategory.SENDER_VS_CONTENT: (
        "The email claims to be from a known or trusted entity (a bank, a "
        "company, a service), but the greeting is generic (e.g. 'Dear "
        "customer') or the writing style does not match how that entity "
        "actually communicates."
    ),
    IncoherenceCategory.URGENCY_VS_CHANNEL: (
        "The email conveys something urgent, severe or high-stakes (account "
        "suspension, legal action, security breach), but does so through an "
        "informal tone, casual channel, or with typos/errors inconsistent "
        "with the claimed severity."
    ),
    IncoherenceCategory.SUBJECT_VS_BODY: (
        "The subject line and the body do not agree on what is being "
        "offered, requested, warned about or claimed."
    ),
    IncoherenceCategory.AUTHORITY_VS_EXECUTION: (
        "The email presents itself as official or institutional, but has "
        "grammar errors, poor formatting, broken layout, or other signs of "
        "execution inconsistent with the claimed institutional authority."
    ),
    IncoherenceCategory.REQUEST_VS_CONTEXT: (
        "The email requests sensitive data (passwords, full card numbers, "
        "PINs) or actions that the legitimate entity it claims to be would "
        "not normally request over email."
    ),
    IncoherenceCategory.IDENTITY_CONSISTENCY: (
        "The sender address, the signature and the body content name "
        "different or inconsistent entities, people or organizations."
    ),
}


class Incoherence(BaseModel):
    """Una incoherencia interna detectada, con su evidencia textual literal."""

    category: IncoherenceCategory = Field(
        description="Una de las 6 categorias de incoherencia auditadas."
    )
    description: str = Field(
        description="Descripcion breve, en lenguaje claro, de la incoherencia detectada."
    )
    quote: str = Field(
        description=(
            "Cita textual literal del correo que evidencia la incoherencia. "
            "Debe aparecer tal cual en el texto original; de lo contrario se descarta."
        )
    )


class CoherenceReport(BaseModel):
    """Reporte estructurado de auditoria de coherencia interna de un correo."""

    incoherences: list[Incoherence] = Field(
        default_factory=list,
        description="Incoherencias internas detectadas, cada una con su evidencia.",
    )
    coherence_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Puntaje global de coherencia interna: 1 = totalmente coherente, 0 = lleno de contradicciones.",
    )
    summary: str = Field(
        description="Resumen en lenguaje claro de las principales incoherencias encontradas (o de su ausencia)."
    )
    discarded_count: int = Field(
        default=0,
        ge=0,
        description=(
            "Cantidad de incoherencias que el LLM reporto pero se descartaron "
            "porque su cita no aparecia literalmente en el correo."
        ),
    )
