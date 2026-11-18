"""
Capa de abstraccion del motor LLM.

El analisis de coherencia depende de un LLM con salida estructurada, pero el
proveedor concreto (Anthropic, OpenAI, etc.) debe poder cambiarse sin tocar
'coherence.py' ni 'server.py'. 'LLMEngine' define el contrato minimo que
cualquier proveedor debe cumplir: recibir un prompt de sistema, un prompt de
usuario y un modelo Pydantic, y devolver un dict que valide contra ese modelo.

Proveedor real implementado: Anthropic, via tool use forzado (tool_choice),
que es el mecanismo mas confiable que ofrece su API para obtener JSON valido
segun un esquema, sin depender de que el modelo "decida" envolver la
respuesta en markdown o texto libre. 'coherence.py' igual vuelve a validar el
resultado con Pydantic antes de confiar en el.

'MockEngine' devuelve siempre la misma respuesta fija y valida, calibrada
sobre 'MOCK_EMAIL_TEXT' (un correo de referencia definido en este mismo
modulo). Existe para poder correr el servidor y las pruebas sin llamar a
ninguna API ni necesitar una API key. Es el proveedor por defecto
('COHERENCE_LLM_PROVIDER=mock') para que el proyecto funcione "out of the
box" sin configuracion.

Agregar un proveedor nuevo: crear una subclase de 'LLMEngine' que implemente
'generate_structured', y agregar una rama para su nombre en 'get_engine'.
"""

from __future__ import annotations

import abc
import os
from typing import Type

from pydantic import BaseModel


class LLMEngineError(RuntimeError):
    """Se lanza cuando el motor LLM configurado no puede producir una respuesta usable."""


class LLMEngine(abc.ABC):
    """Contrato minimo de un motor LLM con salida estructurada."""

    @abc.abstractmethod
    def generate_structured(
        self, system_prompt: str, user_prompt: str, schema: Type[BaseModel]
    ) -> dict:
        """
        Llama al LLM y devuelve un dict cuyo contenido deberia validar contra
        'schema'. El llamador (coherence.py) es responsable de validarlo con
        Pydantic; este metodo solo se encarga de obtener el JSON del proveedor.
        """
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Mock: respuesta fija, sin red, calibrada sobre MOCK_EMAIL_TEXT.
# ---------------------------------------------------------------------------

# Correo de referencia sobre el que esta calibrada la respuesta de MockEngine:
# cada 'quote' en MOCK_RESPONSE aparece literal en este texto, para que el
# validador de evidencia de coherence.py las acepte tal cual. Usar este texto
# (o texto que contenga las mismas citas) en pruebas que quieran ver
# incoherencias sobrevivir al filtro de evidencia.
MOCK_EMAIL_TEXT = """Subject: Account Verification Required

Dear Customer,

We regret to inform you that suspicious activity has been detected on your account. This is extremely urgent, you must act now or your account will be permanently closed within 24 hrs!!

pls click the link below and confirm ur password and full card number to avoid suspension.

http://secure-verification-center.example/confirm

thank u,
Wells Fargo Security Team
support@paypal-alerts.example
"""

# Respuesta fija devuelta por MockEngine, con forma de CoherenceReport
# (ver schema.py). 'discarded_count' se deja en 0 aqui: coherence.py lo
# recalcula siempre a partir del filtro de evidencia real.
MOCK_RESPONSE: dict = {
    "incoherences": [
        {
            "category": "sender_vs_content",
            "description": (
                "Claims to be from a specific bank but greets the recipient "
                "with a generic salutation instead of their name."
            ),
            "quote": "Dear Customer,",
        },
        {
            "category": "urgency_vs_channel",
            "description": (
                "Conveys a severe, time-critical threat using an informal "
                "tone and exclamation marks inconsistent with an official "
                "bank security notice."
            ),
            "quote": (
                "This is extremely urgent, you must act now or your account "
                "will be permanently closed within 24 hrs!!"
            ),
        },
        {
            "category": "request_vs_context",
            "description": (
                "Requests a password and a full card number over email, "
                "which a legitimate bank would not ask for through this "
                "channel."
            ),
            "quote": (
                "pls click the link below and confirm ur password and full "
                "card number to avoid suspension."
            ),
        },
        {
            "category": "authority_vs_execution",
            "description": (
                "Signs off with casual, poorly formatted language "
                "inconsistent with a formal institutional notice."
            ),
            "quote": "thank u,",
        },
        {
            "category": "identity_consistency",
            "description": (
                "Signs as 'Wells Fargo Security Team' but the sender address "
                "domain names a different organization entirely."
            ),
            "quote": "support@paypal-alerts.example",
        },
    ],
    "coherence_score": 0.15,
    "summary": (
        "The email shows several internal contradictions typical of "
        "impersonation attempts: a generic greeting despite claiming to be "
        "a known bank, an urgent threat delivered in an informal and "
        "error-ridden tone, a request for a full card number and password "
        "that a bank would not make by email, and a signature naming a "
        "different organization than the sender's address domain."
    ),
    "discarded_count": 0,
}


class MockEngine(LLMEngine):
    """Motor de prueba: siempre devuelve MOCK_RESPONSE, sin llamar a ninguna API."""

    def generate_structured(
        self, system_prompt: str, user_prompt: str, schema: Type[BaseModel]
    ) -> dict:
        return MOCK_RESPONSE


# ---------------------------------------------------------------------------
# Anthropic: proveedor real de referencia, via tool use forzado.
# ---------------------------------------------------------------------------


class AnthropicEngine(LLMEngine):
    """Motor real usando la API de Anthropic (Claude), con salida forzada por tool use."""

    _TOOL_NAME = "return_result"

    def __init__(self, api_key: str, model: str) -> None:
        if not api_key:
            raise LLMEngineError(
                "COHERENCE_LLM_API_KEY no esta configurada; es requerida "
                "para COHERENCE_LLM_PROVIDER='anthropic'."
            )
        import anthropic  # import perezoso: solo se necesita si se usa este proveedor

        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model

    def generate_structured(
        self, system_prompt: str, user_prompt: str, schema: Type[BaseModel]
    ) -> dict:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=2048,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
            tools=[
                {
                    "name": self._TOOL_NAME,
                    "description": "Return the structured coherence analysis result.",
                    "input_schema": schema.model_json_schema(),
                }
            ],
            tool_choice={"type": "tool", "name": self._TOOL_NAME},
        )

        for block in response.content:
            if block.type == "tool_use" and block.name == self._TOOL_NAME:
                return block.input

        raise LLMEngineError(
            "La respuesta de Anthropic no incluyo el bloque tool_use esperado."
        )


# ---------------------------------------------------------------------------
# Fabrica: selecciona el proveedor segun variables de entorno.
# ---------------------------------------------------------------------------


def get_engine() -> LLMEngine:
    """
    Construye el motor LLM configurado por entorno.

    Variables de entorno:
    - COHERENCE_LLM_PROVIDER: "mock" (por defecto) o "anthropic".
    - COHERENCE_LLM_MODEL: modelo a usar cuando el proveedor no es "mock".
    - COHERENCE_LLM_API_KEY: API key del proveedor configurado.
    """
    provider = os.environ.get("COHERENCE_LLM_PROVIDER", "mock").strip().lower()

    if provider == "mock":
        return MockEngine()

    if provider == "anthropic":
        return AnthropicEngine(
            api_key=os.environ.get("COHERENCE_LLM_API_KEY", ""),
            model=os.environ.get("COHERENCE_LLM_MODEL", "claude-sonnet-5"),
        )

    raise LLMEngineError(
        f"Proveedor de LLM desconocido: '{provider}'. Valores validos: "
        "'mock', 'anthropic'."
    )
