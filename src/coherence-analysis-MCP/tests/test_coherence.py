"""
Pruebas unitarias de la capa de coherencia (sin arrancar el servidor MCP).
No llaman a ninguna API: usan MockEngine o construyen los modelos Pydantic
directamente. No dependen de fixtures de pytest (como monkeypatch), para
poder correr igual con  python tests/test_coherence.py  o con  pytest.
Ejecutar con:  python tests/test_coherence.py
"""

import os
import sys
from contextlib import contextmanager
from pathlib import Path

from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from coherence_analysis_mcp import coherence  # noqa: E402
from coherence_analysis_mcp.llm_engine import (  # noqa: E402
    MOCK_EMAIL_TEXT,
    LLMEngine,
    LLMEngineError,
    MockEngine,
    get_engine,
)
from coherence_analysis_mcp.schema import (  # noqa: E402
    CATEGORY_DESCRIPTIONS,
    CoherenceReport,
    Incoherence,
    IncoherenceCategory,
)


@contextmanager
def _env(name: str, value: str | None):
    """Fija (o borra, si value es None) una variable de entorno y la restaura al salir."""
    original = os.environ.get(name)
    if value is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = value
    try:
        yield
    finally:
        if original is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = original


def test_schema_valido():
    reporte = CoherenceReport(
        incoherences=[
            Incoherence(
                category=IncoherenceCategory.SENDER_VS_CONTENT,
                description="Saludo generico pese a afirmar ser un banco conocido.",
                quote="Dear Customer,",
            )
        ],
        coherence_score=0.2,
        summary="El correo tiene una incoherencia de remitente vs. contenido.",
    )
    assert reporte.discarded_count == 0
    assert reporte.incoherences[0].category == IncoherenceCategory.SENDER_VS_CONTENT
    print("  OK schema valido")


def test_schema_rechaza_categoria_invalida():
    try:
        Incoherence(
            category="categoria_que_no_existe",
            description="x",
            quote="x",
        )
        raise AssertionError("Deberia haber fallado con una categoria invalida")
    except ValidationError:
        pass
    print("  OK schema rechaza categoria invalida")


def test_schema_rechaza_score_fuera_de_rango():
    for score_invalido in (-0.1, 1.5):
        try:
            CoherenceReport(incoherences=[], coherence_score=score_invalido, summary="x")
            raise AssertionError(f"Deberia haber fallado con score={score_invalido}")
        except ValidationError:
            pass
    print("  OK schema rechaza coherence_score fuera de [0, 1]")


def test_seis_categorias_documentadas():
    assert len(IncoherenceCategory) == 6
    assert set(CATEGORY_DESCRIPTIONS.keys()) == set(IncoherenceCategory)
    for descripcion in CATEGORY_DESCRIPTIONS.values():
        assert descripcion.strip()
    print("  OK las 6 categorias estan documentadas")


def test_filtro_evidencia_descarta_cita_inexistente():
    incoherencias = [
        Incoherence(
            category=IncoherenceCategory.SENDER_VS_CONTENT,
            description="Cita real, existe en el correo.",
            quote="Dear Customer,",
        ),
        Incoherence(
            category=IncoherenceCategory.IDENTITY_CONSISTENCY,
            description="Cita inventada, no existe en el correo.",
            quote="This exact sentence does not appear anywhere in the email.",
        ),
    ]
    validas, descartadas = coherence._filter_valid_incoherences(
        incoherencias, MOCK_EMAIL_TEXT
    )
    assert len(validas) == 1
    assert validas[0].quote == "Dear Customer,"
    assert descartadas == 1
    print("  OK el filtro de evidencia descarta citas que no existen en el correo")


def test_filtro_evidencia_tolera_espacios():
    # La cita real esta en una sola linea; se prueba con espacios extra
    # alrededor para comprobar que la normalizacion de espacios funciona.
    incoherencias = [
        Incoherence(
            category=IncoherenceCategory.AUTHORITY_VS_EXECUTION,
            description="Cita real con espacios extra.",
            quote="   thank u,   ",
        )
    ]
    validas, descartadas = coherence._filter_valid_incoherences(
        incoherencias, MOCK_EMAIL_TEXT
    )
    assert len(validas) == 1
    assert descartadas == 0
    print("  OK el filtro de evidencia normaliza espacios en blanco")


def test_mock_engine_es_fijo_y_no_usa_red():
    motor = MockEngine()
    assert isinstance(motor, LLMEngine)
    r1 = motor.generate_structured("sistema", "usuario", CoherenceReport)
    r2 = motor.generate_structured("otro sistema", "otro usuario", CoherenceReport)
    assert r1 == r2, "MockEngine deberia devolver siempre la misma respuesta fija"
    # Debe validar contra el esquema real
    CoherenceReport.model_validate(r1)
    print("  OK MockEngine devuelve siempre la misma respuesta valida")


def test_get_engine_usa_mock_por_defecto():
    with _env("COHERENCE_LLM_PROVIDER", None):
        motor = get_engine()
        assert isinstance(motor, MockEngine)
    print("  OK get_engine() usa mock cuando no hay COHERENCE_LLM_PROVIDER")


def test_get_engine_proveedor_desconocido():
    with _env("COHERENCE_LLM_PROVIDER", "proveedor_inventado"):
        try:
            get_engine()
            raise AssertionError("Deberia haber fallado con un proveedor desconocido")
        except LLMEngineError:
            pass
    print("  OK get_engine() rechaza un proveedor desconocido")


def test_analyze_con_mock_conserva_citas_reales():
    reporte = coherence.analyze(MOCK_EMAIL_TEXT, engine=MockEngine())
    assert isinstance(reporte, CoherenceReport)
    assert len(reporte.incoherences) == 5, "Las 5 citas del mock existen en MOCK_EMAIL_TEXT"
    assert reporte.discarded_count == 0
    assert 0.0 <= reporte.coherence_score <= 1.0
    assert reporte.summary.strip()
    for incoherencia in reporte.incoherences:
        assert incoherencia.quote in MOCK_EMAIL_TEXT
    print("  OK analyze() con mock conserva las incoherencias con evidencia real")


def test_analyze_descarta_incoherencias_si_el_correo_no_las_contiene():
    # Mismo motor mock (respuesta fija), pero un correo que no contiene
    # ninguna de las citas fijas: deben descartarse todas.
    correo_distinto = "This is a completely unrelated legitimate email about a meeting."
    reporte = coherence.analyze(correo_distinto, engine=MockEngine())
    assert reporte.incoherences == []
    assert reporte.discarded_count == 5
    # El puntaje del LLM se conserva tal cual, aunque se hayan descartado
    # todas las incoherencias (decision de diseno: no se recalcula).
    assert reporte.coherence_score == 0.15
    print("  OK analyze() descarta todas las incoherencias cuando el correo no las contiene")


if __name__ == "__main__":
    print("Pruebas de la capa de coherencia...")
    test_schema_valido()
    test_schema_rechaza_categoria_invalida()
    test_schema_rechaza_score_fuera_de_rango()
    test_seis_categorias_documentadas()
    test_filtro_evidencia_descarta_cita_inexistente()
    test_filtro_evidencia_tolera_espacios()
    test_mock_engine_es_fijo_y_no_usa_red()
    test_get_engine_usa_mock_por_defecto()
    test_get_engine_proveedor_desconocido()
    test_analyze_con_mock_conserva_citas_reales()
    test_analyze_descarta_incoherencias_si_el_correo_no_las_contiene()
    print("\nTodas las pruebas unitarias pasaron.")
