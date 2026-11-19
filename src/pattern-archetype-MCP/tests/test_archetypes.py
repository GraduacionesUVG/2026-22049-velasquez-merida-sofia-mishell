"""
Pruebas unitarias de la capa de arquetipos (sin arrancar el servidor MCP).
Ejecutar con:  python tests/test_archetypes.py
"""

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from pattern_analysis_mcp.archetypes import ArchetypeStore  # noqa: E402

_CAMPOS_ARQUETIPO = (
    "label",
    "dominant_emotion",
    "social_engineering_tactic",
    "top_phrases",
    "sample_count",
)
_EMOCIONES_VALIDAS = {"urgencia", "miedo", "confianza", "codicia", "curiosidad"}
_TACTICAS_VALIDAS = {"autoridad", "escasez", "reciprocidad", "prueba social", "simpatia"}


def test_carga_e_integridad():
    tienda = ArchetypeStore()
    assert len(tienda.archetypes) > 0, "No hay arquetipos cargados"
    assert tienda.kmeans.cluster_centers_.shape[0] == len(tienda.archetypes), (
        "Desalineacion entre archetypes.json y kmeans_archetypes.pkl"
    )
    for archetype_id, perfil in tienda.archetypes.items():
        assert isinstance(archetype_id, int), "Los ids de arquetipo deben ser int"
        for campo in _CAMPOS_ARQUETIPO:
            assert campo in perfil, f"Falta el campo '{campo}' en el arquetipo {archetype_id}"
        assert perfil["sample_count"] > 0
    print(f"  OK integridad: {len(tienda.archetypes)} arquetipos")


def test_list_archetypes():
    tienda = ArchetypeStore()
    resumen = tienda.list_archetypes()
    assert len(resumen) == len(tienda.archetypes)
    ids = [a["id"] for a in resumen]
    assert ids == sorted(ids), "list_archetypes no esta ordenado por id"

    primero = resumen[0]
    for campo in ("id", "label", "sample_count", "dominant_emotion", "social_engineering_tactic", "top_phrases"):
        assert campo in primero, f"Falta el campo '{campo}' en el resumen"
    print(f"  OK list_archetypes: {len(resumen)} arquetipos")


def test_get_archetype():
    tienda = ArchetypeStore()
    id_valido = next(iter(tienda.archetypes))
    perfil = tienda.get_archetype(id_valido)

    assert perfil is not None
    assert perfil["id"] == id_valido
    assert "representative_examples" in perfil and len(perfil["representative_examples"]) > 0

    assert tienda.get_archetype(-999999) is None, "Un id inexistente deberia devolver None"
    print("  OK get_archetype")


def test_classify_from_embedding():
    # Se prueba la logica de similitud sin cargar sentence-transformers (mas
    # rapido y no depende de tener el modelo descargado en esta maquina).
    tienda = ArchetypeStore()

    # El propio centroide normalizado del primer arquetipo debe clasificar
    # hacia ese mismo arquetipo, con similitud maxima (cercana a 1.0).
    archetype_id = next(iter(tienda.archetypes))
    vector = tienda._centroides_normalizados[archetype_id].copy()
    resultado = tienda.classify_from_embedding(vector)

    assert resultado["archetype_id"] == archetype_id
    assert resultado["similarity"] > 0.99
    for campo in ("archetype_id", "similarity", "label", "dominant_emotion", "social_engineering_tactic", "caveat"):
        assert campo in resultado, f"Falta el campo '{campo}' en el resultado de classify"
    assert "final classification belongs to the orchestrator" in resultado["caveat"].lower()
    print("  OK classify_from_embedding (logica de similitud, sin cargar el modelo)")


def test_classify_con_modelo_real():
    # Esta prueba si carga el modelo real de sentence-transformers; puede
    # tardar unos segundos la primera vez que se carga en el proceso.
    tienda = ArchetypeStore()
    resultado = tienda.classify(
        "URGENT: your account has been suspended, verify your bank details now"
    )
    assert resultado["archetype_id"] in tienda.archetypes
    assert -1.0 <= resultado["similarity"] <= 1.0
    assert resultado["dominant_emotion"] in _EMOCIONES_VALIDAS
    assert resultado["social_engineering_tactic"] in _TACTICAS_VALIDAS
    print(
        f"  OK classify con modelo real: archetype_id={resultado['archetype_id']} "
        f"similarity={resultado['similarity']:.3f} label={resultado['label']!r}"
    )


if __name__ == "__main__":
    print("Pruebas de la capa de arquetipos...")
    test_carga_e_integridad()
    test_list_archetypes()
    test_get_archetype()
    test_classify_from_embedding()
    test_classify_con_modelo_real()
    print("\nTodas las pruebas unitarias pasaron.")
