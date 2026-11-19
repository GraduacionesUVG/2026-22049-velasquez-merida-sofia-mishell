"""
Pruebas unitarias de la capa de conocimiento (sin arrancar el servidor).
Ejecutar con:  python tests/test_knowledge.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from knowledge_based_mcp.knowledge import KnowledgeBase  # noqa: E402


def test_carga_e_integridad():
    kb = KnowledgeBase()
    assert len(kb.entries) > 0, "La base no tiene entradas"
    # Todo id es unico
    ids = [e["id"] for e in kb.entries]
    assert len(ids) == len(set(ids)), "Hay ids duplicados"
    # Campos minimos presentes
    for e in kb.entries:
        assert e.get("id") and e.get("name") and e.get("type")
        assert e.get("definition", "").strip(), f"Definicion vacia en {e['id']}"
    print(f"  OK integridad: {len(kb.entries)} entradas")


def test_get_definition():
    kb = KnowledgeBase()
    # Por id
    d = kb.get_definition("tactic_urgency")
    assert d is not None and d["id"] == "tactic_urgency"
    # Por nombre (insensible a mayusculas/acentos)
    d2 = kb.get_definition(d["name"].upper())
    assert d2 is not None and d2["id"] == "tactic_urgency"
    # Inexistente
    assert kb.get_definition("no_existe_xyz") is None
    print("  OK get_definition")


def test_listados():
    kb = KnowledgeBase()
    tipos = kb.list_types()
    assert "social_engineering_tactic" in tipos
    entradas = kb.list_by_type("persuasion_principle")
    assert len(entradas) >= 1
    assert kb.list_by_type("tipo_inexistente") == []
    print(f"  OK listados: {len(tipos)} tipos")


def test_search():
    kb = KnowledgeBase()
    res = kb.search("invoice payment", limit=5)
    assert len(res) > 0, "La busqueda no devolvio resultados"
    # Resultados ordenados por score descendente
    scores = [r["score"] for r in res]
    assert scores == sorted(scores, reverse=True)
    # Consulta sin sentido no rompe
    assert isinstance(kb.search("zzzqqq"), list)
    print(f"  OK search: {len(res)} resultados para 'invoice payment'")


def test_reference_phrases():
    kb = KnowledgeBase()
    out = kb.match_reference_phrases("Please act now, this is urgent")
    assert "matches" in out and "caveat" in out
    # El caveat siempre debe estar presente (guardrail)
    assert "not proof" in out["caveat"].lower()
    print(f"  OK reference_phrases: {len(out['matches'])} coincidencia(s)")


def test_explain():
    kb = KnowledgeBase()
    exp = kb.explain(["tactic_urgency"])
    assert len(exp["details"]) == 1
    assert "caveat" in exp
    # Conceptos desconocidos se ignoran sin romper
    assert kb.explain(["no_existe"])["details"] == []
    print("  OK explain")


def test_gobernanza():
    kb = KnowledgeBase()
    assert kb.get_guardrails(), "Sin guardrails"
    assert kb.get_scope(), "Sin scope policy"
    assert kb.get_label_schema("dataphish") is not None
    print("  OK gobernanza (guardrails, scope, label_schema)")


if __name__ == "__main__":
    print("Pruebas de la capa de conocimiento...")
    test_carga_e_integridad()
    test_get_definition()
    test_listados()
    test_search()
    test_reference_phrases()
    test_explain()
    test_gobernanza()
    print("\nTodas las pruebas unitarias pasaron.")
