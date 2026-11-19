"""
Acceso a la base de conocimiento (knowledge-based MCP).

Carga knowledge_base.json y expone consultas deterministas sobre las
entradas, fuentes, esquemas de etiquetas y guardrails. Esta capa es
independiente del servidor MCP para poder probarse de forma aislada.

Principio de diseño: toda respuesta es trazable a entradas concretas con
sus fuentes. El servidor no emite veredictos de clasificacion; solo
provee conocimiento fundamentado (la decision final es del orquestador).
"""

from __future__ import annotations

import json
import unicodedata
from pathlib import Path
from typing import Any, Optional

# Ruta al JSON, empaquetado junto al modulo
_KB_PATH = Path(__file__).parent / "knowledge_base.json"


def _norm(text: str) -> str:
    """Minusculas y sin acentos, para comparaciones robustas."""
    text = str(text).lower().strip()
    text = "".join(
        c for c in unicodedata.normalize("NFD", text)
        if unicodedata.category(c) != "Mn"
    )
    return text


class KnowledgeBase:
    """Encapsula la base de conocimiento y sus operaciones de consulta."""

    def __init__(self, path: Path | str = _KB_PATH):
        with open(path, encoding="utf-8") as f:
            self._data: dict[str, Any] = json.load(f)

        self.meta: dict = self._data.get("meta", {})
        self.scope_policy: dict = self._data.get("scope_policy", {})
        self.guardrails: dict = self._data.get("analysis_guardrails", {})
        self.label_schemas: dict = self._data.get("label_schemas", {})
        self.sources: dict = self._data.get("sources", {})
        self.entries: list[dict] = self._data.get("entries", [])

        # Indice por id para acceso O(1)
        self._by_id: dict[str, dict] = {e["id"]: e for e in self.entries}

    # ---- Consultas de una entrada -----------------------------------------

    def get_entry(self, entry_id: str) -> Optional[dict]:
        """Devuelve la entrada completa con el id dado, o None."""
        return self._by_id.get(entry_id)

    def get_definition(self, name_or_id: str) -> Optional[dict]:
        """
        Busca una entrada por id exacto o por nombre (tolerante a
        mayusculas y acentos). Devuelve una vista con definicion y fuentes.
        """
        entry = self._by_id.get(name_or_id)
        if entry is None:
            target = _norm(name_or_id)
            for e in self.entries:
                if _norm(e["name"]) == target:
                    entry = e
                    break
        if entry is None:
            return None
        return {
            "id": entry["id"],
            "name": entry["name"],
            "type": entry["type"],
            "definition": entry["definition"],
            "why_relevant": entry.get("why_relevant", ""),
            "source_ids": entry.get("source_ids", []),
            "citations": self._citations_for(entry.get("source_ids", [])),
        }

    # ---- Listados ---------------------------------------------------------

    def list_types(self) -> list[str]:
        """Tipos de entrada disponibles, ordenados."""
        return sorted({e["type"] for e in self.entries})

    def list_by_type(self, entry_type: str) -> list[dict]:
        """Entradas de un tipo dado (id, nombre y definicion)."""
        return [
            {"id": e["id"], "name": e["name"], "definition": e["definition"]}
            for e in self.entries
            if e["type"] == entry_type
        ]

    # ---- Busqueda ---------------------------------------------------------

    def search(self, query: str, limit: int = 10) -> list[dict]:
        """
        Busca entradas relevantes a una consulta libre.

        Puntua cada entrada por coincidencias en nombre, search_terms,
        semantic_indicators y definicion. Es una busqueda lexica simple
        (no semantica); el analisis semantico corresponde a otro MCP.
        """
        q = _norm(query)
        q_tokens = set(q.split())
        scored: list[tuple[int, dict]] = []

        for e in self.entries:
            score = 0
            if q in _norm(e["name"]):
                score += 5
            for term in e.get("search_terms", []):
                if q in _norm(term) or _norm(term) in q:
                    score += 3
            for ind in e.get("semantic_indicators", []):
                if _norm(ind) in q or q in _norm(ind):
                    score += 2
            # Coincidencia por tokens en la definicion
            def_norm = _norm(e["definition"])
            score += sum(1 for t in q_tokens if len(t) > 3 and t in def_norm)

            if score > 0:
                scored.append((score, e))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [
            {
                "id": e["id"],
                "name": e["name"],
                "type": e["type"],
                "definition": e["definition"],
                "score": s,
            }
            for s, e in scored[:limit]
        ]

    def match_reference_phrases(self, text: str) -> list[dict]:
        """
        Detecta reference_phrases conocidas presentes en un texto.

        Segun los guardrails, la coincidencia literal es solo una linea
        base, no prueba de phishing. La salida lo indica explicitamente.
        """
        t = _norm(text)
        hits = []
        for e in self.entries:
            found = [p for p in e.get("reference_phrases", []) if _norm(p) in t]
            if found:
                hits.append({
                    "id": e["id"],
                    "name": e["name"],
                    "type": e["type"],
                    "matched_phrases": found,
                })
        return {
            "matches": hits,
            "caveat": (
                "Literal phrase match is a baseline signal only. Presence of "
                "these phrases is not proof of phishing, and their absence is "
                "not proof of legitimacy."
            ),
        }

    # ---- Explicacion ------------------------------------------------------

    def explain(self, concepts: list[str]) -> dict:
        """
        Genera una explicacion fundamentada a partir de conceptos
        (ids o nombres) detectados por otro componente. Encadena la
        definicion y el por-que de cada uno, citando fuentes.
        """
        details = []
        cited_ids: set[str] = set()

        for c in concepts:
            entry = self._by_id.get(c)
            if entry is None:
                view = self.get_definition(c)
                entry = self._by_id.get(view["id"]) if view else None
            if entry is None:
                continue

            related = [
                self._by_id[r]["name"]
                for r in entry.get("related_entry_ids", [])
                if r in self._by_id
            ]
            details.append({
                "concept": entry["name"],
                "type": entry["type"],
                "definition": entry["definition"],
                "why_relevant": entry.get("why_relevant", ""),
                "target_emotions": entry.get("target_emotions", []),
                "attacker_goals": entry.get("attacker_goals", []),
                "related": related,
                "source_ids": entry.get("source_ids", []),
            })
            cited_ids.update(entry.get("source_ids", []))

        return {
            "concepts_evaluated": concepts,
            "details": details,
            "citations": self._citations_for(sorted(cited_ids)),
            "caveat": (
                "This is grounded reference knowledge, not a verdict. The "
                "presence of persuasion or social-engineering tactics is not "
                "proof of phishing; the final classification belongs to the "
                "orchestrator."
            ),
        }

    # ---- Metadatos de gobernanza ------------------------------------------

    def get_guardrails(self) -> dict:
        """Devuelve los guardrails de analisis de la base."""
        return self.guardrails

    def get_scope(self) -> dict:
        """Devuelve la politica de alcance (in/out of scope)."""
        return self.scope_policy

    def get_label_schema(self, name: str = "dataphish") -> Optional[dict]:
        """Devuelve un esquema de etiquetas (por defecto, dataphish)."""
        return self.label_schemas.get(name)

    # ---- Utilidad interna -------------------------------------------------

    def _citations_for(self, source_ids: list[str]) -> list[dict]:
        """Resuelve ids de fuente a sus citas completas."""
        out = []
        for sid in source_ids:
            src = self.sources.get(sid)
            if src:
                out.append({"id": sid, "citation": src.get("citation", "")})
        return out


# Instancia por defecto
kb = KnowledgeBase()
