"""
Acceso a los arquetipos de ataques de phishing (pattern-analysis-mcp).

Carga archetypes.json y kmeans_archetypes.pkl, generados por el notebook
01_construccion_arquetipos.ipynb, y expone la logica de clasificacion de un
correo nuevo contra esos arquetipos. Esta capa es independiente del servidor
MCP para poder probarse de forma aislada.

A diferencia de versiones anteriores, los arquetipos se construyen unicamente
a partir de los correos de phishing del corpus de entrenamiento (data/train.csv,
label == 1), agrupados con KMeans. No hay una nocion de "pureza" o "composicion
de clases" porque el corpus de origen es de una sola clase: cada arquetipo
representa un patron de ataque (con su emocion dominante y su tactica de
ingenieria social), no una mezcla de phishing y correo legitimo.

Principio de diseño: clasificar un correo nuevo produce una señal estadística de
similitud con un patron de ataque observado en el corpus de entrenamiento, no un
veredicto de phishing. Una similitud alta indica parecido a un patron de ataque
conocido; una similitud baja no prueba que el correo sea legitimo (el store no
conoce ningun patron de correo legitimo). La decision final es del orquestador.

Convencion de normalizacion: los embeddings que se generan aqui para un correo
nuevo estan normalizados a norma L2 = 1, igual que los que se usaron para
entrenar KMeans. La similitud reportada se calcula como coseno entre el
embedding del correo y el centroide (normalizado) del cluster asignado por
KMeans.
"""

from __future__ import annotations

import os
import pickle
from pathlib import Path
from typing import Any, Optional

# El modelo de embeddings ya debe estar descargado en cache local (se uso para
# construir los arquetipos en el notebook). Se fuerza modo offline por defecto
# para que el servidor no dependa de conectividad a Hugging Face en cada
# arranque; esto tambien evita llamadas de red innecesarias en cada consulta.
# Se puede desactivar seteando estas variables antes de importar este modulo.
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

import json

import numpy as np
from sentence_transformers import SentenceTransformer

# Ruta a los artifacts, generados en la raiz del proyecto (no dentro del paquete).
# src/pattern_analysis_mcp/archetypes.py -> sube 3 niveles hasta la raiz.
_ARTIFACTS_DIR = Path(__file__).resolve().parents[2] / "artifacts"
_ARCHETYPES_PATH = _ARTIFACTS_DIR / "archetypes.json"
_KMEANS_PATH = _ARTIFACTS_DIR / "kmeans_archetypes.pkl"

_CAVEAT_CLASIFICACION = (
    "This store only contains phishing attack archetypes, built by clustering "
    "the phishing-labeled emails of the training corpus; it has no knowledge of "
    "legitimate mail. A high similarity score means the email resembles a known "
    "phishing attack pattern (with the given dominant emotion and social "
    "engineering tactic), not proof by itself that the email is phishing. A low "
    "similarity score means the email does not closely resemble any known "
    "attack pattern, which is a weak signal only, not proof that the email is "
    "legitimate. The final classification belongs to the orchestrator."
)


class ArchetypeStore:
    """Encapsula los arquetipos de ataque y la logica de clasificacion por
    cercania al cluster KMeans mas similar."""

    def __init__(
        self,
        archetypes_path: Path | str = _ARCHETYPES_PATH,
        kmeans_path: Path | str = _KMEANS_PATH,
        modelo: Optional[SentenceTransformer] = None,
    ):
        with open(archetypes_path, encoding="utf-8") as f:
            data: dict[str, Any] = json.load(f)

        self.meta: dict = data.get("meta", {})
        # El JSON usa las llaves como string (requisito de JSON); aqui se
        # normalizan a int, que es como se referencia un arquetipo en el resto
        # del codigo y en la API del servidor MCP.
        self.archetypes: dict[int, dict] = {
            int(cid): perfil for cid, perfil in data.get("archetypes", {}).items()
        }

        with open(kmeans_path, "rb") as f:
            self.kmeans = pickle.load(f)

        if len(self.archetypes) != self.kmeans.cluster_centers_.shape[0]:
            raise ValueError(
                f"Desalineacion entre archetypes.json ({len(self.archetypes)} "
                f"arquetipos) y kmeans_archetypes.pkl "
                f"({self.kmeans.cluster_centers_.shape[0]} clusters). Vuelve a "
                "correr el notebook de construccion de arquetipos."
            )

        # Centroides normalizados a norma L2 = 1, para poder reportar la
        # similitud coseno con el correo clasificado (KMeans internamente usa
        # distancia euclidiana sobre los centroides sin normalizar).
        self._centroides_normalizados = self.kmeans.cluster_centers_ / np.linalg.norm(
            self.kmeans.cluster_centers_, axis=1, keepdims=True
        )

        # El modelo de embeddings se carga perezosamente (no en __init__), para
        # que las pruebas y consultas que no lo necesitan (list/get) sean
        # instantaneas y no dependan de tener el modelo descargado.
        self._modelo = modelo

    @property
    def modelo(self) -> SentenceTransformer:
        """Carga el modelo de sentence-transformers en el primer uso."""
        if self._modelo is None:
            nombre = self.meta.get("modelo_embedding", "all-MiniLM-L6-v2")
            self._modelo = SentenceTransformer(nombre)
        return self._modelo

    # ---- Embeddings ---------------------------------------------------------

    def embed(self, texto: str) -> np.ndarray:
        """
        Genera el embedding normalizado de un texto.

        Usa el mismo modelo y la misma convencion de normalizacion (norma L2 = 1)
        con las que se entreno KMeans, para que la asignacion de cluster y la
        similitud coseno contra el centroide sean validas.
        """
        return self.modelo.encode(
            [texto], normalize_embeddings=True, convert_to_numpy=True
        )[0]

    # ---- Clasificacion -------------------------------------------------------

    def classify_from_embedding(self, vector: np.ndarray) -> dict:
        """
        Encuentra el arquetipo (cluster KMeans) mas cercano a un embedding ya
        calculado.

        Separado de 'classify' para poder probar la logica de similitud sin
        depender de cargar el modelo de sentence-transformers.
        """
        archetype_id = int(self.kmeans.predict(vector.reshape(1, -1))[0])
        arquetipo = self.archetypes[archetype_id]
        similarity = float(vector @ self._centroides_normalizados[archetype_id])

        return {
            "archetype_id": archetype_id,
            "similarity": similarity,
            "label": arquetipo["label"],
            "dominant_emotion": arquetipo["dominant_emotion"],
            "social_engineering_tactic": arquetipo["social_engineering_tactic"],
            "top_phrases": arquetipo["top_phrases"],
            "sample_count": arquetipo["sample_count"],
            "caveat": _CAVEAT_CLASIFICACION,
        }

    def classify(self, texto: str) -> dict:
        """Genera el embedding de un correo nuevo y lo clasifica contra los
        arquetipos (ver 'classify_from_embedding')."""
        vector = self.embed(texto)
        return self.classify_from_embedding(vector)

    # ---- Listados y detalle ---------------------------------------------------

    def list_archetypes(self) -> list[dict]:
        """Perfil resumido de todos los arquetipos, ordenados por id."""
        return [
            {
                "id": cid,
                "label": a["label"],
                "sample_count": a["sample_count"],
                "dominant_emotion": a["dominant_emotion"],
                "social_engineering_tactic": a["social_engineering_tactic"],
                "top_phrases": a["top_phrases"],
            }
            for cid, a in sorted(self.archetypes.items())
        ]

    def get_archetype(self, archetype_id: int) -> Optional[dict]:
        """Perfil completo de un arquetipo (incluye correos representativos), o
        None si no existe ese id."""
        a = self.archetypes.get(archetype_id)
        if a is None:
            return None
        return {
            "id": archetype_id,
            "label": a["label"],
            "sample_count": a["sample_count"],
            "dominant_emotion": a["dominant_emotion"],
            "social_engineering_tactic": a["social_engineering_tactic"],
            "top_phrases": a["top_phrases"],
            "representative_examples": a["representative_examples"],
        }


# Instancia por defecto, cargada al importar el modulo (igual que knowledge.py).
store = ArchetypeStore()
