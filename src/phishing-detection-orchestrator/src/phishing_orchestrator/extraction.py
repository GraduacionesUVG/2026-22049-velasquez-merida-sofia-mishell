"""Extraccion deterministica de indicadores de red en el texto de un correo.

Se usa antes de llamar al modelo para decidir si las herramientas de
VirusTotal deben ofrecerse o no en esa llamada. La deteccion es heuristica
(regex), pensada para decidir un gate barato, no para ser un parser exacto.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

import re

_URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"'()\[\]]+", re.IGNORECASE)

_IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

# Dominio "pelado" (sin http://), ej. "verifica-tu-cuenta.com". Heuristico:
# exige al menos una etiqueta de 2+ caracteres antes de un TLD alfabetico.
_BARE_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,}[a-z]{2,24}\b", re.IGNORECASE
)

_TRAILING_PUNCTUATION = ".,;:!?)\"'"


@dataclass
class NetworkIndicators:
    """Indicadores de red encontrados en un texto: URLs, dominios e IPs."""

    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)

    def has_any(self) -> bool:
        return bool(self.urls or self.domains or self.ips)


def extract_network_indicators(email_text: str) -> NetworkIndicators:
    """Extrae URLs, dominios e IPs de un texto de correo de forma deterministica."""
    urls = _dedupe(_strip_trailing_punctuation(u) for u in _URL_PATTERN.findall(email_text))
    ips = _dedupe(_IP_PATTERN.findall(email_text))
    ip_set = set(ips)

    domains: list[str] = []
    for url in urls:
        host = _extract_host(url)
        if host and host not in ip_set:
            domains.append(host)

    for match in _BARE_DOMAIN_PATTERN.findall(email_text):
        candidate = match.lower().rstrip(_TRAILING_PUNCTUATION)
        if candidate not in ip_set:
            domains.append(candidate)

    return NetworkIndicators(urls=urls, domains=_dedupe(domains), ips=ips)


def _extract_host(url: str) -> str | None:
    normalized = url if "://" in url else f"http://{url}"
    netloc = urlparse(normalized).netloc
    host = netloc.split("@")[-1].split(":")[0]
    return host.lower() if host else None


def _strip_trailing_punctuation(url: str) -> str:
    return url.rstrip(_TRAILING_PUNCTUATION)


def _dedupe(items: "list[str] | map") -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered
