"""Carga y validacion de configuracion: variables de entorno y servidores MCP.

Las rutas a los servidores propios y las API keys nunca se hardcodean aqui.
Se leen desde variables de entorno (que a su vez vienen de un archivo .env
en la raiz del proyecto, ignorado por git).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "mcp_servers.yaml"
DEFAULT_ENV_PATH = PROJECT_ROOT / ".env"

_VAR_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

# Valores por defecto para variables opcionales. Documentados tambien en
# .env.example; si el usuario no los define, se aplican estos.
_DEFAULT_ENV_VALUES: dict[str, str] = {
    "ORCHESTRATOR_MODEL": "claude-haiku-4-5",
    "ORCHESTRATOR_TEMPERATURE": "0",
    "COHERENCE_LLM_MODEL": "claude-sonnet-5",
    "COHERENCE_LLM_PROVIDER": "anthropic",
    "VIRUSTOTAL_API_KEY": "",
}


class ConfigError(RuntimeError):
    """Error de configuracion del orquestador o de los servidores MCP."""


class ServerConfig(BaseModel):
    """Definicion de como arrancar un servidor MCP via stdio."""

    id: str
    ablation_key: str
    description: str = ""
    command: str
    args: list[str] = Field(default_factory=list)
    cwd: str | None = None
    env: dict[str, str] = Field(default_factory=dict)


class OrchestratorSettings(BaseModel):
    """Configuracion del modelo orquestador de Anthropic."""

    anthropic_api_key: str
    orchestrator_model: str
    orchestrator_temperature: float


def load_environment(env_path: Path | None = None) -> None:
    """Carga variables de entorno desde .env y aplica defaults para las opcionales.

    No sobrescribe variables ya presentes en el entorno del proceso, para que
    variables exportadas manualmente tengan prioridad sobre el archivo .env.
    """
    load_dotenv(dotenv_path=env_path or DEFAULT_ENV_PATH, override=False)
    for key, default_value in _DEFAULT_ENV_VALUES.items():
        os.environ.setdefault(key, default_value)


def load_orchestrator_settings() -> OrchestratorSettings:
    """Lee la configuracion del modelo orquestador desde variables de entorno."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise ConfigError(
            "ANTHROPIC_API_KEY no esta definida. Copia .env.example a .env y "
            "completa tu API key de Anthropic."
        )

    temperature_raw = os.environ.get("ORCHESTRATOR_TEMPERATURE", "0")
    try:
        temperature = float(temperature_raw)
    except ValueError as exc:
        raise ConfigError(
            f"ORCHESTRATOR_TEMPERATURE debe ser un numero, se recibio: '{temperature_raw}'"
        ) from exc

    return OrchestratorSettings(
        anthropic_api_key=api_key,
        orchestrator_model=os.environ.get("ORCHESTRATOR_MODEL", "claude-haiku-4-5"),
        orchestrator_temperature=temperature,
    )


def _interpolate(value: Any) -> Any:
    """Sustituye placeholders ${VAR} por su valor en el entorno del proceso."""
    if isinstance(value, str):
        return _VAR_PATTERN.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    return value


def load_server_configs(
    config_path: Path | None = None,
) -> tuple[dict[str, ServerConfig], dict[str, list[str]]]:
    """Lee config/mcp_servers.yaml, interpola variables de entorno y valida.

    Devuelve una tupla (servidores, mode_defaults):
    - servidores: diccionario {id_servidor: ServerConfig}.
    - mode_defaults: diccionario {modo: [ids de servidores habilitados por defecto]}.
    """
    path = config_path or DEFAULT_CONFIG_PATH
    if not path.exists():
        raise ConfigError(f"No se encontro el archivo de configuracion: {path}")

    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    raw_servers: dict[str, Any] = raw.get("servers", {})
    mode_defaults: dict[str, list[str]] = raw.get("mode_defaults", {})

    servers: dict[str, ServerConfig] = {}
    for server_id, raw_server_config in raw_servers.items():
        interpolated = _interpolate(raw_server_config)
        servers[server_id] = ServerConfig(id=server_id, **interpolated)

    return servers, mode_defaults


def validate_selected_servers(servers: dict[str, ServerConfig]) -> None:
    """Valida que las rutas cwd de los servidores dados existan.

    Se llama solo sobre el subconjunto de servidores que realmente se van a
    usar en una corrida (segun modo y --mcp), no sobre los cuatro definidos en
    mcp_servers.yaml: si el usuario solo quiere usar "knowledge", no debe
    hacer falta tener configurada la ruta de pattern-archetype-MCP.

    No valida API keys (VirusTotal, Anthropic para coherence): el orquestador
    debe poder arrancar y seguir funcionando aunque falten, tratandolo como
    fallo individual de ese servidor en tiempo de ejecucion.
    """
    for server in servers.values():
        if server.cwd and not Path(server.cwd).exists():
            raise ConfigError(
                f"El servidor '{server.id}' tiene cwd configurado en "
                f"'{server.cwd}', pero esa ruta no existe. Revisa la variable "
                "de entorno correspondiente en tu .env."
            )
