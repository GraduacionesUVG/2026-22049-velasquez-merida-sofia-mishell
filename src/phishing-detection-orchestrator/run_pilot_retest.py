"""Reprueba los 3 correos del piloto anterior con mas output_tokens (proxy de
mas iteraciones/re-consultas): trec_2007_361 (1663 out), trec_2007_374
(1307), trec_2007_155 (1208). Compara tool calls a VT, tokens y costo antes
vs. despues de: (1) instruccion "no repitas herramientas" en el system
prompt, (2) cache de tool calls por correo.
"""
import asyncio
import json

import pandas as pd
from anthropic import AsyncAnthropic

from phishing_orchestrator.config import (
    load_environment,
    load_orchestrator_settings,
    load_server_configs,
    validate_selected_servers,
)
from phishing_orchestrator.mcp_client import MCPClientManager
from phishing_orchestrator.orchestrator import OrchestratorError, run_analysis

PRECIO_INPUT_POR_M = 1.00
PRECIO_OUTPUT_POR_M = 5.00

IDS_A_REPROBAR = ["trec_2007_361", "trec_2007_374", "trec_2007_155"]

ANTERIOR = {
    "trec_2007_361": {"input_tokens": 15727, "output_tokens": 1663, "costo_usd": 0.024042},
    "trec_2007_374": {"input_tokens": 18024, "output_tokens": 1307, "costo_usd": 0.024559},
    "trec_2007_155": {"input_tokens": 17104, "output_tokens": 1208, "costo_usd": 0.023144},
}


class UsageTrackingAnthropic:
    def __init__(self, real_client: AsyncAnthropic) -> None:
        self._real = real_client
        self.messages = self
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.n_calls = 0

    async def create(self, **kwargs):
        response = await self._real.messages.create(**kwargs)
        self.total_input_tokens += response.usage.input_tokens
        self.total_output_tokens += response.usage.output_tokens
        self.n_calls += 1
        return response

    def reset(self) -> None:
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.n_calls = 0


class VTCountingMCPClient:
    """Cuenta cuantas veces se PIDE cada herramienta de virustotal (antes de
    cache) vs. cuantas realmente llegan al servidor (despues de cache)."""

    def __init__(self, real_client: MCPClientManager) -> None:
        self._real = real_client
        self.vt_calls_pedidos = 0
        self.vt_calls_a_servidor = 0
        self.detalle = []

    def __getattr__(self, name):
        return getattr(self._real, name)

    async def call_tool(self, qualified_name: str, arguments: dict, call_cache=None):
        if qualified_name.startswith("virustotal__"):
            self.vt_calls_pedidos += 1
            cache_key = (qualified_name, json.dumps(arguments, sort_keys=True, default=str)) if call_cache is not None else None
            era_cache_hit = cache_key is not None and cache_key in call_cache
            if not era_cache_hit:
                self.vt_calls_a_servidor += 1
            self.detalle.append((qualified_name, arguments, "cache" if era_cache_hit else "servidor"))
        return await self._real.call_tool(qualified_name, arguments, call_cache=call_cache)

    def reset(self) -> None:
        self.vt_calls_pedidos = 0
        self.vt_calls_a_servidor = 0
        self.detalle = []


async def main() -> None:
    load_environment()
    settings = load_orchestrator_settings()
    all_servers, _ = load_server_configs()
    server_configs = {k: v for k, v in all_servers.items() if k in ("archetype", "virustotal")}
    validate_selected_servers(server_configs)

    df = pd.read_csv(
        r"C:\Users\50250\Desktop\Sofía Mishell Velásquez UVG\Quinto año\Segundo Semestre\Tesis\Trabajo-de-Graduacion\experiments\external_eval\eval_external.csv"
    )
    muestra = df[df["id"].isin(IDS_A_REPROBAR)]

    real_anthropic = AsyncAnthropic(api_key=settings.anthropic_api_key)
    tracking_client = UsageTrackingAnthropic(real_anthropic)

    filas = []
    async with MCPClientManager(server_configs) as mcp_client:
        statuses = await mcp_client.connect_all()
        print("Servidores conectados:", statuses)
        wrapped_mcp = VTCountingMCPClient(mcp_client)

        for id_ in IDS_A_REPROBAR:
            row = muestra[muestra["id"] == id_].iloc[0]
            tracking_client.reset()
            wrapped_mcp.reset()
            email_text = str(row["body"])
            label_real = int(row["label"])

            try:
                resultado = await run_analysis(
                    email_text=email_text, mode="veredicto", mcp_client=wrapped_mcp,
                    anthropic_client=tracking_client, settings=settings, max_iterations=4,
                    connection_statuses=statuses,
                )
                clasificacion = resultado.resultado.clasificacion.value
                puntaje = resultado.resultado.puntaje_riesgo
            except OrchestratorError as exc:
                clasificacion, puntaje = None, None
                print(f"ERROR en {id_}: {exc}")

            anterior = ANTERIOR[id_]
            fila = {
                "id": id_, "label_real": label_real, "clasificacion": clasificacion, "puntaje_riesgo": puntaje,
                "vt_calls_pedidos": wrapped_mcp.vt_calls_pedidos, "vt_calls_a_servidor": wrapped_mcp.vt_calls_a_servidor,
                "n_llamadas_modelo": tracking_client.n_calls,
                "input_tokens": tracking_client.total_input_tokens, "output_tokens": tracking_client.total_output_tokens,
                "costo_usd": round((tracking_client.total_input_tokens / 1e6) * PRECIO_INPUT_POR_M +
                                    (tracking_client.total_output_tokens / 1e6) * PRECIO_OUTPUT_POR_M, 6),
                "input_tokens_antes": anterior["input_tokens"], "output_tokens_antes": anterior["output_tokens"],
                "costo_usd_antes": anterior["costo_usd"],
                "detalle_vt": wrapped_mcp.detalle,
            }
            filas.append(fila)
            print(json.dumps(fila, ensure_ascii=False, default=str))

    print("\n" + "=" * 110)
    print(f"{'id':<16} {'VT pedidos':>10} {'VT a servidor':>13} {'in_tok antes':>13} {'in_tok ahora':>13} "
          f"{'out_tok antes':>14} {'out_tok ahora':>14} {'costo antes':>12} {'costo ahora':>12}")
    for f in filas:
        print(f"{f['id']:<16} {f['vt_calls_pedidos']:>10} {f['vt_calls_a_servidor']:>13} "
              f"{f['input_tokens_antes']:>13} {f['input_tokens']:>13} "
              f"{f['output_tokens_antes']:>14} {f['output_tokens']:>14} "
              f"${f['costo_usd_antes']:>10.5f} ${f['costo_usd']:>10.5f}")

    total_antes = sum(f["costo_usd_antes"] for f in filas)
    total_ahora = sum(f["costo_usd"] for f in filas)
    print("=" * 110)
    print(f"Costo total 3 correos ANTES: ${total_antes:.5f}")
    print(f"Costo total 3 correos AHORA: ${total_ahora:.5f}")
    print(f"Reduccion: {(1 - total_ahora/total_antes)*100:.1f}%")

    with open("pilot_retest_result.json", "w", encoding="utf-8") as f:
        json.dump(filas, f, ensure_ascii=False, indent=2, default=str)


if __name__ == "__main__":
    asyncio.run(main())
