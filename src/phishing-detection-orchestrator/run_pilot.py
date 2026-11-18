"""Piloto de 10 correos (5 phishing + 5 legitimos, seed=42) en modo veredicto
con solo archetype+virustotal, para validar las Opciones 1 y 2 con llamadas
reales al modelo. Captura tokens reales (no modelados) envolviendo el
cliente de Anthropic y las llamadas MCP -- sin tocar el codigo del
orquestador ya implementado.
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

PRECIO_INPUT_POR_M = 1.00   # Claude Haiku 4.5
PRECIO_OUTPUT_POR_M = 5.00  # Claude Haiku 4.5
BASELINE_ANTERIOR_USD = 0.019  # promedio/correo estimado antes de Opciones 1 y 2


class UsageTrackingAnthropic:
    """Envuelve AsyncAnthropic para acumular input/output tokens reales por
    correo, sin tocar orchestrator.py (que solo conoce `.messages.create`)."""

    def __init__(self, real_client: AsyncAnthropic) -> None:
        self._real = real_client
        self.messages = self
        self.total_input_tokens = 0
        self.total_output_tokens = 0

    async def create(self, **kwargs):
        response = await self._real.messages.create(**kwargs)
        self.total_input_tokens += response.usage.input_tokens
        self.total_output_tokens += response.usage.output_tokens
        return response

    def reset(self) -> None:
        self.total_input_tokens = 0
        self.total_output_tokens = 0


class ArchetypeCapturingMCPClient:
    """Envuelve MCPClientManager para capturar el resultado real de
    archetype__classify_archetype (no expuesto en OrchestratorRunResult),
    sin tocar mcp_client.py."""

    def __init__(self, real_client: MCPClientManager) -> None:
        self._real = real_client
        self.last_archetype_result = None

    def __getattr__(self, name):
        return getattr(self._real, name)

    async def call_tool(self, qualified_name: str, arguments: dict):
        result = await self._real.call_tool(qualified_name, arguments)
        if qualified_name == "archetype__classify_archetype" and result.ok:
            self.last_archetype_result = result.data
        return result


async def main() -> None:
    load_environment()
    settings = load_orchestrator_settings()
    all_servers, _ = load_server_configs()
    server_configs = {k: v for k, v in all_servers.items() if k in ("archetype", "virustotal")}
    validate_selected_servers(server_configs)

    df = pd.read_csv(
        r"C:\Users\50250\Desktop\Sofía Mishell Velásquez UVG\Quinto año\Segundo Semestre\Tesis\Trabajo-de-Graduacion\experiments\external_eval\eval_external.csv"
    )
    phish = df[df["label"] == 1].sample(n=5, random_state=42)
    legit = df[df["label"] == 0].sample(n=5, random_state=42)
    muestra = pd.concat([phish, legit])

    real_anthropic = AsyncAnthropic(api_key=settings.anthropic_api_key)
    tracking_client = UsageTrackingAnthropic(real_anthropic)

    filas = []
    async with MCPClientManager(server_configs) as mcp_client:
        statuses = await mcp_client.connect_all()
        print("Servidores conectados:", statuses)
        wrapped_mcp = ArchetypeCapturingMCPClient(mcp_client)

        for idx, row in muestra.iterrows():
            tracking_client.reset()
            wrapped_mcp.last_archetype_result = None
            email_text = str(row["body"])
            label_real = int(row["label"])

            try:
                resultado = await run_analysis(
                    email_text=email_text,
                    mode="veredicto",
                    mcp_client=wrapped_mcp,
                    anthropic_client=tracking_client,
                    settings=settings,
                    max_iterations=4,
                    connection_statuses=statuses,
                )
                clasificacion = resultado.resultado.clasificacion.value
                puntaje = resultado.resultado.puntaje_riesgo
                error = None
            except OrchestratorError as exc:
                clasificacion = None
                puntaje = None
                error = str(exc)

            arquetipo = None
            if wrapped_mcp.last_archetype_result:
                d = wrapped_mcp.last_archetype_result
                arquetipo = f"#{d.get('archetype_id')} {d.get('label')} (sim={d.get('similarity'):.3f})"

            input_tok = tracking_client.total_input_tokens
            output_tok = tracking_client.total_output_tokens
            costo = (input_tok / 1e6) * PRECIO_INPUT_POR_M + (output_tok / 1e6) * PRECIO_OUTPUT_POR_M

            fila = {
                "id": row["id"], "label_real": label_real, "clasificacion": clasificacion,
                "puntaje_riesgo": puntaje, "arquetipo_asignado": arquetipo,
                "input_tokens": input_tok, "output_tokens": output_tok,
                "costo_usd": round(costo, 6), "error": error,
            }
            filas.append(fila)
            print(json.dumps(fila, ensure_ascii=False, default=str))

    print("\n" + "=" * 100)
    print(f"{'id':<28} {'real':<10} {'pred':<10} {'score':>6} {'arquetipo':<45} {'in_tok':>7} {'out_tok':>7} {'costo':>9}")
    print("-" * 100)
    correctos = 0
    costo_total = 0.0
    for f in filas:
        real_txt = "phishing" if f["label_real"] == 1 else "legitimo"
        if f["clasificacion"] == real_txt:
            correctos += 1
        costo_total += f["costo_usd"]
        arq = (f["arquetipo_asignado"] or "-")[:43]
        score = f"{f['puntaje_riesgo']:.2f}" if f["puntaje_riesgo"] is not None else "ERROR"
        print(f"{f['id']:<28} {real_txt:<10} {str(f['clasificacion']):<10} {score:>6} {arq:<45} "
              f"{f['input_tokens']:>7} {f['output_tokens']:>7} ${f['costo_usd']:>7.5f}")

    print("=" * 100)
    print(f"\nCorrectos: {correctos}/10")
    print(f"Costo total (10 correos): ${costo_total:.5f}")
    print(f"Costo promedio por correo: ${costo_total/10:.5f}")
    print(f"Baseline anterior (antes de Opciones 1 y 2): ${BASELINE_ANTERIOR_USD:.5f}/correo")
    bajo = costo_total / 10 < BASELINE_ANTERIOR_USD
    print(f"¿Bajo el costo por correo? {'SI' if bajo else 'NO'} "
          f"({(1 - (costo_total/10)/BASELINE_ANTERIOR_USD)*100:+.1f}%)")

    with open("pilot_result.json", "w", encoding="utf-8") as f:
        json.dump(filas, f, ensure_ascii=False, indent=2, default=str)


if __name__ == "__main__":
    asyncio.run(main())
