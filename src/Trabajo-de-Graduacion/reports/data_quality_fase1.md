# Reporte de Calidad de Datos — Fase 1

**Proyecto:** Prototipo de detección de phishing con LLM y servidores MCP
**Fecha de generación:** 2026-09-17 09:23
**Actividades:** A1.1 (Adquisición y exploración) y A1.2 (Limpieza, normalización y deduplicación)

## 1. Corpus de origen

| Atributo | Valor |
|---|---|
| Fuente | Al-Subaiey et al. (2024): Enron, CEAS 2008, Ling-Spam, Nazario, Nigerian Fraud, SpamAssassin |
| Archivos | Enron.csv, CEAS_08.csv, Ling.csv, Nazario.csv, Nigerian_Fraud.csv, SpamAssasin.csv |
| Codificación | UTF-8 |
| Registros originales | 82,486 |
| Columnas originales | 4 (text_combined, label, remitente, destinatario) |
| Registros con remitente disponible | 49,529 (60.0%) — ausente en Enron y Ling-Spam |

## 2. Transformaciones aplicadas

| Etapa | Registros | Eliminados |
|---|---|---|
| Corpus original | 82,486 | - |
| Tras deduplicación normalizada | 77,273 | 5,213 |
| Tras filtrado de no válidos | 77,267 | 6 |
| **Corpus final procesado** | **77,267** | **5,219** |

## 3. Balance de clases (corpus final)

| Clase | Cantidad | Proporción |
|---|---|---|
| Legítimo (0) | 39,201 | 50.73% |
| Phishing/Spam (1) | 38,066 | 49.27% |

## 4. Señales y metadatos extraídos (corpus final)

| Señal | Correos con presencia | Cobertura |
|---|---|---|
| Al menos una URL | 28,126 | 36.4% |
| URL basada en IP | 154 | 0.2% |
| Al menos un correo (hallado en el cuerpo) | 15,158 | 19.6% |
| Dominio de remitente identificado | 43,968 | 56.9% |
| Señal de urgencia | 20,661 | 26.7% |
| Señal de incentivo económico | 10,681 | 13.8% |
| Señal de credenciales | 11,975 | 15.5% |
| Señal de llamado a la acción | 19,080 | 24.7% |

## 5. Parámetros de reproducibilidad

| Parámetro | Valor |
|---|---|
| Semilla global | 42 |
| Umbral mínimo de palabras | 3 |

## 6. Artefactos exportados

- `data/corpus_construccion.csv` — corpus de construcción completo
- `figures/*.png` — gráficas del análisis exploratorio (incluye dominios de remitente y nubes de palabras por clase)

---

**Referencia del conjunto de datos:**
Al-Subaiey, A., Al-Thani, M., Alam, N. A., Antora, K. F., Khandakar, A., & Zaman, S. A. U. (2024). Novel interpretable and robust web-based AI platform for phishing email detection. *Computers & Electrical Engineering, 120*(Part A), Article 109625. https://doi.org/10.1016/j.compeleceng.2024.109625
