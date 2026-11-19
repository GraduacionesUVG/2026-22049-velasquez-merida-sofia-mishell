"""
Punto de entrada robusto para arrancar el servidor MCP.

Se recomienda usar este script en vez del comando de consola
'pattern-analysis-mcp', porque este ultimo depende de que
'pattern_analysis_mcp' sea importable a traves del mecanismo de instalacion
editable de site-packages (un archivo .pth generado por uv/pip). En maquinas
donde la ruta del proyecto contiene caracteres no ASCII (tildes, enies),
Python puede leer ese .pth con la codificacion equivocada (cp1252 en vez de
UTF-8), la ruta queda corrupta, y el import de 'pattern_analysis_mcp' falla en
silencio con ModuleNotFoundError, sin relacion con el codigo del servidor.

Este script evita el problema por completo: agrega 'src/' a sys.path
directamente en Python antes de importar el paquete, sin depender de ningun
mecanismo de instalacion externo. Funciona igual sin importar como se invoque
(consola, cliente MCP, mcp dev, etc.) y sin necesitar variables de entorno.

Ejecutar con:  uv run python run_server.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from pattern_analysis_mcp.server import main  # noqa: E402

if __name__ == "__main__":
    main()
