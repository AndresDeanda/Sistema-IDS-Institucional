"""
===========================================================
  MÓDULO: logger.py
  Configuración del Sistema de Bitácoras
  
  Descripción:
    Configura el logger centralizado del IDS. Escribe
    simultáneamente a consola (coloreada) y a archivo
    rotativo (.log). Los archivos rotan a 5 MB con
    respaldo de 7 días para auditoría.
===========================================================
"""

import logging
import logging.handlers
import sys
from pathlib import Path


# Colores ANSI para consola
COLORES = {
    "DEBUG"   : "\033[36m",   # Cyan
    "INFO"    : "\033[32m",   # Verde
    "WARNING" : "\033[33m",   # Amarillo
    "ERROR"   : "\033[31m",   # Rojo
    "CRITICAL": "\033[35m",   # Magenta
    "RESET"   : "\033[0m",
}


class FormateadorColor(logging.Formatter):
    """Formateador con colores ANSI para salida en consola."""

    FORMATO = "[%(asctime)s] [%(levelname)-8s] %(message)s"
    FECHA   = "%H:%M:%S"

    def format(self, record: logging.LogRecord) -> str:
        color  = COLORES.get(record.levelname, COLORES["RESET"])
        reset  = COLORES["RESET"]
        fmt    = logging.Formatter(
            f"{color}{self.FORMATO}{reset}", datefmt=self.FECHA
        )
        return fmt.format(record)


def configurar_logger(nombre: str, ruta_log: str,
                       nivel: int = logging.INFO) -> logging.Logger:
    """
    Crea y configura un logger con doble salida:
    consola coloreada + archivo rotativo.

    Parámetros:
        nombre   : Nombre del logger (ej. 'IDS_PRINCIPAL').
        ruta_log : Directorio donde guardar los archivos .log.
        nivel    : Nivel mínimo de logging (default: INFO).

    Retorna el logger configurado.
    """
    Path(ruta_log).mkdir(parents=True, exist_ok=True)
    ruta_archivo = Path(ruta_log) / "ids.log"

    logger = logging.getLogger(nombre)
    logger.setLevel(nivel)

    # Evitar duplicar handlers si se llama múltiples veces
    if logger.handlers:
        return logger

    # ── Handler de consola con colores ───────────────────────────────────────
    handler_consola = logging.StreamHandler(sys.stdout)
    handler_consola.setLevel(nivel)
    handler_consola.setFormatter(FormateadorColor())

    # ── Handler de archivo rotativo ──────────────────────────────────────────
    handler_archivo = logging.handlers.RotatingFileHandler(
        filename    = ruta_archivo,
        maxBytes    = 5 * 1024 * 1024,   # 5 MB por archivo
        backupCount = 7,                  # 7 archivos de respaldo
        encoding    = "utf-8"
    )
    handler_archivo.setLevel(logging.DEBUG)  # Guardar TODO en archivo
    handler_archivo.setFormatter(
        logging.Formatter(
            "[%(asctime)s] [%(levelname)-8s] [%(threadName)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    )

    logger.addHandler(handler_consola)
    logger.addHandler(handler_archivo)

    return logger
