
import logging
import logging.handlers
import sys
from pathlib import Path


# [MOD-009.1]
COLORES = {
    "DEBUG": "\033[36m",
    "INFO": "\033[32m",
    "WARNING": "\033[33m",
    "ERROR": "\033[31m",
    "CRITICAL": "\033[35m",
    "RESET": "\033[0m",
}


# [MOD-009.2]
class FormateadorColor(logging.Formatter):

    FORMATO = "[%(asctime)s] [%(levelname)-8s] %(message)s"
    FECHA = "%H:%M:%S"

    # [MOD-009.3]
    def format(self, record: logging.LogRecord) -> str:
        color = COLORES.get(record.levelname, COLORES["RESET"])
        reset = COLORES["RESET"]
        fmt = logging.Formatter(
            f"{color}{self.FORMATO}{reset}",
            datefmt=self.FECHA
        )
        return fmt.format(record)


# [MOD-009.4]
def configurar_logger(
    nombre: str,
    ruta_log: str,
    nivel: int = logging.INFO
) -> logging.Logger:

    Path(ruta_log).mkdir(parents=True, exist_ok=True)
    ruta_archivo = Path(ruta_log) / "ids.log"

    logger = logging.getLogger(nombre)
    logger.setLevel(nivel)

    # [MOD-009.5]
    if logger.handlers:
        return logger

    # [MOD-009.6]
    handler_consola = logging.StreamHandler(sys.stdout)
    handler_consola.setLevel(nivel)
    handler_consola.setFormatter(FormateadorColor())

    # [MOD-009.7]
    handler_archivo = logging.handlers.RotatingFileHandler(
        filename=ruta_archivo,
        maxBytes=5 * 1024 * 1024,
        backupCount=7,
        encoding="utf-8"
    )
    handler_archivo.setLevel(logging.DEBUG)
    handler_archivo.setFormatter(
        logging.Formatter(
            "[%(asctime)s] [%(levelname)-8s] [%(threadName)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    )

    # [MOD-009.8]
    logger.addHandler(handler_consola)
    logger.addHandler(handler_archivo)

    return logger

