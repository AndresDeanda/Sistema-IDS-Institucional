"""
===========================================================
  MÓDULO: config_loader.py
  Cargador seguro de configuración desde archivo .env
  
  Descripción:
    Lee variables de entorno desde un archivo .env
    ubicado en la raíz del proyecto. Nunca almacena
    credenciales en texto plano dentro del código fuente.
    Compatible con python-dotenv.
===========================================================
"""

import os
import sys
from pathlib import Path


# ── Ruta base del proyecto ───────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent


# ── Variables requeridas (el sistema no inicia sin ellas) ────────────────────
VARIABLES_REQUERIDAS = [
    "SMTP_HOST",
    "SMTP_USER",
    "SMTP_PASSWORD",
    "ADMIN_EMAIL",
]


def cargar_configuracion() -> dict:
    """
    Carga la configuración desde el archivo .env ubicado en BASE_DIR.

    Retorna un diccionario con todas las variables de entorno del proyecto.
    Lanza SystemExit si faltan variables críticas.
    """
    env_path = BASE_DIR / ".env"

    # Intentar cargar con python-dotenv si está disponible
    try:
        from dotenv import load_dotenv
        if env_path.exists():
            load_dotenv(dotenv_path=env_path, override=True)
            print(f"[✓] Configuración cargada desde: {env_path}")
        else:
            print(f"[ADVERTENCIA] No se encontró .env en {env_path}")
            print("    Se usarán variables de entorno del sistema operativo.")
    except ImportError:
        # Si python-dotenv no está instalado, leer manualmente
        if env_path.exists():
            _cargar_env_manual(env_path)
        else:
            print("[ADVERTENCIA] python-dotenv no instalado y .env no encontrado.")

    # Construir diccionario de configuración
    config = {
        # ── Servidor SMTP para alertas ───────────────────────────────────────
        "SMTP_HOST"          : os.getenv("SMTP_HOST", "smtp.gmail.com"),
        "SMTP_PORT"          : os.getenv("SMTP_PORT", "587"),
        "SMTP_USER"          : os.getenv("SMTP_USER", ""),
        "SMTP_PASSWORD"      : os.getenv("SMTP_PASSWORD", ""),
        # ── Correo del administrador (AAA: Identificación/Autenticación/Autorización)
        "ADMIN_EMAIL"        : os.getenv("ADMIN_EMAIL", ""),
        # ── Interfaz de red a monitorear ─────────────────────────────────────
        "NETWORK_INTERFACE"  : os.getenv("NETWORK_INTERFACE", None),
        # ── Rutas de archivos ────────────────────────────────────────────────
        "WHITELIST_FILE"     : os.getenv("WHITELIST_FILE", str(BASE_DIR / "config" / "whitelist.csv")),
        "BLACKLIST_FILE"     : os.getenv("BLACKLIST_FILE", str(BASE_DIR / "config" / "blacklist.txt")),
        "LOG_DIR"            : os.getenv("LOG_DIR", str(BASE_DIR / "logs")),
        "REPORT_DIR"         : os.getenv("REPORT_DIR", str(BASE_DIR / "reports")),
        # ── Opciones adicionales ──────────────────────────────────────────────
        "DEBUG_MODE"         : os.getenv("DEBUG_MODE", "false"),
        "ABUSEIPDB_API_KEY"  : os.getenv("ABUSEIPDB_API_KEY", ""),
    }

    # Validar variables requeridas
    faltantes = [v for v in VARIABLES_REQUERIDAS if not config.get(v)]
    if faltantes:
        print("\n[ERROR] Faltan las siguientes variables en el archivo .env:")
        for v in faltantes:
            print(f"        - {v}")
        print(f"\n  Crea o edita el archivo: {env_path}")
        print("  Consulta el archivo .env.example para referencia.\n")
        sys.exit(1)

    return config


def _cargar_env_manual(env_path: Path):
    """Carga manual de .env sin dependencias externas."""
    with open(env_path, "r", encoding="utf-8") as f:
        for linea in f:
            linea = linea.strip()
            # Ignorar comentarios y líneas vacías
            if not linea or linea.startswith("#"):
                continue
            if "=" in linea:
                clave, _, valor = linea.partition("=")
                clave  = clave.strip()
                valor  = valor.strip().strip('"').strip("'")
                os.environ.setdefault(clave, valor)
    print(f"[✓] Configuración cargada manualmente desde: {env_path}")
