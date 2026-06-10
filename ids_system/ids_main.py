#!/usr/bin/env python3
"""
===========================================================
  SISTEMA IDS INSTITUCIONAL - Módulo Principal
  Intrusion Detection System v1.0
  Licencia: GNU/GPL v3
===========================================================
  Descripción:
    Punto de entrada del IDS. Orquesta la inicialización
    de todos los módulos: captura de paquetes, listas
    blancas, threat intelligence, monitoreo de sitios
    y forense automatizado.
===========================================================
"""

import os
import sys
import time
import threading
import logging
from datetime import datetime

# Módulos internos del IDS
from modules.config_loader   import cargar_configuracion
from modules.whitelist        import ModuloListaBlanca
from modules.traffic_monitor  import ModuloMonitoreoTrafico
from modules.threat_intel     import ModuloThreatIntelligence
from modules.forensics         import ModuloForense
from modules.packet_capture   import ModuloCapturaPaquetes
from modules.email_alerter    import ModuloAlertas
from modules.logger           import configurar_logger


# ── Banner de inicio ────────────────────────────────────────────────────────
BANNER = r"""
                     ___  ____  ____       ____  ____   ___  __   __
                    |_ _||  _ \/ ___|     |  _ \|  _ \ / _ \ \ \ / /
                    | | | | | \___ \ _____| |_) | |_) | | | | \ V / 
                    | | | |_| |___) |_____|  __/|  _ <| |_| |  | |  
                    |___||____/|____/     |_|   |_| \_\\___/   |_|

                Sistema de Detección de Intrusiones Institucional v1.0
                ──────────────────────────────────────────────────────
                        GNU/GPL v3  - Dev by ERIK-ERNESTO-ANDRES
"""


def main():
    """Función principal de orquestación del IDS."""
    print(BANNER)

    # ── 1. Cargar configuración desde .env ──────────────────────────────────
    print("[*] Cargando configuración del sistema...")
    config = cargar_configuracion()

    # ── 2. Inicializar logger principal ─────────────────────────────────────
    log = configurar_logger(
        nombre="IDS_PRINCIPAL",
        ruta_log=config.get("LOG_DIR", "logs"),
        nivel=logging.DEBUG if config.get("DEBUG_MODE", "false").lower() == "true" else logging.INFO
    )
    log.info("=" * 60)
    log.info(f"IDS iniciado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log.info(f"Interfaz de red: {config.get('NETWORK_INTERFACE', 'no especificada')}")
    log.info("=" * 60)

    # ── 3. Inicializar módulo de alertas por correo ──────────────────────────
    alertas = ModuloAlertas(
        smtp_host     = config["SMTP_HOST"],
        smtp_port     = int(config.get("SMTP_PORT", 587)),
        smtp_user     = config["SMTP_USER"],
        smtp_password = config["SMTP_PASSWORD"],
        admin_email   = config["ADMIN_EMAIL"],
        logger        = log
    )

    # ── 4. Inicializar módulos de análisis ───────────────────────────────────
    lista_blanca  = ModuloListaBlanca(
        ruta_whitelist=config.get("WHITELIST_FILE", "config/whitelist.csv"),
        alertas=alertas,
        logger=log
    )
    threat_intel  = ModuloThreatIntelligence(
        ruta_blacklist=config.get("BLACKLIST_FILE", "config/blacklist.txt"),
        alertas=alertas,
        logger=log
    )
    monitor_sitios = ModuloMonitoreoTrafico(
        ruta_reporte=config.get("REPORT_DIR", "reports"),
        alertas=alertas,
        logger=log
    )
    forense        = ModuloForense(
        alertas=alertas,
        logger=log
    )

    # ── 5. Inicializar y arrancar captura de paquetes ────────────────────────
    captura = ModuloCapturaPaquetes(
        interfaz         = config.get("NETWORK_INTERFACE", None),
        lista_blanca     = lista_blanca,
        threat_intel     = threat_intel,
        monitor_sitios   = monitor_sitios,
        forense          = forense,
        logger           = log
    )

    print("[*] Todos los módulos inicializados correctamente.")
    print(f"[*] Interfaz monitorizada: {config.get('NETWORK_INTERFACE', 'auto')}")
    print(f"[*] Correo del administrador: {config.get('ADMIN_EMAIL')}")
    print("[*] Iniciando captura de tráfico... (Ctrl+C para detener)\n")
    log.info("Captura de paquetes iniciada.")

    try:
        captura.iniciar()
    except KeyboardInterrupt:
        print("\n[!] Deteniendo el IDS...")
        log.info("IDS detenido por el usuario.")
        captura.detener()
        print("[*] IDS detenido correctamente. Bitácoras guardadas.")
        sys.exit(0)
    except Exception as e:
        log.critical(f"Error crítico en el IDS: {e}", exc_info=True)
        print(f"[ERROR CRÍTICO] {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Verificar privilegios de administrador (necesario para captura raw)
    if os.name == "nt":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[ERROR] Este programa requiere privilegios de Administrador.")
            print("        Ejecuta desde una terminal como Administrador.")
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            print("[ERROR] Este programa requiere ejecutarse como root.")
            print("        Usa: sudo python3 ids_main.py")
            sys.exit(1)
    main()
