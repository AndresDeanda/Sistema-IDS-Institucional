"""
===========================================================
  MÓDULO: forensics.py
  Módulo de Automatización Forense (Abuse/WHOIS)
  
  Descripción:
    Ante la detección de una IP peligrosa, automatiza:
      1. Consulta WHOIS para obtener datos del propietario.
      2. Consulta a APIs de abuso (AbuseIPDB, ipinfo.io).
      3. Extrae el correo de contacto de abuso del ISP.
      4. Envía al administrador un reporte completo con
         los datos para reportar el abuso fácilmente.
    Opera como soporte post-detección de Threat Intel.
===========================================================
"""

import json
import logging
import subprocess
import threading
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime


class ModuloForense:
    """
    Automatiza la investigación forense de IPs peligrosas.
    Obtiene datos WHOIS, información de abuso y los envía
    por correo al administrador.
    """

    def __init__(self, alertas, logger: logging.Logger):
        """
        Inicializa el módulo forense.

        Parámetros:
            alertas : Instancia de ModuloAlertas.
            logger  : Logger del sistema.
        """
        self.alertas   = alertas
        self.log       = logger
        self._lock     = threading.Lock()

        # Control de investigaciones ya realizadas
        self._investigadas: set[str] = set()

    # ── Investigación forense completa ────────────────────────────────────────

    def investigar_ip(self, ip: str, ip_interna: str = "desconocida",
                       categoria: str = "unknown", api_key_abuseipdb: str = ""):
        """
        Realiza investigación forense completa sobre una IP peligrosa.
        Ejecuta en hilo separado para no bloquear la captura.

        Parámetros:
            ip              : IP externa a investigar.
            ip_interna      : IP del host interno afectado.
            categoria       : Categoría de amenaza detectada.
            api_key_abuseipdb: Clave API de AbuseIPDB (opcional).
        """
        if ip in self._investigadas:
            self.log.debug(f"[FORENSE] IP {ip} ya investigada, omitiendo.")
            return

        hilo = threading.Thread(
            target=self._investigar_async,
            args=(ip, ip_interna, categoria, api_key_abuseipdb),
            daemon=True,
            name=f"ForenseHilo-{ip}"
        )
        hilo.start()

    def _investigar_async(self, ip: str, ip_interna: str,
                           categoria: str, api_key: str):
        """Ejecuta la investigación en segundo plano."""
        with self._lock:
            if ip in self._investigadas:
                return
            self._investigadas.add(ip)

        self.log.info(f"[FORENSE] Iniciando investigación forense de {ip}...")

        # ── Recopilar información de múltiples fuentes ───────────────────────
        datos_whois    = self._consultar_whois(ip)
        datos_ipinfo   = self._consultar_ipinfo(ip)
        datos_abuse    = self._consultar_abuseipdb(ip, api_key)

        # ── Extraer contacto de abuso ────────────────────────────────────────
        contacto_abuso = self._extraer_contacto_abuso(datos_whois, datos_ipinfo)

        # ── Generar y enviar reporte ─────────────────────────────────────────
        self._enviar_reporte_forense(
            ip, ip_interna, categoria,
            datos_whois, datos_ipinfo, datos_abuse, contacto_abuso
        )

    # ── Consultas externas ────────────────────────────────────────────────────

    def _consultar_whois(self, ip: str) -> str:
        """
        Ejecuta consulta WHOIS usando comando del sistema operativo.
        En Windows requiere whois.exe de Sysinternals.
        """
        resultado = "No disponible (WHOIS no instalado o sin acceso)"
        try:
            # Intentar con whois de Sysinternals (Windows) o whois nativo (Linux)
            cmd_windows = ["whois.exe", ip]
            cmd_linux   = ["whois", ip]

            import os
            cmd = cmd_windows if os.name == "nt" else cmd_linux

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                encoding="utf-8",
                errors="replace"
            )
            if proc.returncode == 0 and proc.stdout.strip():
                resultado = proc.stdout[:3000]  # Limitar a 3000 chars
            else:
                resultado = f"WHOIS retornó código {proc.returncode}: {proc.stderr[:200]}"
        except FileNotFoundError:
            resultado = (
                "Comando 'whois' no encontrado.\n"
                "Windows: Descarga whois.exe de https://docs.microsoft.com/sysinternals\n"
                "Linux  : sudo apt install whois"
            )
        except subprocess.TimeoutExpired:
            resultado = "WHOIS: Tiempo de espera agotado (15s)."
        except Exception as e:
            resultado = f"WHOIS error: {e}"

        self.log.debug(f"[FORENSE] WHOIS para {ip}: {len(resultado)} chars")
        return resultado

    def _consultar_ipinfo(self, ip: str) -> dict:
        """
        Consulta ipinfo.io (sin API key) para información básica de la IP:
        país, organización/ASN, ciudad.
        """
        datos = {}
        try:
            url = f"https://ipinfo.io/{ip}/json"
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "IDS-Institucional/1.0")

            with urllib.request.urlopen(req, timeout=10) as resp:
                datos = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            self.log.debug(f"[FORENSE] ipinfo.io error para {ip}: {e}")
        return datos

    def _consultar_abuseipdb(self, ip: str, api_key: str) -> dict:
        """
        Consulta AbuseIPDB para obtener historial de reportes de abuso.
        Solo ejecuta si se proporciona una API key.
        """
        if not api_key:
            return {}

        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose"
            req = urllib.request.Request(url)
            req.add_header("Key",    api_key)
            req.add_header("Accept", "application/json")

            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8")).get("data", {})
        except Exception as e:
            self.log.debug(f"[FORENSE] AbuseIPDB error para {ip}: {e}")
        return {}

    # ── Extracción de datos clave ─────────────────────────────────────────────

    def _extraer_contacto_abuso(self, whois_texto: str, ipinfo: dict) -> str:
        """
        Extrae el correo de contacto de abuso del texto WHOIS.
        Retorna el correo si lo encuentra, o guía alternativa.
        """
        import re
        # Patrones comunes en WHOIS para contacto de abuso
        patrones = [
            r"abuse[^\s@]*@[^\s]+",        # abuse@dominio.com
            r"OrgAbuseEmail:\s*(\S+@\S+)",  # ARIN format
            r"abuse-mailbox:\s*(\S+@\S+)",  # RIPE format
            r"e-mail:\s*(\S+abuse\S*@\S+)", # Generic abuse email
        ]
        for patron in patrones:
            match = re.search(patron, whois_texto, re.IGNORECASE)
            if match:
                return match.group(0) if "@" in match.group(0) else match.group(1)

        # Fallback: usar org de ipinfo
        org = ipinfo.get("org", "")
        if org:
            return f"No encontrado automáticamente. Organización: {org}. Buscar manualmente en abuse.ch"

        return "No encontrado. Reportar manualmente en: https://www.abuse.ch o https://www.abuseipdb.com/report"

    # ── Generación de reporte ─────────────────────────────────────────────────

    def _enviar_reporte_forense(self, ip: str, ip_interna: str, categoria: str,
                                 datos_whois: str, datos_ipinfo: dict,
                                 datos_abuse: dict, contacto_abuso: str):
        """Construye y envía el reporte forense completo al administrador."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Datos de ipinfo
        pais  = datos_ipinfo.get("country", "Desconocido")
        ciudad= datos_ipinfo.get("city",    "Desconocida")
        org   = datos_ipinfo.get("org",     "Desconocida")
        asn   = datos_ipinfo.get("asn",     {}).get("asn", "N/A") if isinstance(datos_ipinfo.get("asn"), dict) else "N/A"

        # Datos de AbuseIPDB
        score_abuso   = datos_abuse.get("abuseConfidenceScore", "N/A")
        total_reportes= datos_abuse.get("totalReports",         "N/A")
        ultimo_reporte= datos_abuse.get("lastReportedAt",       "N/A")

        asunto = f"[IDS FORENSE] Reporte de investigación: {ip} ({categoria.upper()})"
        cuerpo = f"""
╔══════════════════════════════════════════════════════════════╗
║          REPORTE FORENSE AUTOMATIZADO                        ║
║          SISTEMA IDS - MÓDULO DE ABUSO/WHOIS                 ║
╚══════════════════════════════════════════════════════════════╝

  ┌─ Datos del Incidente ─────────────────────────────────────┐
  │  Fecha/Hora       : {timestamp}
  │  IP Peligrosa     : {ip}
  │  Host Afectado    : {ip_interna}
  │  Categoría        : {categoria.upper()}
  └───────────────────────────────────────────────────────────┘

  ┌─ Geolocalización e ISP (ipinfo.io) ────────────────────────┐
  │  País             : {pais}
  │  Ciudad           : {ciudad}
  │  Organización/ISP : {org}
  │  ASN              : {asn}
  └───────────────────────────────────────────────────────────┘

  ┌─ Historial de Abuso (AbuseIPDB) ──────────────────────────┐
  │  Score de Abuso   : {score_abuso}/100
  │  Total Reportes   : {total_reportes}
  │  Último Reporte   : {ultimo_reporte}
  └───────────────────────────────────────────────────────────┘

  ┌─ Contacto de Abuso del ISP ────────────────────────────────┐
  │  {contacto_abuso}
  └───────────────────────────────────────────────────────────┘

CÓMO REPORTAR EL ABUSO:
  1. Envía un correo a: {contacto_abuso}
  2. O reporta en:      https://www.abuseipdb.com/report
  3. Incluye: IP={ip}, Fecha={timestamp}, Tipo={categoria}
  4. Adjunta esta bitácora como evidencia.

  ┌─ Datos WHOIS Completos ────────────────────────────────────┐
{chr(10).join("  │  " + l for l in datos_whois.splitlines()[:40])}
  └───────────────────────────────────────────────────────────┘

────────────────────────────────────────────────────────────────
Sistema IDS Institucional v1.0 | GNU/GPL v3
Reporte generado automáticamente - No responder a este correo
"""
        self.alertas.enviar(asunto=asunto, cuerpo=cuerpo)
        self.log.info(f"[FORENSE] Reporte forense enviado para {ip}. Contacto abuso: {contacto_abuso}")
