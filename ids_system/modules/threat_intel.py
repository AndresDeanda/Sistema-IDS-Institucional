
import csv
import json
import logging
import threading
import urllib.request
import urllib.error
from datetime import datetime
from pathlib  import Path


# [MOD-006.1]
CATEGORIAS_RIESGO = {
    "botnet"   : "🔴 CRÍTICO - Botnet/C2 Server",
    "malware"  : "🔴 CRÍTICO - Distribución de Malware",
    "ransomware": "🔴 CRÍTICO - Ransomware Command & Control",
    "phishing" : "🟠 ALTO   - Sitio de Phishing",
    "spam"     : "🟡 MEDIO  - Servidor de Spam",
    "scanner"  : "🟡 MEDIO  - Escáner de puertos masivo",
    "tor"      : "🟡 MEDIO  - Nodo de salida TOR",
    "proxy"    : "🟡 MEDIO  - Proxy anónimo malicioso",
    "unknown"  : "⚪ INFO   - IP en lista negra (tipo desconocido)",
}


# [MOD-006.2]
class ModuloThreatIntelligence:

    # [MOD-006.3]
    def __init__(self, ruta_blacklist: str, alertas, logger: logging.Logger):
        self.ruta_blacklist = Path(ruta_blacklist)
        self.alertas        = alertas
        self.log            = logger
        self._lock          = threading.Lock()

        self._ips_peligrosas: dict[str, dict] = {}

        self._alertas_enviadas: set[str] = set()

        self._cargar_blacklist()

    # [MOD-006.4]
    def _cargar_blacklist(self):
        if not self.ruta_blacklist.exists():
            self.log.warning(f"[THREAT] Blacklist no encontrada: {self.ruta_blacklist}")
            self._crear_blacklist_ejemplo()
            return

        extension = self.ruta_blacklist.suffix.lower()
        with self._lock:
            self._ips_peligrosas.clear()
            if extension == ".csv":
                self._cargar_csv()
            else:
                self._cargar_txt()

        self.log.info(f"[THREAT] Lista negra cargada: {len(self._ips_peligrosas)} IPs peligrosas.")

    # [MOD-006.5]
    def _cargar_csv(self):
        try:
            with open(self.ruta_blacklist, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for fila in reader:
                    ip   = fila.get("ip", "").strip()
                    cat  = fila.get("categoria", "unknown").strip().lower()
                    desc = fila.get("descripcion", "").strip()
                    if ip:
                        self._ips_peligrosas[ip] = {
                            "categoria"   : cat,
                            "descripcion" : desc,
                            "riesgo_label": CATEGORIAS_RIESGO.get(cat, CATEGORIAS_RIESGO["unknown"])
                        }
        except Exception as e:
            self.log.error(f"[THREAT] Error leyendo CSV: {e}")

    # [MOD-006.6]
    def _cargar_txt(self):
        try:
            with open(self.ruta_blacklist, "r", encoding="utf-8") as f:
                for linea in f:
                    linea = linea.strip()
                    if not linea or linea.startswith("#"):
                        continue
                    partes = linea.split("#", 1)
                    ip     = partes[0].strip()
                    meta   = partes[1].strip() if len(partes) > 1 else ""
                    if ip:
                        cat = "unknown"
                        for c in CATEGORIAS_RIESGO:
                            if c in meta.lower():
                                cat = c
                                break
                        self._ips_peligrosas[ip] = {
                            "categoria"   : cat,
                            "descripcion" : meta,
                            "riesgo_label": CATEGORIAS_RIESGO.get(cat, CATEGORIAS_RIESGO["unknown"])
                        }
        except Exception as e:
            self.log.error(f"[THREAT] Error leyendo TXT: {e}")

    # [MOD-006.7]
    def recargar(self):
        self.log.info("[THREAT] Recargando lista negra...")
        self._cargar_blacklist()

    # [MOD-006.8]
    def es_ip_peligrosa(self, ip: str) -> tuple[bool, dict]:
        datos = self._ips_peligrosas.get(ip, {})
        return bool(datos), datos

    # [MOD-006.9]
    def verificar_y_alertar(self, ip_interna: str, ip_externa: str,
                             protocolo: str = "TCP", puerto: int = 0):
        es_peligrosa, datos = self.es_ip_peligrosa(ip_externa)
        clave = f"{ip_interna}->{ip_externa}"

        if es_peligrosa and clave not in self._alertas_enviadas:
            self._alertas_enviadas.add(clave)
            self.log.critical(
                f"[THREAT] ¡IP PELIGROSA! {ip_interna} → {ip_externa} | "
                f"Categoría: {datos.get('categoria', 'unknown')} | "
                f"Puerto: {puerto}"
            )
            self._enviar_alerta_emergencia(ip_interna, ip_externa, protocolo, puerto, datos)

    # [MOD-006.10]
    def _enviar_alerta_emergencia(self, ip_interna: str, ip_externa: str,
                                   protocolo: str, puerto: int, datos: dict):
        timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        riesgo      = datos.get("riesgo_label", CATEGORIAS_RIESGO["unknown"])
        categoria   = datos.get("categoria", "unknown")
        descripcion = datos.get("descripcion", "No disponible")

        asunto = f"🚨 [IDS EMERGENCIA] Conexión a IP PELIGROSA detectada - {ip_externa}"
        cuerpo = f"""
╔══════════════════════════════════════════════════════════════╗
║         ⚠⚠⚠  ALERTA DE EMERGENCIA  ⚠⚠⚠                     ║
║         SISTEMA IDS - THREAT INTELLIGENCE                     ║
╚══════════════════════════════════════════════════════════════╝

Se detectó una conexión hacia una IP clasificada como
PELIGROSA en la base de datos de Threat Intelligence.

  ┌─ Datos del Incidente ─────────────────────────────────────┐
  │  Fecha/Hora    : {timestamp}
  │  Host Interno  : {ip_interna}
  │  IP Peligrosa  : {ip_externa}
  │  Protocolo     : {protocolo}
  │  Puerto Destino: {puerto}
  └───────────────────────────────────────────────────────────┘

  ┌─ Clasificación de Riesgo ──────────────────────────────────┐
  │  Nivel de Riesgo: {riesgo}
  │  Categoría      : {categoria.upper()}
  │  Descripción    : {descripcion}
  └───────────────────────────────────────────────────────────┘

ACCIONES INMEDIATAS RECOMENDADAS:
  1. Aislar el host {ip_interna} de la red inmediatamente.
  2. Verificar procesos activos en el equipo afectado.
  3. Ejecutar análisis antimalware completo.
  4. Revisar conexiones de red: netstat -an | findstr {ip_externa}
  5. Consultar los logs de forense adjuntos.

CONSULTA WHOIS/ABUSO en próximo correo de reporte forense.

────────────────────────────────────────────────────────────────
Sistema IDS Institucional v1.0 | GNU/GPL v3
"""
        self.alertas.enviar(asunto=asunto, cuerpo=cuerpo)

    # [MOD-006.11]
    def consultar_abuseipdb(self, ip: str, api_key: str) -> dict:
        if not api_key:
            self.log.debug("[THREAT] Sin API key de AbuseIPDB, omitiendo consulta.")
            return {}

        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(url)
        req.add_header("Key",    api_key)
        req.add_header("Accept", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=10) as respuesta:
                datos = json.loads(respuesta.read().decode("utf-8"))
                return datos.get("data", {})
        except urllib.error.HTTPError as e:
            self.log.warning(f"[THREAT] AbuseIPDB HTTP error {e.code} para {ip}")
        except Exception as e:
            self.log.warning(f"[THREAT] Error consultando AbuseIPDB para {ip}: {e}")
        return {}

    # [MOD-006.12]
    def _crear_blacklist_ejemplo(self):
        self.ruta_blacklist.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(self.ruta_blacklist, "w", encoding="utf-8") as f:
                f.write("# Lista Negra IDS Institucional\n")
                f.write("# Formato: IP # categoria descripcion\n")
                f.write("# Categorías: botnet, malware, ransomware, phishing, spam, scanner, tor, proxy\n\n")
                f.write("185.220.101.1    # tor      Nodo de salida TOR conocido\n")
                f.write("193.32.162.50    # botnet   Servidor C2 de botnet Emotet\n")
                f.write("45.142.212.100   # malware  Distribución de AgentTesla\n")
                f.write("91.92.109.10     # scanner  Escáner masivo de puertos\n")
                f.write("185.234.219.13   # phishing Dominio de phishing bancario\n")
                f.write("194.165.16.73    # ransomware C2 de LockBit\n")
            self.log.info(f"[THREAT] Blacklist de ejemplo creada: {self.ruta_blacklist}")
            self._cargar_blacklist()
        except Exception as e:
            self.log.error(f"[THREAT] No se pudo crear blacklist de ejemplo: {e}")
