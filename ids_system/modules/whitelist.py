
import csv
import logging
import threading
from datetime import datetime
from pathlib import Path


# [MOD-003]
class ModuloListaBlanca:

    # [MOD-003.1]
    def __init__(self, ruta_whitelist: str, alertas, logger: logging.Logger):
        self.ruta_whitelist = Path(ruta_whitelist)
        self.alertas        = alertas
        self.log            = logger
        self._lock          = threading.Lock()

        self.ips_autorizadas  : dict[str, str] = {}
        self.macs_autorizadas : dict[str, str] = {}

        self._alertas_enviadas: set[str] = set()

        self._cargar_whitelist()

    # [MOD-003.2]
    def _cargar_whitelist(self):
        if not self.ruta_whitelist.exists():
            self.log.warning(f"[WHITELIST] Archivo no encontrado: {self.ruta_whitelist}")
            self.log.warning("[WHITELIST] Se creará una lista vacía. Todos los hosts generarán alertas.")
            self._crear_whitelist_ejemplo()
            return

        with self._lock:
            self.ips_autorizadas.clear()
            self.macs_autorizadas.clear()
            try:
                with open(self.ruta_whitelist, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for fila in reader:
                        ip  = fila.get("ip",  "").strip()
                        mac = fila.get("mac", "").strip().lower()
                        desc = fila.get("descripcion", "Sin descripción").strip()
                        if ip:
                            self.ips_autorizadas[ip] = desc
                        if mac and mac != "n/a":
                            self.macs_autorizadas[mac] = desc

                self.log.info(
                    f"[WHITELIST] Cargada: {len(self.ips_autorizadas)} IPs, "
                    f"{len(self.macs_autorizadas)} MACs autorizadas."
                )
            except Exception as e:
                self.log.error(f"[WHITELIST] Error al leer whitelist: {e}")

    # [MOD-003.3]
    def recargar(self):
        self.log.info("[WHITELIST] Recargando lista blanca...")
        self._cargar_whitelist()

    # [MOD-003.4]
    def verificar_ip(self, ip: str) -> bool:
        return ip in self.ips_autorizadas

    # [MOD-003.5]
    def verificar_mac(self, mac: str) -> bool:
        return mac.lower() in self.macs_autorizadas

    # [MOD-003.6]
    def verificar_y_alertar(self, ip: str, mac: str = "desconocida",
                            protocolo: str = "desconocido"):
        ip_ok  = self.verificar_ip(ip)
        mac_ok = self.verificar_mac(mac) if mac != "desconocida" else True
        clave_alerta = f"{ip}_{mac}"

        if not ip_ok and clave_alerta not in self._alertas_enviadas:
            self._alertas_enviadas.add(clave_alerta)
            descripcion = self.ips_autorizadas.get(ip, "No registrada")
            self.log.warning(
                f"[WHITELIST] INTRUSIÓN DETECTADA | IP: {ip} | MAC: {mac} | Protocolo: {protocolo}"
            )
            self._enviar_alerta_intrusion(ip, mac, protocolo)

    # [MOD-003.7]
    def _enviar_alerta_intrusion(self, ip: str, mac: str, protocolo: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        asunto = f"[IDS ALERTA] Dispositivo NO autorizado detectado - {ip}"
        cuerpo = f"""
╔══════════════════════════════════════════════════════════════╗
║           SISTEMA IDS - ALERTA DE SEGURIDAD                  ║
╚══════════════════════════════════════════════════════════════╝

Se ha detectado tráfico de red de un dispositivo NO REGISTRADO
en la lista blanca de la organización.

  ┌─ Datos del Incidente ─────────────────────────────────────┐
  │  Fecha/Hora  : {timestamp}
  │  IP Origen   : {ip}
  │  MAC Origen  : {mac}
  │  Protocolo   : {protocolo}
  │  Módulo      : Lista Blanca (Capa 2/3 OSI)
  └───────────────────────────────────────────────────────────┘

ACCIÓN RECOMENDADA:
  1. Verificar si el dispositivo pertenece a la organización.
  2. Si es desconocido: aislar el segmento de red.
  3. Si es autorizado: agregar a config/whitelist.csv y recargar.

Para agregar el dispositivo a la lista blanca:
  Editar config/whitelist.csv y añadir la línea:
  {ip},{mac},Descripción del dispositivo

────────────────────────────────────────────────────────────────
Sistema IDS Institucional v1.0 | GNU/GPL v3
"""
        self.alertas.enviar(asunto=asunto, cuerpo=cuerpo)

    # [MOD-003.8]
    def agregar_ip(self, ip: str, descripcion: str = "Agregado manualmente"):
        with self._lock:
            self.ips_autorizadas[ip] = descripcion
            self._persistir_entrada(ip, "n/a", descripcion)
        self.log.info(f"[WHITELIST] IP agregada: {ip} | {descripcion}")
        self._alertas_enviadas.discard(f"{ip}_desconocida")

    # [MOD-003.9]
    def listar_autorizados(self) -> list[dict]:
        resultado = []
        for ip, desc in self.ips_autorizadas.items():
            mac = next(
                (m for m, d in self.macs_autorizadas.items() if d == desc), "n/a"
            )
            resultado.append({"ip": ip, "mac": mac, "descripcion": desc})
        return resultado

    # [MOD-003.10]
    def _persistir_entrada(self, ip: str, mac: str, descripcion: str):
        try:
            with open(self.ruta_whitelist, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([ip, mac, descripcion, datetime.now().strftime("%Y-%m-%d")])
        except Exception as e:
            self.log.error(f"[WHITELIST] Error al persistir entrada: {e}")

    # [MOD-003.11]
    def _crear_whitelist_ejemplo(self):
        self.ruta_whitelist.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(self.ruta_whitelist, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ip", "mac", "descripcion", "fecha_alta"])
                writer.writerow(["192.168.1.1", "aa:bb:cc:dd:ee:01", "Router Principal", "2025-01-01"])
                writer.writerow(["192.168.1.2", "aa:bb:cc:dd:ee:02", "Servidor DNS", "2025-01-01"])
                writer.writerow(["192.168.1.10", "aa:bb:cc:dd:ee:10", "PC Administrador", "2025-01-01"])
            self.log.info(f"[WHITELIST] Archivo de ejemplo creado: {self.ruta_whitelist}")
            self._cargar_whitelist()
        except Exception as e:
            self.log.error(f"[WHITELIST] No se pudo crear whitelist de ejemplo: {e}")
