"""
===========================================================
  MÓDULO: traffic_monitor.py
  Monitoreo de Sitios Web y Generación de Reportes
  
  Descripción:
    Intercepta consultas DNS y peticiones HTTP/HTTPS
    para registrar en tiempo real los dominios visitados
    por cada host de la red. Genera bitácoras y reportes
    en formato CSV y HTML. Opera en Capa 7 (Aplicación).
===========================================================
"""

import csv
import logging
import threading
from collections import defaultdict
from datetime    import datetime
from pathlib     import Path


class ModuloMonitoreoTrafico:
    """
    Registra dominios visitados por usuarios de la red.
    Genera reportes en tiempo real (CSV + HTML).
    """

    def __init__(self, ruta_reporte: str, alertas, logger: logging.Logger):
        """
        Inicializa el monitor de tráfico.

        Parámetros:
            ruta_reporte : Directorio donde se guardan los reportes.
            alertas      : Instancia de ModuloAlertas.
            logger       : Logger del sistema.
        """
        self.ruta_reporte = Path(ruta_reporte)
        self.alertas      = alertas
        self.log          = logger
        self._lock        = threading.Lock()

        # Historial de navegación: {ip: [{dominio, timestamp, protocolo}, ...]}
        self._historial: dict[str, list[dict]] = defaultdict(list)

        # Contador global de peticiones por dominio
        self._contador_dominios: dict[str, int] = defaultdict(int)

        # Crear directorio de reportes
        self.ruta_reporte.mkdir(parents=True, exist_ok=True)

        # Nombre del archivo de bitácora del día actual
        self._archivo_bitacora = self.ruta_reporte / f"bitacora_{datetime.now().strftime('%Y%m%d')}.csv"
        self._inicializar_bitacora()

        self.log.info(f"[MONITOR] Módulo de monitoreo iniciado. Reportes en: {self.ruta_reporte}")

    # ── Registro de tráfico ───────────────────────────────────────────────────

    def registrar_consulta_dns(self, ip_origen: str, dominio: str):
        """
        Registra una consulta DNS (resolución de nombre de dominio).

        Parámetros:
            ip_origen : IP del host que realiza la consulta.
            dominio   : Nombre de dominio consultado.
        """
        self._registrar(ip_origen, dominio, "DNS")

    def registrar_peticion_http(self, ip_origen: str, host: str, metodo: str = "GET"):
        """
        Registra una petición HTTP (capa de aplicación).

        Parámetros:
            ip_origen : IP del host origen.
            host      : Nombre del host HTTP (cabecera Host:).
            metodo    : Método HTTP (GET, POST, etc.).
        """
        self._registrar(ip_origen, host, f"HTTP/{metodo}")

    def _registrar(self, ip: str, dominio: str, protocolo: str):
        """Método interno que persiste el evento en memoria y en la bitácora."""
        timestamp = datetime.now()
        entrada = {
            "timestamp" : timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "dominio"   : dominio,
            "protocolo" : protocolo,
        }
        with self._lock:
            self._historial[ip].append(entrada)
            self._contador_dominios[dominio] += 1
            self._escribir_en_bitacora(ip, dominio, protocolo, timestamp)

        self.log.debug(f"[MONITOR] {ip} → {dominio} ({protocolo})")

    # ── Bitácora CSV ──────────────────────────────────────────────────────────

    def _inicializar_bitacora(self):
        """Crea el encabezado del CSV si el archivo no existe."""
        if not self._archivo_bitacora.exists():
            with open(self._archivo_bitacora, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "ip_origen", "dominio", "protocolo"])
            self.log.info(f"[MONITOR] Bitácora iniciada: {self._archivo_bitacora}")

    def _escribir_en_bitacora(self, ip: str, dominio: str, protocolo: str,
                               timestamp: datetime):
        """Escribe una línea en la bitácora CSV."""
        try:
            with open(self._archivo_bitacora, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    ip, dominio, protocolo
                ])
        except Exception as e:
            self.log.error(f"[MONITOR] Error escribiendo bitácora: {e}")

    # ── Generación de Reporte HTML ────────────────────────────────────────────

    def generar_reporte_html(self) -> Path:
        """
        Genera un reporte HTML con el resumen del tráfico del día.
        Retorna la ruta del archivo generado.
        """
        fecha_str    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        nombre_arch  = f"reporte_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        ruta_archivo = self.ruta_reporte / nombre_arch

        with self._lock:
            historial_copia = dict(self._historial)
            top_dominios    = sorted(
                self._contador_dominios.items(),
                key=lambda x: x[1],
                reverse=True
            )[:20]

        # ── Construir tabla por host ─────────────────────────────────────────
        filas_hosts = ""
        for ip, visitas in historial_copia.items():
            filas_hosts += f'<tr class="host-row"><td colspan="3"><strong>🖥 {ip}</strong></td></tr>\n'
            for visita in visitas[-50:]:  # Últimas 50 por host
                filas_hosts += (
                    f'<tr>'
                    f'<td>{visita["timestamp"]}</td>'
                    f'<td>{visita["dominio"]}</td>'
                    f'<td><span class="badge">{visita["protocolo"]}</span></td>'
                    f'</tr>\n'
                )

        # ── Construir tabla top dominios ─────────────────────────────────────
        filas_top = "".join(
            f'<tr><td>{d}</td><td>{c}</td></tr>\n'
            for d, c in top_dominios
        )

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Reporte IDS - {fecha_str}</title>
  <style>
    body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
    h1   {{ color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }}
    h2   {{ color: #79c0ff; margin-top: 30px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
    th    {{ background: #161b22; color: #58a6ff; padding: 10px; text-align: left; }}
    td    {{ padding: 8px 10px; border-bottom: 1px solid #21262d; }}
    .host-row td {{ background: #1c2129; color: #f0f6fc; font-weight: bold; }}
    .badge {{ background: #1f6feb; color: #fff; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; }}
    .stat  {{ display: inline-block; background: #161b22; border: 1px solid #30363d;
              padding: 15px 25px; border-radius: 8px; margin: 5px; text-align: center; }}
    .stat-num {{ font-size: 2em; color: #58a6ff; font-weight: bold; }}
    .stat-lbl {{ font-size: 0.85em; color: #8b949e; }}
  </style>
</head>
<body>
  <h1>📊 Reporte IDS Institucional</h1>
  <p>Generado: <strong>{fecha_str}</strong></p>

  <div>
    <div class="stat">
      <div class="stat-num">{len(historial_copia)}</div>
      <div class="stat-lbl">Hosts activos</div>
    </div>
    <div class="stat">
      <div class="stat-num">{sum(len(v) for v in historial_copia.values())}</div>
      <div class="stat-lbl">Peticiones totales</div>
    </div>
    <div class="stat">
      <div class="stat-num">{len(self._contador_dominios)}</div>
      <div class="stat-lbl">Dominios únicos</div>
    </div>
  </div>

  <h2>🔝 Top 20 Dominios más Visitados</h2>
  <table>
    <tr><th>Dominio</th><th>Visitas</th></tr>
    {filas_top}
  </table>

  <h2>📋 Detalle por Host</h2>
  <table>
    <tr><th>Timestamp</th><th>Dominio</th><th>Protocolo</th></tr>
    {filas_hosts}
  </table>

  <p style="margin-top:40px; color:#484f58; font-size:0.85em;">
    Sistema IDS Institucional v1.0 | GNU/GPL v3
  </p>
</body>
</html>"""

        try:
            ruta_archivo.write_text(html, encoding="utf-8")
            self.log.info(f"[MONITOR] Reporte HTML generado: {ruta_archivo}")
        except Exception as e:
            self.log.error(f"[MONITOR] Error generando reporte: {e}")

        return ruta_archivo

    def obtener_resumen(self) -> dict:
        """Retorna un resumen del tráfico para uso interno."""
        with self._lock:
            return {
                "total_hosts"    : len(self._historial),
                "total_peticiones": sum(len(v) for v in self._historial.values()),
                "dominios_unicos": len(self._contador_dominios),
                "top_dominios"   : sorted(
                    self._contador_dominios.items(),
                    key=lambda x: x[1], reverse=True
                )[:10],
            }
