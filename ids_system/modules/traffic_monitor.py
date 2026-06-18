
import csv
import logging
import threading
from collections import defaultdict
from datetime    import datetime
from pathlib     import Path


# [MOD-005]
class ModuloMonitoreoTrafico:

    # [MOD-005.1]
    def __init__(self, ruta_reporte: str, alertas, logger: logging.Logger):
        self.ruta_reporte = Path(ruta_reporte)
        self.alertas      = alertas
        self.log          = logger
        self._lock        = threading.Lock()

        self._historial: dict[str, list[dict]] = defaultdict(list)

        self._contador_dominios: dict[str, int] = defaultdict(int)

        self.ruta_reporte.mkdir(parents=True, exist_ok=True)

        self._archivo_bitacora = self.ruta_reporte / f"bitacora_{datetime.now().strftime('%Y%m%d')}.csv"
        self._inicializar_bitacora()

        self.log.info(f"[MONITOR] Módulo de monitoreo iniciado. Reportes en: {self.ruta_reporte}")

    # [MOD-005.2]
    def registrar_consulta_dns(self, ip_origen: str, dominio: str):
        self._registrar(ip_origen, dominio, "DNS")

    # [MOD-005.3]
    def registrar_peticion_http(self, ip_origen: str, host: str, metodo: str = "GET"):
        self._registrar(ip_origen, host, f"HTTP/{metodo}")

    # [MOD-005.4]
    def _registrar(self, ip: str, dominio: str, protocolo: str):
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

    # [MOD-005.5]
    def _inicializar_bitacora(self):
        if not self._archivo_bitacora.exists():
            with open(self._archivo_bitacora, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "ip_origen", "dominio", "protocolo"])
            self.log.info(f"[MONITOR] Bitácora iniciada: {self._archivo_bitacora}")

    # [MOD-005.6]
    def _escribir_en_bitacora(self, ip: str, dominio: str, protocolo: str,
                               timestamp: datetime):
        try:
            with open(self._archivo_bitacora, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    ip, dominio, protocolo
                ])
        except Exception as e:
            self.log.error(f"[MONITOR] Error escribiendo bitácora: {e}")

    # [MOD-005.7]
    def generar_reporte_html(self) -> Path:
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

        # [MOD-005.7.1]
        filas_hosts = ""
        for ip, visitas in historial_copia.items():
            filas_hosts += f'<tr class="host-row"><td colspan="3"><strong>🖥 {ip}</strong></td></tr>\n'
            for visita in visitas[-50:]:
                filas_hosts += (
                    f'<tr>'
                    f'<td>{visita["timestamp"]}</td>'
                    f'<td>{visita["dominio"]}</td>'
                    f'<td><span class="badge">{visita["protocolo"]}</span></td>'
                    f'</tr>\n'
                )

        # [MOD-005.7.2]
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

    # [MOD-005.8]
    def obtener_resumen(self) -> dict:
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
