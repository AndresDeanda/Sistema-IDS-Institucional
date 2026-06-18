
import logging
import threading
from datetime import datetime

try:
    from scapy.all import (
        sniff, ARP, IP, TCP, UDP, DNS, DNSQR,
        Raw, Ether, get_if_list, conf
    )
    SCAPY_DISPONIBLE = True
except ImportError:
    SCAPY_DISPONIBLE = False


# [MOD-004.1]
class ModuloCapturaPaquetes:

    # [MOD-004.2]
    def __init__(self, interfaz, lista_blanca, threat_intel,
                 monitor_sitios, forense, logger: logging.Logger):
        if not SCAPY_DISPONIBLE:
            logger.critical(
                "[CAPTURA] Scapy no está instalado. "
                "Ejecuta: pip install scapy"
            )
            raise ImportError("Scapy no instalado. Ejecuta: pip install scapy")

        self.interfaz      = interfaz
        self.lista_blanca  = lista_blanca
        self.threat_intel  = threat_intel
        self.monitor       = monitor_sitios
        self.forense       = forense
        self.log           = logger
        self._activo       = False
        self._contadores   = {
            "total": 0, "arp": 0, "dns": 0,
            "http": 0, "tcp": 0, "udp": 0
        }

        if not self.interfaz:
            self.interfaz = self._detectar_interfaz()

    # [MOD-004.3]
    def iniciar(self):
        self._activo = True
        self.log.info(f"[CAPTURA] Sniffing en interfaz: {self.interfaz}")
        print(f"[*] Escuchando en: {self.interfaz}")
        print(f"[*] Estadísticas cada 60 segundos. Ctrl+C para detener.\n")

        hilo_stats = threading.Thread(
            target=self._imprimir_estadisticas_periodicas,
            daemon=True,
            name="StatsHilo"
        )
        hilo_stats.start()

        sniff(
            iface  = self.interfaz,
            prn    = self._procesar_paquete,
            store  = False,
            stop_filter = lambda _: not self._activo
        )

    # [MOD-004.4]
    def detener(self):
        self._activo = False
        self.log.info(
            f"[CAPTURA] Detenido. Estadísticas finales: {self._contadores}"
        )
        try:
            ruta_reporte = self.monitor.generar_reporte_html()
            self.log.info(f"[CAPTURA] Reporte final generado: {ruta_reporte}")
            print(f"\n[*] Reporte guardado en: {ruta_reporte}")
        except Exception as e:
            self.log.error(f"[CAPTURA] Error generando reporte final: {e}")

    # [MOD-004.5]
    def _procesar_paquete(self, paquete):
        self._contadores["total"] += 1

        try:
            # [MOD-004.6]
            if paquete.haslayer(ARP):
                self._analizar_arp(paquete)

            # [MOD-004.7]
            if paquete.haslayer(IP):
                ip_src = paquete[IP].src
                ip_dst = paquete[IP].dst

                # [MOD-004.8]
                if self._es_ip_privada(ip_src):
                    mac_src = paquete[Ether].src if paquete.haslayer(Ether) else "desconocida"
                    protocolo = "TCP" if paquete.haslayer(TCP) else "UDP" if paquete.haslayer(UDP) else "IP"
                    self.lista_blanca.verificar_y_alertar(ip_src, mac_src, protocolo)

                # [MOD-004.9]
                if not self._es_ip_privada(ip_dst):
                    puerto_dst = 0
                    protocolo  = "IP"
                    if paquete.haslayer(TCP):
                        puerto_dst = paquete[TCP].dport
                        protocolo  = "TCP"
                        self._contadores["tcp"] += 1
                    elif paquete.haslayer(UDP):
                        puerto_dst = paquete[UDP].dport
                        protocolo  = "UDP"
                        self._contadores["udp"] += 1

                    es_peligrosa, datos = self.threat_intel.es_ip_peligrosa(ip_dst)
                    if es_peligrosa:
                        self.threat_intel.verificar_y_alertar(ip_src, ip_dst, protocolo, puerto_dst)
                        self.forense.investigar_ip(
                            ip        = ip_dst,
                            ip_interna= ip_src,
                            categoria = datos.get("categoria", "unknown")
                        )

                # [MOD-004.10]
                if paquete.haslayer(DNS) and paquete.haslayer(DNSQR):
                    self._analizar_dns(paquete, ip_src)

                # [MOD-004.11]
                if paquete.haslayer(TCP) and paquete.haslayer(Raw):
                    self._analizar_http(paquete, ip_src)

        except Exception as e:
            self.log.debug(f"[CAPTURA] Error procesando paquete: {e}")

    # [MOD-004.12]
    def _analizar_arp(self, paquete):
        self._contadores["arp"] += 1
        arp     = paquete[ARP]
        ip_src  = arp.psrc
        mac_src = arp.hwsrc

        if arp.op in (1, 2):
            if self._es_ip_privada(ip_src) and ip_src not in ("0.0.0.0", "255.255.255.255"):
                self.lista_blanca.verificar_y_alertar(
                    ip=ip_src, mac=mac_src, protocolo="ARP"
                )

    # [MOD-004.13]
    def _analizar_dns(self, paquete, ip_src: str):
        self._contadores["dns"] += 1
        try:
            dominio = paquete[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
            if dominio and len(dominio) > 3:
                self.monitor.registrar_consulta_dns(ip_src, dominio)
                self.log.debug(f"[CAPTURA] DNS: {ip_src} → {dominio}")
        except Exception as e:
            self.log.debug(f"[CAPTURA] Error en DNS: {e}")

    # [MOD-004.14]
    def _analizar_http(self, paquete, ip_src: str):
        try:
            puerto = paquete[TCP].dport
            if puerto != 80:
                return
            payload = paquete[Raw].load.decode("utf-8", errors="replace")
            if not payload.startswith(("GET ", "POST ", "HEAD ", "PUT ")):
                return

            self._contadores["http"] += 1
            for linea in payload.splitlines():
                if linea.lower().startswith("host:"):
                    host   = linea.split(":", 1)[1].strip()
                    metodo = payload.split(" ")[0]
                    self.monitor.registrar_peticion_http(ip_src, host, metodo)
                    break
        except Exception:
            pass

    # [MOD-004.15]
    def _es_ip_privada(self, ip: str) -> bool:
        try:
            partes = list(map(int, ip.split(".")))
            if len(partes) != 4:
                return False
            if partes[0] == 10:
                return True
            if partes[0] == 172 and 16 <= partes[1] <= 31:
                return True
            if partes[0] == 192 and partes[1] == 168:
                return True
            if partes[0] == 127:
                return True
            if partes[0] == 169 and partes[1] == 254:
                return True
        except Exception:
            pass
        return False

    # [MOD-004.16]
    def _detectar_interfaz(self) -> str:
        try:
            if hasattr(conf.iface, "name") and conf.iface.name:
                self.log.info(f"[CAPTURA] Interfaz activa detectada vía Scapy: {conf.iface.name}")
                return conf.iface.name
            
            interfaces = get_if_list()
            activas = [i for i in interfaces if "loopback" not in i.lower() and "lo" != i.lower()]
            
            if activas:
                self.log.info(f"[CAPTURA] Interfaces disponibles encontradas: {activas}")
                return activas[0]
                
        except Exception as e:
            self.log.warning(f"[CAPTURA] No se pudo detectar interfaz automáticamente: {e}")

        return str(conf.iface)

    # [MOD-004.17]
    def _imprimir_estadisticas_periodicas(self):
        import time
        while self._activo:
            time.sleep(60)
            if self._activo:
                c = self._contadores
                print(
                    f"\n[STATS {datetime.now().strftime('%H:%M:%S')}] "
                    f"Total: {c['total']} | ARP: {c['arp']} | "
                    f"DNS: {c['dns']} | HTTP: {c['http']} | "
                    f"TCP: {c['tcp']} | UDP: {c['udp']}"
                )
                resumen = self.monitor.obtener_resumen()
                print(
                    f"         Hosts activos: {resumen['total_hosts']} | "
                    f"Dominios únicos: {resumen['dominios_unicos']}\n"
                )
