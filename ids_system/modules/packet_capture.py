"""
===========================================================
  MÓDULO: packet_capture.py
  Captura de Paquetes en Tiempo Real (Motor Principal)
  
  Descripción:
    Núcleo del IDS. Captura paquetes usando Scapy/Npcap
    y los distribuye a cada módulo de análisis según el
    tipo de tráfico (ARP, DNS, HTTP, TCP, UDP).
    Opera en las Capas 2-7 del modelo OSI.
    
  Dependencias:
    - scapy (pip install scapy)
    - Npcap instalado en Windows (https://npcap.com)
===========================================================
"""

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


class ModuloCapturaPaquetes:
    """
    Motor de captura de paquetes usando Scapy.
    Distribuye eventos a los módulos de análisis.
    """

    def __init__(self, interfaz, lista_blanca, threat_intel,
                 monitor_sitios, forense, logger: logging.Logger):
        """
        Inicializa el motor de captura.

        Parámetros:
            interfaz       : Nombre de la interfaz de red (None = auto).
            lista_blanca   : ModuloListaBlanca.
            threat_intel   : ModuloThreatIntelligence.
            monitor_sitios : ModuloMonitoreoTrafico.
            forense        : ModuloForense.
            logger         : Logger del sistema.
        """
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

        # Resolver interfaz automáticamente si no se especificó
        if not self.interfaz:
            self.interfaz = self._detectar_interfaz()

    # ── Inicio y parada ────────────────────────────────────────────────────────

    def iniciar(self):
        """Inicia la captura bloqueante de paquetes."""
        self._activo = True
        self.log.info(f"[CAPTURA] Sniffing en interfaz: {self.interfaz}")
        print(f"[*] Escuchando en: {self.interfaz}")
        print(f"[*] Estadísticas cada 60 segundos. Ctrl+C para detener.\n")

        # Hilo de estadísticas periódicas
        hilo_stats = threading.Thread(
            target=self._imprimir_estadisticas_periodicas,
            daemon=True,
            name="StatsHilo"
        )
        hilo_stats.start()

        # Iniciar sniff (bloqueante)
        sniff(
            iface  = self.interfaz,
            prn    = self._procesar_paquete,
            store  = False,          # No almacenar en RAM para eficiencia
            stop_filter = lambda _: not self._activo
        )

    def detener(self):
        """Detiene la captura de paquetes."""
        self._activo = False
        self.log.info(
            f"[CAPTURA] Detenido. Estadísticas finales: {self._contadores}"
        )
        # Generar reporte final
        try:
            ruta_reporte = self.monitor.generar_reporte_html()
            self.log.info(f"[CAPTURA] Reporte final generado: {ruta_reporte}")
            print(f"\n[*] Reporte guardado en: {ruta_reporte}")
        except Exception as e:
            self.log.error(f"[CAPTURA] Error generando reporte final: {e}")

    # ── Procesamiento de paquetes ─────────────────────────────────────────────

    def _procesar_paquete(self, paquete):
        """
        Callback principal. Analiza cada paquete capturado
        y lo distribuye al módulo correspondiente.
        """
        self._contadores["total"] += 1

        try:
            # ── Capa 2: ARP (Detección de dispositivos en red local) ──────────
            if paquete.haslayer(ARP):
                self._analizar_arp(paquete)

            # ── Capa 3/4: IP ──────────────────────────────────────────────────
            if paquete.haslayer(IP):
                ip_src = paquete[IP].src
                ip_dst = paquete[IP].dst

                # Verificar IP origen en lista blanca (solo IPs privadas/locales)
                if self._es_ip_privada(ip_src):
                    mac_src = paquete[Ether].src if paquete.haslayer(Ether) else "desconocida"
                    protocolo = "TCP" if paquete.haslayer(TCP) else "UDP" if paquete.haslayer(UDP) else "IP"
                    self.lista_blanca.verificar_y_alertar(ip_src, mac_src, protocolo)

                # Verificar IP destino contra lista negra (IPs externas)
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
                        # Lanzar investigación forense en segundo plano
                        self.forense.investigar_ip(
                            ip        = ip_dst,
                            ip_interna= ip_src,
                            categoria = datos.get("categoria", "unknown")
                        )

                # ── Capa 7: DNS ────────────────────────────────────────────────
                if paquete.haslayer(DNS) and paquete.haslayer(DNSQR):
                    self._analizar_dns(paquete, ip_src)

                # ── Capa 7: HTTP ───────────────────────────────────────────────
                if paquete.haslayer(TCP) and paquete.haslayer(Raw):
                    self._analizar_http(paquete, ip_src)

        except Exception as e:
            # Los errores en paquetes individuales no deben detener el IDS
            self.log.debug(f"[CAPTURA] Error procesando paquete: {e}")

    def _analizar_arp(self, paquete):
        """Analiza paquetes ARP para detección de dispositivos Capa 2."""
        self._contadores["arp"] += 1
        arp     = paquete[ARP]
        ip_src  = arp.psrc
        mac_src = arp.hwsrc

        if arp.op in (1, 2):  # ARP Request (1) o Reply (2)
            if self._es_ip_privada(ip_src) and ip_src not in ("0.0.0.0", "255.255.255.255"):
                self.lista_blanca.verificar_y_alertar(
                    ip=ip_src, mac=mac_src, protocolo="ARP"
                )

    def _analizar_dns(self, paquete, ip_src: str):
        """Extrae el nombre de dominio de consultas DNS."""
        self._contadores["dns"] += 1
        try:
            # DNSQR.qname es el nombre de dominio consultado
            dominio = paquete[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
            if dominio and len(dominio) > 3:
                self.monitor.registrar_consulta_dns(ip_src, dominio)
                self.log.debug(f"[CAPTURA] DNS: {ip_src} → {dominio}")
        except Exception as e:
            self.log.debug(f"[CAPTURA] Error en DNS: {e}")

    def _analizar_http(self, paquete, ip_src: str):
        """Extrae el host HTTP de peticiones en texto plano (puerto 80)."""
        try:
            puerto = paquete[TCP].dport
            if puerto != 80:
                return
            payload = paquete[Raw].load.decode("utf-8", errors="replace")
            if not payload.startswith(("GET ", "POST ", "HEAD ", "PUT ")):
                return

            self._contadores["http"] += 1
            # Extraer cabecera Host:
            for linea in payload.splitlines():
                if linea.lower().startswith("host:"):
                    host   = linea.split(":", 1)[1].strip()
                    metodo = payload.split(" ")[0]
                    self.monitor.registrar_peticion_http(ip_src, host, metodo)
                    break
        except Exception:
            pass

    # ── Utilidades ────────────────────────────────────────────────────────────

    def _es_ip_privada(self, ip: str) -> bool:
        """
        Determina si una IP pertenece a rangos privados (RFC 1918)
        o es loopback/link-local.
        """
        try:
            partes = list(map(int, ip.split(".")))
            if len(partes) != 4:
                return False
            # 10.0.0.0/8
            if partes[0] == 10:
                return True
            # 172.16.0.0/12
            if partes[0] == 172 and 16 <= partes[1] <= 31:
                return True
            # 192.168.0.0/16
            if partes[0] == 192 and partes[1] == 168:
                return True
            # 127.0.0.0/8 loopback
            if partes[0] == 127:
                return True
            # 169.254.0.0/16 link-local
            if partes[0] == 169 and partes[1] == 254:
                return True
        except Exception:
            pass
        return False

    def _detectar_interfaz(self) -> str:
        """
        Detecta automáticamente la interfaz de red activa de forma segura.
        Soporta los formatos legibles de Scapy en Windows y Linux.
        """
        try:
            # En Windows, conf.iface de Scapy ya tiene el objeto de la interfaz activa corregido
            if hasattr(conf.iface, "name") and conf.iface.name:
                self.log.info(f"[CAPTURA] Interfaz activa detectada vía Scapy: {conf.iface.name}")
                return conf.iface.name
            
            # Fallback para sistemas Linux o configuraciones estándar
            interfaces = get_if_list()
            activas = [i for i in interfaces if "loopback" not in i.lower() and "lo" != i.lower()]
            
            if activas:
                self.log.info(f"[CAPTURA] Interfaces disponibles encontradas: {activas}")
                return activas[0]
                
        except Exception as e:
            self.log.warning(f"[CAPTURA] No se pudo detectar interfaz automáticamente: {e}")

        # Último recurso: lo que sea que Scapy tenga mapeado por defecto
        return str(conf.iface)

    def _imprimir_estadisticas_periodicas(self):
        """Imprime estadísticas en consola cada 60 segundos."""
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
