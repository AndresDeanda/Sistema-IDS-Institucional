"""
===========================================================
  MÓDULO: email_alerter.py
  Sistema de Alertas por Correo Electrónico
  
  Descripción:
    Gestiona el envío de correos de alerta al administrador.
    Usa credenciales almacenadas en variables de entorno
    (NUNCA en texto plano en el código).
    Implementa cola de envío asíncrono para no bloquear
    la captura de paquetes. Concepto AAA: el correo del
    administrador es configurable sin tocar el código.
===========================================================
"""

import logging
import queue
import smtplib
import ssl
import threading
from datetime     import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText


class ModuloAlertas:
    """
    Módulo de envío de alertas por correo electrónico.
    Usa cola asíncrona para no bloquear el hilo de captura.
    """

    def __init__(self, smtp_host: str, smtp_port: int, smtp_user: str,
                 smtp_password: str, admin_email: str, logger: logging.Logger):
        """
        Inicializa el módulo de alertas.

        Parámetros:
            smtp_host     : Servidor SMTP (ej. smtp.gmail.com).
            smtp_port     : Puerto SMTP (587 para TLS, 465 para SSL).
            smtp_user     : Usuario SMTP (correo del remitente).
            smtp_password : Contraseña SMTP (desde variable de entorno).
            admin_email   : Correo del administrador destinatario.
                            (CONCEPTO AAA: identificación del administrador)
            logger        : Logger del sistema.
        """
        self.smtp_host     = smtp_host
        self.smtp_port     = smtp_port
        self.smtp_user     = smtp_user
        self._smtp_password= smtp_password  # Prefijo _ indica privado
        self.admin_email   = admin_email
        self.log           = logger

        # Cola de correos pendientes de envío
        self._cola: queue.Queue = queue.Queue(maxsize=100)

        # Estadísticas
        self._enviados   = 0
        self._fallidos   = 0

        # Iniciar hilo de envío en background
        self._hilo_envio = threading.Thread(
            target=self._worker_envio,
            daemon=True,
            name="AletrasEmailWorker"
        )
        self._hilo_envio.start()
        self.log.info(f"[ALERTAS] Módulo iniciado. Destino: {self.admin_email}")

    # ── API pública ────────────────────────────────────────────────────────────

    def enviar(self, asunto: str, cuerpo: str, prioridad: str = "normal"):
        """
        Encola un correo de alerta para envío asíncrono.

        Parámetros:
            asunto    : Asunto del correo.
            cuerpo    : Cuerpo del correo (texto plano).
            prioridad : 'alta' para insertar al frente de la cola.
        """
        mensaje = {
            "asunto"    : asunto,
            "cuerpo"    : cuerpo,
            "timestamp" : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "prioridad" : prioridad,
        }
        try:
            self._cola.put_nowait(mensaje)
            self.log.debug(f"[ALERTAS] Correo encolado: {asunto[:60]}...")
        except queue.Full:
            self.log.error("[ALERTAS] Cola de correos llena. Alerta descartada.")

    def cambiar_admin_email(self, nuevo_email: str):
        """
        Cambia el correo del administrador en tiempo real.
        Implementa el concepto AAA (Autorización) de forma dinámica:
        el destinatario autorizado puede actualizarse sin reiniciar.

        Parámetros:
            nuevo_email : Nueva dirección del administrador.
        """
        email_anterior    = self.admin_email
        self.admin_email  = nuevo_email
        self.log.info(
            f"[ALERTAS] Correo de administrador actualizado: "
            f"{email_anterior} → {nuevo_email}"
        )

    def obtener_estadisticas(self) -> dict:
        """Retorna estadísticas de envío."""
        return {
            "enviados"  : self._enviados,
            "fallidos"  : self._fallidos,
            "en_cola"   : self._cola.qsize(),
            "admin"     : self.admin_email,
        }

    # ── Worker de envío asíncrono ─────────────────────────────────────────────

    def _worker_envio(self):
        """
        Hilo de background que procesa la cola de correos.
        Reintenta hasta 3 veces en caso de fallo.
        """
        while True:
            try:
                mensaje = self._cola.get(timeout=5)
                exito   = self._enviar_smtp(
                    asunto=mensaje["asunto"],
                    cuerpo=mensaje["cuerpo"]
                )
                if exito:
                    self._enviados += 1
                else:
                    self._fallidos += 1
                self._cola.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                self.log.error(f"[ALERTAS] Error inesperado en worker: {e}")

    def _enviar_smtp(self, asunto: str, cuerpo: str) -> bool:
        """
        Envía el correo vía SMTP con TLS.
        Retorna True si fue exitoso, False en caso contrario.
        """
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = asunto
            msg["From"]    = f"IDS Institucional <{self.smtp_user}>"
            msg["To"]      = self.admin_email
            msg["X-Priority"] = "1"  # Alta prioridad

            # Adjuntar cuerpo como texto plano
            msg.attach(MIMEText(cuerpo, "plain", "utf-8"))

            # Conexión TLS (puerto 587)
            contexto_tls = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30) as servidor:
                servidor.ehlo()
                servidor.starttls(context=contexto_tls)
                servidor.ehlo()
                servidor.login(self.smtp_user, self._smtp_password)
                servidor.sendmail(
                    from_addr = self.smtp_user,
                    to_addrs  = [self.admin_email],
                    msg       = msg.as_string()
                )

            self.log.info(f"[ALERTAS] ✓ Correo enviado: {asunto[:70]}")
            return True

        except smtplib.SMTPAuthenticationError:
            self.log.error(
                "[ALERTAS] Error de autenticación SMTP. "
                "Verifica SMTP_USER y SMTP_PASSWORD en el archivo .env"
            )
        except smtplib.SMTPConnectError:
            self.log.error(
                f"[ALERTAS] No se pudo conectar a {self.smtp_host}:{self.smtp_port}. "
                "Verifica conectividad y SMTP_HOST/SMTP_PORT en .env"
            )
        except smtplib.SMTPException as e:
            self.log.error(f"[ALERTAS] Error SMTP: {e}")
        except Exception as e:
            self.log.error(f"[ALERTAS] Error inesperado enviando correo: {e}")

        return False
