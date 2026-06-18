
import logging
import queue
import smtplib
import ssl
import threading
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


# [MOD-007.1]
class ModuloAlertas:

    # [MOD-007.2]
    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        smtp_user: str,
        smtp_password: str,
        admin_email: str,
        logger: logging.Logger
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self._smtp_password = smtp_password
        self.admin_email = admin_email
        self.log = logger

        self._cola: queue.Queue = queue.Queue(maxsize=100)

        self._enviados = 0
        self._fallidos = 0

        self._hilo_envio = threading.Thread(
            target=self._worker_envio,
            daemon=True,
            name="AletrasEmailWorker"
        )

        self._hilo_envio.start()

        self.log.info(
            f"[ALERTAS] Módulo iniciado. Destino: {self.admin_email}"
        )

    # [MOD-007.3]
    def enviar(
        self,
        asunto: str,
        cuerpo: str,
        prioridad: str = "normal"
    ):
        mensaje = {
            "asunto": asunto,
            "cuerpo": cuerpo,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "prioridad": prioridad,
        }

        try:
            self._cola.put_nowait(mensaje)
            self.log.debug(
                f"[ALERTAS] Correo encolado: {asunto[:60]}..."
            )

        except queue.Full:
            self.log.error(
                "[ALERTAS] Cola de correos llena. Alerta descartada."
            )

    # [MOD-007.4]
    def cambiar_admin_email(self, nuevo_email: str):
        email_anterior = self.admin_email
        self.admin_email = nuevo_email

        self.log.info(
            f"[ALERTAS] Correo de administrador actualizado: "
            f"{email_anterior} → {nuevo_email}"
        )

    # [MOD-007.5]
    def obtener_estadisticas(self) -> dict:
        return {
            "enviados": self._enviados,
            "fallidos": self._fallidos,
            "en_cola": self._cola.qsize(),
            "admin": self.admin_email,
        }

    # [MOD-007.6]
    def _worker_envio(self):
        while True:
            try:
                mensaje = self._cola.get(timeout=5)

                exito = self._enviar_smtp(
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
                self.log.error(
                    f"[ALERTAS] Error inesperado en worker: {e}"
                )

    # [MOD-007.7]
    def _enviar_smtp(
        self,
        asunto: str,
        cuerpo: str
    ) -> bool:

        try:
            msg = MIMEMultipart("alternative")

            msg["Subject"] = asunto
            msg["From"] = (
                f"IDS Institucional <{self.smtp_user}>"
            )
            msg["To"] = self.admin_email
            msg["X-Priority"] = "1"

            msg.attach(
                MIMEText(cuerpo, "plain", "utf-8")
            )

            contexto_tls = ssl.create_default_context()

            with smtplib.SMTP(
                self.smtp_host,
                self.smtp_port,
                timeout=30
            ) as servidor:

                servidor.ehlo()
                servidor.starttls(context=contexto_tls)
                servidor.ehlo()

                servidor.login(
                    self.smtp_user,
                    self._smtp_password
                )

                servidor.sendmail(
                    from_addr=self.smtp_user,
                    to_addrs=[self.admin_email],
                    msg=msg.as_string()
                )

            self.log.info(
                f"[ALERTAS] ✓ Correo enviado: {asunto[:70]}"
            )

            return True

        except smtplib.SMTPAuthenticationError:
            self.log.error(
                "[ALERTAS] Error de autenticación SMTP. "
                "Verifica SMTP_USER y SMTP_PASSWORD en el archivo .env"
            )

        except smtplib.SMTPConnectError:
            self.log.error(
                f"[ALERTAS] No se pudo conectar a "
                f"{self.smtp_host}:{self.smtp_port}. "
                "Verifica conectividad y SMTP_HOST/SMTP_PORT en .env"
            )

        except smtplib.SMTPException as e:
            self.log.error(
                f"[ALERTAS] Error SMTP: {e}"
            )

        except Exception as e:
            self.log.error(
                f"[ALERTAS] Error inesperado enviando correo: {e}"
            )

        return False

