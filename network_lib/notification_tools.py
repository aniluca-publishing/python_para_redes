import smtplib
import requests
from email.message import EmailMessage


def send_email_smtp(
    to_email: str, subject: str,
    body: str, smtp_host: str,
    username: str, password: str,
    smtp_port: int = 587,
    timeout: int = 10,
) -> dict:
    """
    Envía un correo electrónico mediante SMTP autenticado.

    Parámetros:
        to_email (str): Dirección de destino.
        subject (str): Asunto del mensaje.
        body (str): Contenido del mensaje en texto plano.
        smtp_host (str): Servidor SMTP (ej. smtp.gmail.com).
        username (str): Usuario de autenticación.
        password (str): Contraseña o app password.
        smtp_port (int, opcional): Puerto SMTP. 587 por defecto.
        timeout (int, opcional): Tiempo máximo de espera en segundos.

    Retorna:
        dict: {
            "smtp_status": "ok" o "error",
            "errors": None o str (mensaje de error)
        }
    """
    msg = EmailMessage()
    msg['From'] = username
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.set_content(body)

    try:
        if smtp_port == 465:
            # TLS implícito
            with smtplib.SMTP_SSL(smtp_host, smtp_port,
                                  timeout=timeout) as smtp:
                smtp.login(username, password)
                smtp.send_message(msg)
        else:
            # STARTTLS (TLS explícito)
            with smtplib.SMTP(smtp_host, smtp_port,
                              timeout=timeout) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                smtp.login(username, password)
                smtp.send_message(msg)
        return {'smtp_status': 'ok', 'errors': None}
    except Exception as e:
        return {'smtp_status': 'error', 'errors': str(e)}


def send_webhook(webhook: str,
                 payload: dict,
                 timeout: int = 5) -> dict:
    """
    Envía un payload en formato JSON a una URL webhook mediante
    HTTP POST.

    Parámetros:
        webhook (str): URL destino del webhook.
        payload (dict): Diccionario que será enviado como JSON.
        timeout (int): Tiempo máximo de espera en segundos.

    Retorna:
        dict: {
            "webhook_status": "ok" o "error",
            "errors": None o str (mensaje de error)
        }
    """
    try:
        response = requests.post(webhook, json=payload,
                                 timeout=timeout)
        if 200 <= response.status_code < 300:
            return {'webhook_status': 'ok', 'errors': None}
        return {'webhook_status': 'error',
                'errors': f'HTTP {response.status_code}'}
    except requests.RequestException as e:
        return {'webhook_status': 'error', 'errors': str(e)}


def send_slack_notification(webhook: str,
                            text: str,
                            timeout: int = 5) -> dict:
    """
    Envía un mensaje simple a Slack utilizando un webhook.

    Parámetros:
        webhook (str): URL del webhook de Slack.
        text (str): Texto que será publicado en el canal.
        timeout (int): Tiempo máximo de espera en segundos.

    Retorna:
        dict: Resultado retornado por send_webhook().
    """
    payload = {'text': text}
    return send_webhook(webhook, payload, timeout)
