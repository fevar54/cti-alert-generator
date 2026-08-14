import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import json
import os

def load_config():
    config_path = "config.json"
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return None

def send_alert_email(subject, html_content, pdf_path=None):
    config = load_config()
    if not config:
        print("❌ Error: No se encontró el archivo config.json")
        return

    smtp_conf = config["smtp"]
    recipients = config["clients"]

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_conf["sender_email"]
    msg["To"] = ", ".join(recipients)

    # Adjuntar HTML
    msg.attach(MIMEText(html_content, "html"))

    # Adjuntar PDF si existe
    if pdf_path and os.path.exists(pdf_path):
        with open(pdf_path, "rb") as f:
            pdf_attachment = MIMEApplication(f.read(), Name=os.path.basename(pdf_path))
            pdf_attachment["Content-Disposition"] = f'attachment; filename="{os.path.basename(pdf_path)}"'
            msg.attach(pdf_attachment)

    try:
        print("🔄 Conectando al servidor SMTP de Gmail...")
        server = smtplib.SMTP(smtp_conf["server"], smtp_conf["port"])
        server.starttls()
        server.login(smtp_conf["sender_email"], smtp_conf["sender_password"])
        server.sendmail(smtp_conf["sender_email"], recipients, msg.as_string())
        server.quit()
        print("✅ ¡Alerta enviada con éxito a todos los clientes configurados!")
    except Exception as e:
        print(f"❌ Error al enviar el correo: {e}")