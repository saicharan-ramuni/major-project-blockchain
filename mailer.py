import smtplib
from email.message import EmailMessage

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_FROM = "saibabutruproject@gmail.com"
SMTP_PASSWORD = "qlwmjoxzfddcrqns"


def send_email(to_email, subject, body):
    if not to_email:
        return False
    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    s = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
    s.starttls()
    s.login(SMTP_FROM, SMTP_PASSWORD)
    s.send_message(msg)
    s.quit()
    return True


def send_email_with_attachment(to_email, subject, body, attachment_bytes, attachment_name, mimetype="application/octet-stream"):
    if not to_email:
        return False
    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    if attachment_bytes is not None and attachment_name:
        msg.add_attachment(attachment_bytes, maintype="application", subtype="octet-stream", filename=attachment_name)
    s = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
    s.starttls()
    s.login(SMTP_FROM, SMTP_PASSWORD)
    s.send_message(msg)
    s.quit()
    return True


def build_share_email(patient_name, symptoms, report_date):
    subject = "New Patient Report Shared"
    body = (
        "A patient has shared a report with your hospital/doctor.\n\n"
        f"Patient Name: {patient_name}\n"
        f"Symptoms: {symptoms}\n"
        f"Report Date: {report_date}\n"
        "Report file is attached with this email.\n"
    )
    return subject, body


def build_prescription_email(patient_name, report_date, prescription_text):
    subject = "Prescription Provided"
    body = (
        "A prescription has been provided for your report.\n\n"
        f"Patient Name: {patient_name}\n"
        f"Report Date: {report_date}\n"
        f"Prescription: {prescription_text}\n"
        "Report file is attached with this email.\n"
    )
    return subject, body
