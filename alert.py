# backend/alert.py

import psycopg2
from datetime import datetime
import smtplib
from email.mime.text import MIMEText

# PostgreSQL connection string
DB_URL = "postgresql://traffic_db_2_user:MBuTs1sQlPZawUwdU5lc6VAZtL3WrsUb@dpg-cvumdpbuibrs738cdp30-a.oregon-postgres.render.com/traffic_db_2"

# Email credentials
SENDER_EMAIL = "iambalamurugan005@gmail.com"
APP_PASSWORD = "hqpsaxhskmahouyx"
RECEIVER_EMAIL = "iambalamurugan05@gmail.com"
from datetime import datetime
import psycopg2

def insert_alert_to_db(ip, message, source="DNN Detection"):
    try:
        conn = psycopg2.connect(DB_URL)
        cur = conn.cursor()
        timestamp = datetime.now()
        cur.execute(
            "INSERT INTO alerts (ip, message, timestamp, source) VALUES (%s, %s, %s, %s)",
            (ip, message, timestamp, source)
        )
        conn.commit()
        conn.close()
        print("✅ Alert inserted into DB.")
    except Exception as e:
        print("❌ Failed to insert alert:", e)
print(f"Inserting alert: IP={ip}, Message={message}, Timestamp={timestamp}, Source={source}")


def send_email_alert(subject, body):
    # Encode the email body as UTF-8 to handle emojis and special characters
    msg = MIMEText(body.encode('utf-8'), _charset="utf-8")
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL

    try:
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(SENDER_EMAIL, APP_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()
        print("✅ Email alert sent.")
    except Exception as e:
        print("❌ Email failed:", e)




def trigger_alert(ip, message):
    insert_alert_to_db(ip, message)
    send_email_alert("🚨 DDoS Alert", message)

