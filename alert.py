import smtplib
from email.mime.text import MIMEText
from datetime import datetime
import psycopg2

# Database connection (update with your credentials)
DB_URL = "postgresql://traffic_db_2_user:MBuTs1sQlPZawUwdU5lc6VAZtL3WrsUb@dpg-cvumdpbuibrs738cdp30-a.oregon-postgres.render.com/traffic_db_2"

def check_for_malicious_traffic():
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM traffic WHERE status = 1")
    count = cur.fetchone()[0]
    conn.close()
    return count > 0

def insert_alert(message):
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor()
    timestamp = datetime.now()
    cur.execute("INSERT INTO alerts (message, timestamp, source) VALUES (%s, %s, %s)",
                (message, timestamp, 'DNN Detection'))
    conn.commit()
    conn.close()

def send_email_alert(subject, body):
    sender_email = "your_email@example.com"
    receiver_email = "admin@example.com"
    password = "your_email_password"
    
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email

    try:
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
        print("Email alert sent.")
    except Exception as e:
        print("Email failed:", e)

def generate_alert_if_needed():
    if check_for_malicious_traffic():
        message = "DDoS attack detected by DNN model. Malicious traffic present."
        insert_alert(message)
        send_email_alert("🚨 DDoS Alert", message)
        return True
    return False
