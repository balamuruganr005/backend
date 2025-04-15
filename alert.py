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

from datetime import datetime
import psycopg2

def insert_alert_to_db(ip, message, source="DNN Detection"):
    try:
        # Ensure valid types before inserting
        ip = str(ip)
        message = str(message)

        # Log input data before execution
        print(f"Inserting alert: IP={ip}, Message={message}, Source={source}")

        timestamp = datetime.now()

        # Connect to the database
        conn = psycopg2.connect(DB_URL)
        cur = conn.cursor()

        # Execute the insert statement
        query = 'INSERT INTO alerts ("ip", "message", "timestamp", "source") VALUES (%s, %s, %s, %s)'
        cur.execute(query, (ip, message, timestamp, source))

        conn.commit()

        print(" Data inserted successfully.")

        conn.close()
    except Exception as e:
        print(" Failed to insert alert:", e)




import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header

def send_email_alert(subject, body):
    print(" Sending email now...")
    try:
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = RECEIVER_EMAIL
        msg["Subject"] = Header(subject,)

        body_part = MIMEText(body, "plain",)
        msg.attach(body_part)

        # Now initialize the SMTP server inside the 'with' statement
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.set_debuglevel(1)  # Optional: enable SMTP debugging
            server.login(SENDER_EMAIL, APP_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())

        print(" Email sent successfully!")

    except Exception as e:
        print(" Email failed:", e)



def trigger_alert(ip, message):
    print("Triggered alert!")  # Debug: Confirm trigger is being called
    # Ensure message is a string
    message = str(message)  
    insert_alert_to_db(ip, message)
    send_email_alert("DDoS Alert", message)



