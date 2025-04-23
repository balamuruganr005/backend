from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time
import matplotlib.pyplot as plt
import io
import psycopg2
import geoip2.database
import numpy as np
import requests
from urllib.parse import urlparse
from io import StringIO
import os
import joblib
from flask_mail import Mail, Message
from collections import defaultdict
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from threading import Thread
from sqlalchemy import create_engine



app = Flask(__name__)

# Updated CORS configuration
CORS(app, origins=["http://localhost:5173", "https://ddosweb.vercel.app"])

# Initialize rate limiter (to prevent DDoS)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["500 per minute"]
)

# PostgreSQL connection setup using your Render database connection string
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://traffic_db_2_user:MBuTs1sQlPZawUwdU5lc6VAZtL3WrsUb@dpg-cvumdpbuibrs738cdp30-a.oregon-postgres.render.com/traffic_db_2')
conn = psycopg2.connect(DATABASE_URL, sslmode='require')
c = conn.cursor()

# Create table if not exists (updated to match all 18 columns)
c.execute("""
    CREATE TABLE IF NOT EXISTS traffic_logs2 (
        id SERIAL PRIMARY KEY,
        ip TEXT,
        timestamp REAL,
        request_size INTEGER,
        status TEXT,
        location TEXT,
        user_agent TEXT,
        request_type TEXT,
        high_request_rate BOOLEAN,
        small_payload BOOLEAN,
        large_payload BOOLEAN,
        spike_in_requests BOOLEAN,
        repeated_access BOOLEAN,
        unusual_user_agent BOOLEAN,
        invalid_headers BOOLEAN,
        destination_port TEXT,
        country TEXT,
        city TEXT
    )
""")
conn.commit()

# Define Malicious & Blocked IPs
MALICIOUS_IPS = {"45.140.143.77", "185.220.100.255"}
BLOCKED_IPS = {"81.23.152.244", "222.252.194.204"}

def rate_limiter(ip, trust_score):
    current_time = time.time()

    # If the user is trusted (score > 0.9), allow instantly
    if trust_score >= 0.9:
        user_last_request[ip] = current_time
        return True  # ✅ Full Priority

    # If the user is suspicious (score 0.5-0.9), introduce delay
    elif 0.5 <= trust_score < 0.9:
        if ip in user_last_request and (current_time - user_last_request[ip] < 2):  # Delay 2s
            return False  # ⚠️ Limited Priority
        user_last_request[ip] = current_time
        return True

    # If attacker (score < 0.5), block
    else:
        return False  # ❌ No Priority

@app.route("/check_access", methods=["POST"])
def check_access():
    data = request.json
    ip = data.get("ip")
    trust_score = data.get("trust_score")  # This should come from the DNN

    allowed = rate_limiter(ip, trust_score)

    return jsonify({"ip": ip, "allowed": allowed})

def get_client_ips():
    """
    Returns a list of client IPs from headers in priority order:
    1. CF-Connecting-IP (Cloudflare)
    2. X-Forwarded-For (proxy chains)
    3. Remote address (direct request)
    """
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return [cf_ip]

    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return [ip.strip() for ip in forwarded.split(",")]

    return [request.remote_addr]


def get_location(ip):
    try:
        reader = geolite2.reader()
        geo_info = reader.get(ip)
        geolite2.close()

        if geo_info:
            country = geo_info.get('country', {}).get('names', {}).get('en', 'Unknown')
            city = geo_info.get('city', {}).get('names', {}).get('en', 'Unknown')
            location = f"{geo_info.get('location', {}).get('latitude', 'N/A')}, {geo_info.get('location', {}).get('longitude', 'N/A')}"
        else:
            location, city, country = 'Unknown', 'Unknown', 'Unknown'

        return location, city, country

    except Exception as e:
        print(f"[GeoError] {e}")
        return 'Unknown', 'Unknown', 'Unknown'


@app.route("/", methods=["GET", "POST"])
def home():
    timestamp = time.time()
    ips = get_client_ips()
    request_size = len(request.data)  # ✅ Accurate byte size
    user_agent = request.headers.get("User-Agent", "unknown")
    request_type = request.method

    for ip in ips:
        destination_port = int(request.environ.get('REMOTE_PORT', 443))

        # Get location info
        location, city, country = get_location(ip)

        # Get request count for the IP in the past 60 seconds
        c.execute("""SELECT COUNT(*) FROM traffic_logs2 WHERE ip = %s AND timestamp > %s""",
                  (ip, time.time() - 60))
        request_count = c.fetchone()[0]

        # Get total requests in the past 5 seconds (for spike detection)
        c.execute("""SELECT COUNT(*) FROM traffic_logs2 WHERE timestamp > %s""",
                  (time.time() - 5,))
        recent_requests = c.fetchone()[0]

        # Behavioral flags
        high_request_rate = request_count > 100
        small_payload = request_size < 500
        large_payload = request_size > 10000
        spike_in_requests = recent_requests > 100
        repeated_access = request_count > 10
        unusual_user_agent = "bot" in user_agent.lower() or "crawl" in user_agent.lower()
        invalid_headers = False  # Optional future check

        # --- Prioritized status detection ---
        if ip in MALICIOUS_IPS or spike_in_requests:
            status = "malicious"
            request_size = max(request_size, 1500)  # Normalize for attack traffic
        elif ip in BLOCKED_IPS:
            status = "blocked"
        elif request_size < 50 or request_size > 5000 or unusual_user_agent or request_count > 50:
            status = "suspicious"
        else:
            status = "normal"

        # Insert into traffic_logs2
        c.execute("""
            INSERT INTO traffic_logs2 
            (ip, timestamp, request_size, status, location, user_agent, request_type, 
             high_request_rate, small_payload, large_payload, spike_in_requests, 
             repeated_access, unusual_user_agent, invalid_headers, destination_port, 
             country, city) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (ip, timestamp, request_size, status, location, user_agent, request_type,
              high_request_rate, small_payload, large_payload, spike_in_requests,
              repeated_access, unusual_user_agent, invalid_headers, destination_port,
              country, city))
        conn.commit()

    return jsonify({"message": "Request logged", "ips": ips, "size": request_size})

def analyze_traffic_entry(ip, request_size, user_agent, request_type):
    """Analyze traffic and assign flags + status."""
    status = "normal"

    # Define status based on user agent and request behavior
    if "sqlmap" in user_agent.lower() or "bot" in user_agent.lower() or request_type == "HEAD":
        status = "suspicious"
    if request_size < 50:
        status = "suspicious"
    elif request_size > 5000:
        status = "suspicious"

    # Behavioral flags
    high_request_rate = False  # Update if needed from DB
    small_payload = request_size < 100
    large_payload = request_size > 1000
    spike_in_requests = False
    repeated_access = False
    unusual_user_agent = "bot" in user_agent.lower() or "sqlmap" in user_agent.lower()
    invalid_headers = False  # Optional: analyze headers

    return {
        "status": status,
        "high_request_rate": high_request_rate,
        "small_payload": small_payload,
        "large_payload": large_payload,
        "spike_in_requests": spike_in_requests,
        "repeated_access": repeated_access,
        "unusual_user_agent": unusual_user_agent,
        "invalid_headers": invalid_headers
    }


@app.route("/traffic-data", methods=["GET"])
def get_traffic_data():
    try:
        with conn.cursor() as c:
            c.execute("""
                SELECT id, ip, timestamp, request_size, status, location, user_agent, 
                       request_type, high_request_rate, small_payload, large_payload, 
                       spike_in_requests, repeated_access, unusual_user_agent, 
                       invalid_headers, destination_port, country, city 
                FROM traffic_logs2
            """)
            rows = c.fetchall()

            columns = [
                "id", "ip", "time", "size", "status", "location", "user_agent",
                "request_type", "high_request_rate", "small_payload", "large_payload",
                "spike_in_requests", "repeated_access", "unusual_user_agent",
                "invalid_headers", "destination_port", "country", "city"
            ]

            data = []
            for row in rows:
                entry = dict(zip(columns, row))

                # 🔍 Real-time status override logic
                size = entry["size"]
                user_agent = entry["user_agent"].lower()
                req_type = entry["request_type"]

                suspicious_conditions = [
                    size < 100,
                    "sqlmap" in user_agent,
                    "bot" in user_agent,
                    req_type == "HEAD"
                ]

                if "malicious" in entry["status"].lower():
                    entry["status"] = "malicious"
                elif any(suspicious_conditions):
                    entry["status"] = "suspicious"
                else:
                    entry["status"] = "normal"

                data.append(entry)

        return jsonify({"traffic_logs2": data})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/traffic-graph", methods=["GET"])
def traffic_graph():
    try:
        with conn.cursor() as c:
            c.execute("SELECT timestamp FROM traffic_logs2 ORDER BY timestamp ASC")
            rows = c.fetchall()

        if not rows:
            return jsonify({"error": "No data available"}), 404

        timestamps = [time.strftime("%H:%M:%S", time.localtime(row[0])) for row in rows]

        plt.figure(figsize=(10, 5))
        plt.step(timestamps, range(len(timestamps)), marker="o", linestyle="-", color="b")
        plt.xlabel("Time")
        plt.ylabel("Requests")
        plt.title("Traffic Flow Over Time")
        plt.xticks(rotation=45)

        img_path = "traffic_graph.png"
        plt.savefig(img_path)
        plt.close()

        return send_file(img_path, mimetype='image/png')

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/insert-traffic-data", methods=["POST"])
def insert_traffic_data():
    print("🔔 insert_traffic_data called")
    print("Payload:", request.get_json())

    try:
        data = request.get_json()

        # Auto IP detection fallback
        ip = request.remote_addr if data.get("ip") == "auto" or not data.get("ip") else data.get("ip")
        request_size = int(data.get("request_size", 0))
        request_type = data.get("request_type", "GET")
        destination_port = int(data.get("destination_port", 443))
        user_agent = data.get("user_agent", "unknown")
        timestamp = int(time.time())

        # Default location placeholders
        location = data.get("location", "unknown")
        country = data.get("country", "unknown")
        city = data.get("city", "unknown")

        # Analyze and determine flags/status
        analysis = analyze_traffic_entry(ip, request_size, user_agent, request_type)
        status = analysis["status"]

        # Insert data
        with conn.cursor() as c:
            c.execute("""
                INSERT INTO traffic_logs2 (
                    ip, timestamp, request_size, status, location, user_agent, request_type, 
                    high_request_rate, small_payload, large_payload, spike_in_requests, 
                    repeated_access, unusual_user_agent, invalid_headers, destination_port, 
                    country, city
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s
                )
            """, (
                ip, timestamp, request_size, status, location, user_agent, request_type,
                analysis["high_request_rate"], analysis["small_payload"], analysis["large_payload"],
                analysis["spike_in_requests"], analysis["repeated_access"], analysis["unusual_user_agent"],
                analysis["invalid_headers"], destination_port, country, city
            ))
            conn.commit()

        return jsonify({"message": f"Traffic data logged with status '{status}'"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/detect-anomaly", methods=["GET"])
def detect_anomaly():
    try:
        # Time window: last 60 seconds
        time_threshold = time.time() - 60

        # Get number of requests per IP in the last 60 seconds
        c.execute("""
            SELECT ip, COUNT(*) as request_count
            FROM traffic_logs2
            WHERE timestamp > %s
            GROUP BY ip
            ORDER BY request_count DESC
        """, (time_threshold,))
        rows = c.fetchall()

        anomalies = []
        for ip, count in rows:
            if count > 100:  # 👈 Set your own threshold here
                anomalies.append({
                    "ip": ip,
                    "request_count": count,
                    "status": "anomaly detected"
                })

        return jsonify({
            "anomalies": anomalies,
            "message": f"Detected {len(anomalies)} anomalies."
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/detect-attack', methods=['GET'])
def detect_attack():
    try:
        cursor = conn.cursor()
        # Check if there are any malicious or suspicious entries
        cursor.execute("""
            SELECT COUNT(*) FROM traffic_logs2 
            WHERE status IN ('malicious', 'suspicious')
        """)
        attack_count = cursor.fetchone()[0]
        cursor.close()

        if attack_count > 0:
            return jsonify({"message": "Attack detected!", "attack_status": "ongoing"}), 200
        else:
            return jsonify({"message": "No attack detected", "attack_status": "safe"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

conn = psycopg2.connect("postgresql://traffic_db_2_user:MBuTs1sQlPZawUwdU5lc6VAZtL3WrsUb@dpg-cvumdpbuibrs738cdp30-a.oregon-postgres.render.com/traffic_db_2")
cursor = conn.cursor()

@app.route('/stop-attack', methods=['GET', 'POST'])
def stop_attack():
    if request.method == 'GET':
        return jsonify({
            "message": "📍 This endpoint is used to stop DDoS attacks.",
            "usage": "Send a POST request with JSON body: { 'request_size': <int> } to block traffic with request_size < 90"
        }), 200

    if request.method == 'POST':
        request_size = request.json.get('request_size')
        try:
            if request_size and request_size < 90:
                # Fetch details of entries that will be blocked
                cursor.execute("""
                    SELECT ip, time, request_size, user_agent, status
                    FROM traffic_logs2
                    WHERE request_size < %s AND (status = '1' OR status = 'suspicious' OR status = 'malicious' OR status = '2')
                """, (request_size,))
                blocked_users = cursor.fetchall()

                # Update their status to 'blocked'
                cursor.execute("""
                    UPDATE traffic_logs2
                    SET status = 'blocked'
                    WHERE request_size < %s AND (status = '1' OR status = 'suspicious' OR status = 'malicious' OR status = '2')
                """, (request_size,))
                conn.commit()

                # Format blocked user data
                blocked_list = [
                    {
                        "ip": row[0],
                        "time": str(row[1]),
                        "request_size": row[2],
                        "user_agent": row[3],
                        "old_status": row[4],
                        "new_status": "blocked"
                    } for row in blocked_users
                ]

                return jsonify({
                    "message": f"✅ Attack stopped: {len(blocked_list)} IPs blocked with request size < {request_size}.",
                    "blocked_users": blocked_list
                }), 200
            else:
                return jsonify({"message": "❌ Request size not valid for stopping attack."}), 400
        except Exception as e:
            print("Error stopping attack:", e)
            return jsonify({"error": str(e)}), 500



## Define DB URL
DB_URL = "postgresql://traffic_db_2_user:MBuTs1sQlPZawUwdU5lc6VAZtL3WrsUb@dpg-cvumdpbuibrs738cdp30-a.oregon-postgres.render.com/traffic_db_2"

@app.route('/traffic-summary', methods=['GET'])
def traffic_summary():
    try:
        conn = psycopg2.connect(DB_URL, sslmode='require')
        cursor = conn.cursor()

        # Fetch needed fields for logic
        cursor.execute("""
            SELECT request_size, user_agent, request_type, status FROM traffic_logs2
        """)
        rows = cursor.fetchall()

        legit_count = 0
        malicious_count = 0

        for size, user_agent, req_type, db_status in rows:
            user_agent = user_agent.lower()

            # Real-time logic
            suspicious = (
                size < 100 or
                "sqlmap" in user_agent or
                "bot" in user_agent or
                req_type == "HEAD"
            )

            if "malicious" in db_status.lower():
                malicious_count += 1
            elif suspicious:
                malicious_count += 1
            else:
                legit_count += 1

        cursor.close()
        conn.close()

        return jsonify({
            "legit": legit_count,
            "malicious": malicious_count
        })

    except Exception as e:
        print(f"Error in /traffic-summary: {e}")
        return jsonify({"error": str(e)}), 500





@app.route("/debug-status", methods=["GET"])
def debug_status():
    try:
        conn = psycopg2.connect(DATABASE_URL, sslmode='require')
        cursor = conn.cursor()

        cursor.execute("SELECT status, COUNT(*) FROM traffic_logs2 GROUP BY status;")
        rows = cursor.fetchall()

        result = {status: count for status, count in rows}
        cursor.close()
        conn.close()

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Add to app.py
@app.route('/dnn-status', methods=['GET'])
def dnn_status():
    try:
        conn = get_connect_db()
        cur = conn.cursor()
        cur.execute("SELECT timestamp, status FROM traffic_logs2 ORDER BY timestamp DESC LIMIT 100;")
        rows = cur.fetchall()
        result = [{"timestamp": r[0], "status": r[1]} for r in rows]
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)})

model = joblib.load('dnn_model.pkl')  # Load your DNN model

# Fetch the DATABASE_URL from environment variables
DATABASE_URL = os.getenv('DATABASE_URL')

# Function to connect to PostgreSQL using the URL
def connect_db():
    parsed_url = urlparse(DATABASE_URL)
    conn = psycopg2.connect(
        database=parsed_url.path[1:],  # Removing the leading '/' from the database name
        user=parsed_url.username,
        password=parsed_url.password,
        host=parsed_url.hostname,
        port=parsed_url.port
    )
    return conn

# Function to fetch traffic data
def get_traffic_data():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM traffic_logs2 WHERE timestamp > %s", (datetime.now() - timedelta(minutes=15),))
    data = cursor.fetchall()
    conn.close()
    return data

# DNN-based traffic analysis
def analyze_traffic(data):
    predictions = model.predict(data)
    return predictions

# Function to send alerts (using alert.py)
from alert import trigger_alert

@app.route('/detect-dnn', methods=['POST'])
def detect_dnn():
    traffic_data = get_traffic_data()
    features = [data[1:] for data in traffic_data]  # Skip timestamp etc.
    predictions = analyze_traffic(features)

    malicious_entries = [traffic_data[i] for i, pred in enumerate(predictions) if pred == 1]

    if malicious_entries:
        trigger_alert("🚨 DDoS Detected by DNN! Malicious traffic found. Take action immediately.")
        return jsonify({
            "status": "malicious traffic detected",
            "data": malicious_entries
        }), 200

    return jsonify({"status": "no malicious traffic detected"}), 200

@app.route('/traffic-dataa', methods=['GET'])
def traffic_data():
    data = get_traffic_data()
    return jsonify(data), 200

# Route to view alert history
@app.route('/alert-history', methods=['GET'])
def alert_history():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
    alerts = cursor.fetchall()
    conn.close()
    return jsonify(alerts), 200

from alert import trigger_alert

@app.route("/test-email-alert")
def test_email_alert():
    print(" Test email route hit!")  # Debug: Checking if the route is being hit
    
    ip = "127.0.0.1"
    message = "Test alert from /test-email-alert endpoint."
    
    # Log values before passing to trigger_alert
    print(f"Test Email Alert - IP: {ip}, Message: {message}")
    
    trigger_alert(ip, message)  # Call the trigger_alert function
    return "Alert Triggered"

DB_URL = "postgresql://traffic_db_2_user:MBuTs1sQlPZawUwdU5lc6VAZtL3WrsUb@dpg-cvumdpbuibrs738cdp30-a.oregon-postgres.render.com/traffic_db_2"

@app.route("/alert-history", methods=["GET"])
def get_alert_history():
    try:
        conn = psycopg2.connect(DB_URL)
        cur = conn.cursor()
        cur.execute("SELECT id, ip, message, timestamp, source FROM alerts ORDER BY timestamp DESC")
        rows = cur.fetchall()
        conn.close()

        alert_list = []
        for row in rows:
            alert_list.append({
                "id": row[0],
                "ip": row[1],
                "message": row[2],
                "timestamp": row[3].strftime("%Y-%m-%d %H:%M:%S"),
                "source": row[4]
            })

        return jsonify(alert_list), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

DB_URL = "postgresql://traffic_db_2_user:MBuTs1sQlPZawUwdU5lc6VAZtL3WrsUb@dpg-cvumdpbuibrs738cdp30-a.oregon-postgres.render.com/traffic_db_2"

# Email credentials
SENDER_EMAIL = "iambalamurugan005@gmail.com"
APP_PASSWORD = "hqpsaxhskmahouyx"
RECEIVER_EMAIL = "iambalamurugan05@gmail.com"

# Function to fetch alerts from the alerts table
def fetch_alerts():
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor()
    cur.execute("SELECT * FROM traffic_logs2 ORDER BY timestamp DESC LIMIT 100")
    data = cur.fetchall()
    columns = [desc[0] for desc in cur.description]
    conn.close()
    return columns, data

# Function to send the email with the CSV attachment
def send_email_with_csv(subject, body, columns, rows):
    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL
    msg["Subject"] = subject

    msg.attach(MIMEText(body, "plain"))

    csvfile = StringIO()
    writer = csv.writer(csvfile)
    writer.writerow(columns)
    writer.writerows(rows)
    csv_data = csvfile.getvalue()

    attachment = MIMEApplication(csv_data, Name="alert_history.csv")
    attachment['Content-Disposition'] = 'attachment; filename="alert_history.csv"'
    msg.attach(attachment)

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(SENDER_EMAIL, APP_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())

# Continuous monitor function
def monitor_traffic():
    while True:
        try:
            conn = psycopg2.connect(DB_URL)
            cur = conn.cursor()

            # Check for bad traffic in traffic_logs2 table
            cur.execute("SELECT COUNT(*) FROM traffic_logs2 WHERE status=1 OR status ILIKE 'suspicious' OR status ILIKE 'malicious'")
            count = cur.fetchone()[0]
            conn.close()

            if count >= 1:
                # Fetch the alerts and send the email with CSV attachment
                columns, rows = fetch_alerts()
                send_email_with_csv(
                    subject="DDOS/DOS detected immediate action required",
                    body="Attached is the latest DDoS alert history. Please investigate immediately.",
                    columns=columns,
                    rows=rows
                )

            # Wait for 15 seconds before checking again
            time.sleep(15)
        except Exception as e:
            print(f"❌ Error during monitoring: {e}")

# Start the monitoring in a separate thread
def start_monitoring():
    monitor_thread = threading.Thread(target=monitor_traffic)
    monitor_thread.daemon = True
    monitor_thread.start()

# Simple /monitor route to confirm monitoring is active
@app.route("/monitor", methods=["GET"])
def monitor_route():
    return jsonify({"status": "monitoring_active", "message": "Monitoring is running in the background every 15 seconds."})


# Run the Flask app
if __name__ == "__main__":
    create_traffic_logs2_table()
    start_monitoring()
    app.run(host="0.0.0.0", port=5000, debug=True)
