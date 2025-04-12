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
import os
import joblib
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
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://traffic_db_6kci_user:bTXPfiMeieoQ8EqNZYv1480Vwl7lJJaz@dpg-cvajkgin91rc7395vv1g-a.oregon-postgres.render.com/traffic_db_6kci')
conn = psycopg2.connect(DATABASE_URL, sslmode='require')
c = conn.cursor()

# Create table if not exists (updated to match all 18 columns)
c.execute("""
    CREATE TABLE IF NOT EXISTS traffic_logs (
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
    request_size = len(str(request.data))
    user_agent = request.headers.get("User-Agent", "unknown")
    request_type = request.method

    for ip in ips:
        status = "normal"
        destination_port = int(request.environ.get('REMOTE_PORT', 443))

        # Rules
        if request_size < 50:
            status = "suspicious"
        elif request_size > 5000:
            status = "suspicious"

        c.execute("""SELECT COUNT(*) FROM traffic_logs WHERE ip = %s AND timestamp > %s""",
                  (ip, time.time() - 60))
        request_count = c.fetchone()[0]
        if request_count > 50:
            status = "suspicious"

        if ip in MALICIOUS_IPS:
            status = "malicious"
            request_size = 1500
        elif ip in BLOCKED_IPS:
            status = "blocked"

        if "bot" in user_agent.lower() or "crawl" in user_agent.lower():
            status = "suspicious"

        c.execute("""SELECT COUNT(*) FROM traffic_logs WHERE timestamp > %s""",
                  (time.time() - 5,))
        recent_requests = c.fetchone()[0]
        if recent_requests > 100:
            status = "malicious"

        # Get location data
        location, city, country = get_location(ip)

        # Behavioral flags
        high_request_rate = request_count > 100
        small_payload = request_size < 500
        large_payload = request_size > 10000
        spike_in_requests = recent_requests > 100
        repeated_access = request_count > 10
        unusual_user_agent = "bot" in user_agent.lower()
        invalid_headers = False  # You can implement actual logic here

        c.execute("""
            INSERT INTO traffic_logs 
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


@app.route("/traffic-data", methods=["GET"])
def get_traffic_data():
    try:
        with conn.cursor() as c:
            c.execute("""
                SELECT id, ip, timestamp, request_size, status, location, user_agent, 
                       request_type, high_request_rate, small_payload, large_payload, 
                       spike_in_requests, repeated_access, unusual_user_agent, 
                       invalid_headers, destination_port, country, city 
                FROM traffic_logs
            """)
            rows = c.fetchall()

            columns = [
                "id", "ip", "time", "size", "status", "location", "user_agent",
                "request_type", "high_request_rate", "small_payload", "large_payload",
                "spike_in_requests", "repeated_access", "unusual_user_agent",
                "invalid_headers", "destination_port", "country", "city"
            ]

            data = [dict(zip(columns, row)) for row in rows]

        return jsonify({"traffic_logs": data})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/traffic-graph", methods=["GET"])
def traffic_graph():
    try:
        with conn.cursor() as c:
            c.execute("SELECT timestamp FROM traffic_logs ORDER BY timestamp ASC")
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

        # Default placeholders
        location = data.get("location", "unknown")
        country = data.get("country", "unknown")
        city = data.get("city", "unknown")

        # Flags – default to False for now
        high_request_rate = False
        small_payload = request_size < 100
        large_payload = request_size > 1000
        spike_in_requests = False
        repeated_access = False
        unusual_user_agent = "bot" in user_agent.lower()
        invalid_headers = False  # Could be improved with header analysis

        # Insert data
        with conn.cursor() as c:
            c.execute("""
                INSERT INTO traffic_logs (
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
                ip, timestamp, request_size, "normal", location, user_agent, request_type,
                high_request_rate, small_payload, large_payload, spike_in_requests,
                repeated_access, unusual_user_agent, invalid_headers, destination_port,
                country, city
            ))
            conn.commit()

        return jsonify({"message": "Traffic data logged successfully"}), 200

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
            FROM traffic_logs
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


@app.route('/traffic-summary', methods=['GET'])
def traffic_summary():
    try:
        conn = psycopg2.connect(DATABASE_URL, sslmode='require')
        cursor = conn.cursor()

        cursor.execute("SELECT status, COUNT(*) FROM traffic_logs GROUP BY status;")
        rows = cursor.fetchall()

        summary = {"legit": 0, "malicious": 0}
        for status, count in rows:
            if str(status).lower() in ["0", "legit", "good"]:
                summary["legit"] += count
            elif str(status).lower() in ["1", "malicious", "bad", "suspicious"]:
                summary["malicious"] += count

        cursor.close()
        conn.close()
        return jsonify(summary)

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/debug-status", methods=["GET"])
def debug_status():
    try:
        conn = psycopg2.connect(DATABASE_URL, sslmode='require')
        cursor = conn.cursor()

        cursor.execute("SELECT status, COUNT(*) FROM traffic_logs GROUP BY status;")
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
        cur.execute("SELECT timestamp, status FROM traffic_logs ORDER BY timestamp DESC LIMIT 100;")
        rows = cur.fetchall()
        result = [{"timestamp": r[0], "status": r[1]} for r in rows]
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)})
with open("dnn_model.pkl", "rb") as f:
    dnn_model = joblib.load(f)  # Ensure to load using joblib since it’s a sklearn model

# Add your 18 DNN feature list here
DNN_FEATURES = ['feature1', 'feature2', 'feature3', ..., 'feature18']  # Replace with your actual feature names

# Configs for PostgreSQL and Email
engine = create_engine("postgresql://traffic_db_6kci_user:bTXPfiMeieoQ8EqNZYv1480Vwl7lJJaz@dpg-cvajkgin91rc7395vv1g-a.oregon-postgres.render.com/traffic_db_6kci")

EMAIL_FROM = "iambalamurugna005@gmail.com"
EMAIL_TO = "iambalamurugan05@gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "iambalamurugna005@gmail.com"
SMTP_PASSWORD = "tsdryornazoifbcl"

# Function to send email alert
def send_email_alert(alert_rows):
    subject = "⚠️ DDoS Alert Triggered!"
    body = "🚨 The following suspicious/malicious traffic has been detected:\n\n"
    for row in alert_rows:
        body += f"IP: {row['ip']} | Port: {row['destination_port']} | Size: {row['request_size']} | Status: {row['status']}\n"

    body += "\nPlease investigate immediately.\n— Team 7 DDoS Monitor"
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_FROM
    msg['To'] = EMAIL_TO

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
            print("[✅] Email alert sent.")
    except Exception as e:
        print("[❌] Failed to send email:", e)

# Handle missing or "unknown" values
def handle_missing_values(row):
    for feature in DNN_FEATURES:
        if pd.isna(row[feature]):  # Check for NaN or missing data
            row[feature] = 0  # Or use a default value (e.g., 0 or the mean)
    return row

# Analyze traffic with DNN and rule-based checks
def analyze_traffic_with_rules_and_dnn(df):
    suspicious_rows = []
    
    for _, row in df.iterrows():
        # Handle missing data in the row
        row = handle_missing_values(row)

        rule_violated = (
            row.get("high_request_rate", 0) == 1 or
            row.get("large_payload", 0) == 1 or
            row.get("spike_in_requests", 0) == 1 or
            row.get("repeated_access", 0) == 1 or
            row.get("unusual_user_agent", 0) == 1 or
            row.get("invalid_headers", 0) == 1
        )

        # Predict with DNN model
        try:
            dnn_input = row[DNN_FEATURES].values.reshape(1, -1)  # Reshape to match model input format
            prediction = dnn_model.predict(dnn_input)[0]  # Get single prediction value
        except Exception as e:
            print("[❌] DNN Prediction failed:", e)
            prediction = 0

        if rule_violated or prediction == 1:
            suspicious_rows.append(row)

    return suspicious_rows

# Monitor DDoS and send alerts
def monitor_ddos_and_alert():
    while True:
        time.sleep(15)  # Run the check every 15 seconds
        with engine.connect() as conn:
            result = conn.execute(text("SELECT * FROM traffic_data")).mappings().all()
            if not result:
                print("[ℹ️] No traffic data yet.")
                continue

            df = pd.DataFrame(result)
            suspicious = analyze_traffic_with_rules_and_dnn(df)

            if suspicious:
                print(f"[⚠️] Found {len(suspicious)} suspicious entries.")
                send_email_alert(suspicious)
            else:
                print("[✅] No suspicious or malicious traffic detected.")

# Start alert monitoring in a separate thread
@app.before_first_request
def start_alert_monitor():
    thread = Thread(target=monitor_ddos_and_alert)
    thread.daemon = True
    thread.start()

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)
