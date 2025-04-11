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
    """Detects unusual spikes in request rate and groups anomalies by IP"""
    c.execute("SELECT ip, timestamp FROM traffic_logs")
    records = c.fetchall()

    if len(records) < 5:  # Not enough data for anomaly detection
        return jsonify({"message": "Not enough data for anomaly detection"})

    ip_data = {}  # Group requests by IP
    for ip, timestamp in records:
        if ip not in ip_data:
            ip_data[ip] = []
        ip_data[ip].append(timestamp)

    anomalies_by_ip = {}
    for ip, timestamps in ip_data.items():
        if len(timestamps) >= 3:  # Rule: IP repeated 3 or more times is suspicious
            anomalies_by_ip[ip] = "Repeated IP detected"

    # Add all malicious IPs to anomalies
    for ip in MALICIOUS_IPS:
        anomalies_by_ip[ip] = "Malicious IP detected"

    return jsonify({
        "anomalies_by_ip": anomalies_by_ip,
        "total_ips_with_anomalies": len(anomalies_by_ip)
    })

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
        conn = connect_db()
        cur = conn.cursor()
        cur.execute("SELECT timestamp, status FROM traffic_logs ORDER BY timestamp DESC LIMIT 100;")
        rows = cur.fetchall()
        result = [{"timestamp": r[0], "status": r[1]} for r in rows]
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)})


import os
import joblib

model_path = os.path.join(os.path.dirname(__file__), "dnn_model.pkl")

try:
    dnn_model = joblib.load(model_path)
    print("[Model Load] DNN model loaded successfully ✅")
except Exception as e:
    print(f"[Model Load Error] Could not load DNN model: {e}")
    dnn_model = None
    
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

# Load DNN model
def load_dnn_model():
    return joblib.load("dnn_model.pkl")

dnn_model = load_dnn_model()

# Fetch recent traffic logs from DB for retraining
def fetch_recent_traffic():
    conn = psycopg2.connect(DATABASE_URL)
    query = """
    SELECT * FROM traffic_logs
    WHERE status IS NOT NULL
    ORDER BY timestamp DESC
    LIMIT 1000;
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

# Preprocess features
def preprocess(df):
    X = df[[
        'request_size', 'status', 'destination_port',
        'high_request_rate', 'large_payload', 'spike_in_requests',
        'repeated_access', 'unusual_user_agent', 'invalid_headers', 'small_payload'
    ]]
    y = df['status']  # status should be 0 (legit) or 1 (bad)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    return X_scaled, y

# Retrain DNN and save model
def retrain_dnn_model():
    df = fetch_recent_traffic()
    X, y = preprocess(df)
    model = MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=500)
    model.fit(X, y)
    joblib.dump(model, "dnn_model.pkl")
    return "DNN model retrained with new traffic patterns."

# Rule-based detection
def violates_rules(log):
    return any([
        log.get('high_request_rate', False),
        log.get('large_payload', False),
        log.get('spike_in_requests', False),
        log.get('invalid_headers', False),
        log.get('unusual_user_agent', False),
        log.get('repeated_access', False),
    ])

# Whitelist legit users
def prioritize_legit_users():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("SELECT ip FROM traffic_logs WHERE status = 0")
    legit_ips = cur.fetchall()
    conn.close()

    with open("whitelist.txt", "w") as f:
        for ip in legit_ips:
            f.write(f"{ip[0]}\n")  # Store or sync to firewall allowlist

app = Flask(__name__)
CORS(app)

# Load DNN model
dnn_model = joblib.load("dnn_model.pkl")

# PostgreSQL connection
conn = psycopg2.connect("postgresql://traffic_db_6kci_user:bTXPfiMeieoQ8EqNZYv1480Vwl7lJJaz@dpg-cvajkgin91rc7395vv1g-a.oregon-postgres.render.com/traffic_db_6kci")
cursor = conn.cursor()

# Create alerts table if not exists
cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id SERIAL PRIMARY KEY,
        ip VARCHAR,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        message TEXT,
        dnn_prediction INT
    );
""")
conn.commit()

ip_requests = defaultdict(list)
blocklist = set()

def preprocess_request_data(request_data):
    features = [
        request_data.get("request_size", 0),
        request_data.get("destination_port", 0),
        request_data.get("high_request_rate", 0),
        request_data.get("large_payload", 0),
        request_data.get("spike_in_requests", 0),
        request_data.get("repeated_access", 0),
        request_data.get("unusual_user_agent", 0),
        request_data.get("invalid_headers", 0),
        request_data.get("small_payload", 0)
    ]
    return [features]

def send_alert_email(ip, dnn_prediction, request_data):
    from_email = "iambalamurugan005@gmail.com"
    to_email = "iambalamurugan05@gmail.com"
    subject = "🚨 DDoS Alert from DNN Detection"
    
    body = f"""
    ⚠️ Potential DDoS attack detected!
    IP Address: {ip}
    DNN Prediction: {dnn_prediction}
    Request Data: {request_data}
    """
    
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_email, 'tsdryornazoifbcl')  # App Password
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        print("✅ Email alert sent.")
    except Exception as e:
        print("❌ Failed to send email:", e)

@app.route("/detect-dnn", methods=["POST"])
def detect_dnn():
    data = request.get_json()
    ip = data.get("ip", "unknown")
    features = preprocess_request_data(data)
    
    prediction = dnn_model.predict(features)[0]

    if prediction == 1:
        # Block IP
        blocklist.add(ip)

        # Store alert in DB
        alert_msg = f"DNN detected attack from IP: {ip}"
        cursor.execute("""
            INSERT INTO alerts (ip, message, dnn_prediction)
            VALUES (%s, %s, %s)
        """, (ip, alert_msg, prediction))
        conn.commit()

        # Send email
        send_alert_email(ip, prediction, data)

        return jsonify({"status": "blocked", "prediction": int(prediction), "message": alert_msg})
    else:
        return jsonify({"status": "allowed", "prediction": int(prediction)})

@app.route("/alert-history", methods=["GET"])
def get_alert_history():
    cursor.execute("SELECT ip, timestamp, message, dnn_prediction FROM alerts ORDER BY timestamp DESC LIMIT 50;")
    rows = cursor.fetchall()

    history = []
    for row in rows:
        history.append({
            "ip": row[0],
            "timestamp": row[1].strftime("%Y-%m-%d %H:%M:%S"),
            "message": row[2],
            "dnn_prediction": row[3]
        })
    return jsonify(history)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
