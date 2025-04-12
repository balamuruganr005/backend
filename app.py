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


# Configs
DATABASE_URL = "postgresql://traffic_db_6kci_user:bTXPfiMeieoQ8EqNZYv1480Vwl7lJJaz@dpg-cvajkgin91rc7395vv1g-a.oregon-postgres.render.com/traffic_db_6kci"
FROM_EMAIL = "iambalamurugan005@gmail.com"
TO_EMAIL = "iambalamurugan05@gmail.com"
EMAIL_PASS = "tsdryornazoifbcl"
MODEL_PATH = os.path.join(os.path.dirname(__file__), "dnn_model.pkl")

# Initialize Flask App
app = Flask(__name__)

# Updated CORS configuration
CORS(app, origins=["http://localhost:5173", "https://ddosweb.vercel.app"])

# DB setup
def get_db_connection():
    return psycopg2.connect(DATABASE_URL, sslmode='require')

# Load DNN model
def load_dnn_model():
    return joblib.load(MODEL_PATH)

dnn_model = load_dnn_model()

# Fetch recent traffic logs from DB for retraining
def fetch_recent_traffic():
    conn = get_db_connection()
    query = """
    SELECT * FROM traffic_logs
    WHERE status IS NOT NULL
    ORDER BY timestamp DESC
    LIMIT 1000;
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

# Retrain DNN and save model
def retrain_dnn_model():
    df = fetch_recent_traffic()
    X, y = preprocess(df)
    model = MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=500)
    model.fit(X, y)
    joblib.dump(model, MODEL_PATH)
    return "DNN model retrained with new traffic patterns."

# Preprocess traffic data
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

# Utility Functions
def save_alert_to_db(ip, message, dnn_prediction):
    conn = get_db_connection()
    cur = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    image = "ddos_pattern.jpg"  # Optional image placeholder, can be added if needed
    cur.execute(
        "INSERT INTO alerts (ip, timestamp, message, dnn_prediction, image) VALUES (%s, %s, %s, %s, %s)",
        (ip, timestamp, message, dnn_prediction, image)
    )
    conn.commit()
    cur.close()
    conn.close()

def send_alert_email(ip, pred, data):
    body = f"""⚠️ DDoS Alert!\nIP: {ip}\nPrediction: {pred}\nRequest: {data}"""
    msg = MIMEMultipart()
    msg['From'], msg['To'], msg['Subject'] = FROM_EMAIL, TO_EMAIL, "🚨 DDoS Alert"
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(FROM_EMAIL, EMAIL_PASS)
        server.sendmail(FROM_EMAIL, TO_EMAIL, msg.as_string())
        server.quit()
        print("✅ Email sent.")
    except Exception as e:
        print("❌ Email failed:", e)

def prioritize_legit_users():
    conn = get_db_connection()
    with conn.cursor() as c:
        c.execute("SELECT ip FROM traffic_logs WHERE status = 0")
        ips = c.fetchall()
    with open("whitelist.txt", "w") as f:
        for ip in ips:
            f.write(f"{ip[0]}\n")

# Routes
@app.route('/dnn-status', methods=['GET'])
def dnn_status():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT timestamp, status FROM traffic_logs ORDER BY timestamp DESC LIMIT 100;")
        rows = cur.fetchall()
        result = [{"timestamp": r[0], "status": r[1]} for r in rows]
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/detect-dnn", methods=["POST"])
def detect_dnn():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        now = time.time()
        cur.execute("SELECT * FROM traffic_logs WHERE trust_score = 1 AND timestamp > %s", (now - 20,))
        attackers = cur.fetchall()

        if attackers:
            subject = "🚨 DDoS Attack Detected!"
            body = f"{len(attackers)} malicious or suspicious users detected.\n\nDetails:\n"
            for attacker in attackers:
                body += f"IP: {attacker[2]}, Location: {attacker[3]}, UA: {attacker[4]}\n"

            # Send email
            send_alert_email(subject, body)

            # Save alert in alerts table
            for attacker in attackers:
                ip = attacker[2]
                message = "Suspicious activity detected from IP."
                dnn_prediction = attacker[6]  # Assuming trust_score is used
                save_alert_to_db(ip, message, dnn_prediction)

        return jsonify({"status": "checked", "attackers_found": len(attackers)})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/alert-history", methods=["GET"])
def get_alert_history():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT ip, timestamp, message, dnn_prediction FROM alerts ORDER BY timestamp DESC LIMIT 50;")
    rows = cur.fetchall()
    conn.close()
    return jsonify([{
        "ip": row[0], "timestamp": row[1].strftime("%Y-%m-%d %H:%M:%S"),
        "message": row[2], "dnn_prediction": row[3]
    } for row in rows])

@app.route('/test-email', methods=["GET"])
def test_email():
    try:
        # Test data (you can modify this to your specific case)
        test_data = {
            "ip": "123.123.123.123", 
            "request_size": 500, 
            "destination_port": 80,
            "high_request_rate": 1, 
            "large_payload": 1, 
            "spike_in_requests": 1,
            "repeated_access": 1, 
            "unusual_user_agent": 1, 
            "invalid_headers": 1,
            "small_payload": 0
        }

        # Send the test email
        send_alert_email(test_data['ip'], 1, test_data)

        # Save the alert to the database so it shows in /alert-history
        message = "Test DDoS alert sent via /test-email endpoint"
        dnn_prediction = 1  # Let's assume 1 indicates bad traffic (DDoS)
        save_alert_to_db(test_data['ip'], message, dnn_prediction)

        return jsonify({"message": "✅ Test email sent and saved to alert history!"})

    except Exception as e:
        return jsonify({"error": str(e)})


# --- Background DDoS Monitor ---
def monitor_ddos():
    while True:
        try:
            conn = get_db_connection()
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM traffic WHERE status = 1 ORDER BY timestamp DESC LIMIT 1;")
                row = cur.fetchone()
                if row:
                    print("🚨 Malicious traffic found")
                    req_data = {
                        "ip": row[1], "request_size": row[2], "destination_port": row[3],
                        "high_request_rate": row[4], "large_payload": row[5], "spike_in_requests": row[6],
                        "repeated_access": row[7], "unusual_user_agent": row[8],
                        "invalid_headers": row[9], "small_payload": row[10]
                    }
                    send_alert_email(req_data["ip"], 1, req_data)
            conn.close()
        except Exception as e:
            print(f"❌ Monitor error: {e}")
        time.sleep(15)

if __name__ == "__main__":
    threading.Thread(target=monitor_ddos, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=True)
