from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime
import matplotlib.pyplot as plt
import io
import psycopg2
import numpy as np
import requests  # For proxy detection
import os

app = Flask(__name__)
CORS(app)


# Initialize rate limiter (prevents DDoS)
limiter = Limiter(get_remote_address, app=app, default_limits=["500 per minute"])

# Load PostgreSQL Database URL
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not set")

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

# Create table if not exists
try:
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id SERIAL PRIMARY KEY,
            ip TEXT,
            timestamp REAL,
            request_size INTEGER,
            status TEXT DEFAULT 'normal'
        )
    """)
    conn.commit()
    c.close()
    conn.close()
except Exception as e:
    print(f"Error connecting to database: {e}")

# Define thresholds and tracking
MALICIOUS_IPS = set()
BLOCKED_IPS = set()
IP_ANOMALY_COUNT = {}
REPEATING_IP_THRESHOLD = 5
ANOMALY_THRESHOLD = 3

import requests

def get_geolocation(ip):
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/")
        data = response.json()
        country = data.get("country_name")
        city = data.get("city")
        latitude = data.get("latitude")
        longitude = data.get("longitude")
        
        print(f"Geo Data for {ip}: Country={country}, City={city}, Lat={latitude}, Lon={longitude}")
        return country, city, latitude, longitude
    except Exception as e:
        print(f"Error fetching geolocation: {e}")
        return None, None, None, None

def update_and_check_schema():
    """Ensure all required columns exist in traffic_logs (only runs once)."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # List existing columns
        cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'traffic_logs';")
        existing_columns = {row[0] for row in cur.fetchall()}

        # Define required columns and their types
        required_columns = {
            "request_type": "TEXT",
            "destination_port": "INTEGER",
            "country": "TEXT",
            "city": "TEXT",
            "user_agent": "TEXT"
        }

        # Add missing columns if they don't exist
        for column, datatype in required_columns.items():
            if column not in existing_columns:
                cur.execute(f"ALTER TABLE traffic_logs ADD COLUMN {column} {datatype};")
                print(f"✅ Added missing column: {column}")

        conn.commit()
        cur.close()
        conn.close()
        print("✅ Schema update and check completed successfully!")

    except Exception as e:
        print(f"❌ Error updating schema: {e}")

# Run only once
if __name__ == "__main__":
    update_and_check_schema()


def log_traffic(ip, request_size, request_type, destination_port, user_agent):
    global IP_ANOMALY_COUNT, MALICIOUS_IPS

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    status = "normal"

    # Detect malicious traffic
    IP_ANOMALY_COUNT[ip] = IP_ANOMALY_COUNT.get(ip, 0) + 1
    if IP_ANOMALY_COUNT[ip] > REPEATING_IP_THRESHOLD:
        status = "malicious"
        MALICIOUS_IPS.add(ip)

    # Fetch geolocation
    country, city, latitude, longitude = get_geolocation(ip)

    print(f"Logging: IP={ip}, RequestType={request_type}, Country={country}, UserAgent={user_agent}")

    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            INSERT INTO traffic_logs (ip, timestamp, request_size, request_type, destination_port, user_agent, status, country, city)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (ip, timestamp, request_size, request_type, destination_port, user_agent, status, country, city))
        
        conn.commit()
        c.close()
        conn.close()
    except Exception as e:
        print(f"Error logging traffic: {e}")

def track_request():
    """
    API endpoint to receive traffic data and log it into the database.
    Expects JSON payload with 'ip' and 'request_size'.
    """
    data = request.json
    ip = data.get("ip", request.remote_addr)  # Get client IP if not provided
    request_size = data.get("request_size", 0)

    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    log_traffic(ip, request_size)
    return jsonify({"message": "Traffic logged successfully", "ip": ip, "status": "logged"}), 200


@app.route('/test_db', methods=['GET'])
def test_db():
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT NOW();")  # Simple test query
        result = c.fetchone()
        c.close()
        conn.close()
        return jsonify({"status": "success", "db_time": result[0]})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

# Function to insert traffic logs
insert_traffic_log(ip, request_size, "normal", "legitimate")  # Add a status
    country, city, latitude, longitude = get_geolocation(ip)
    
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO traffic_logs (ip, timestamp, request_size, status, country, city, latitude, longitude)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """, (ip, timestamp, request_size, status, country, city, latitude, longitude))

    conn.commit()
    cur.close()
    conn.close()

@app.route("/", methods=["GET", "POST"])
def home():
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ip = request.remote_addr
    request_size = len(str(request.data))
    insert_traffic_log(ip, request_size, "normal")
    return jsonify({"message": "Request logged", "ip": ip, "size": request_size})

@app.route("/traffic-data", methods=["GET"])
def get_traffic_data():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, ip, timestamp, request_size, status FROM traffic_logs")
    data = [{"id": row[0], "ip": row[1], "time": row[2], "size": row[3], "status": row[4]} for row in c.fetchall()]
    conn.close()
    return jsonify({"traffic_logs": data})

@app.route("/traffic-graph", methods=["GET"])
def traffic_graph():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT timestamp FROM traffic_logs")
    data = c.fetchall()
    conn.close()

    if not data:
        return jsonify({"error": "No data available"})

    times = [row[0] for row in data if row[0] is not None]
    if not times:
        return jsonify({"error": "Invalid timestamps in database"})

    timestamps = [time.strftime("%H:%M:%S", time.localtime(t)) for t in times]
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

@app.route("/detect-anomaly", methods=["GET"])
def detect_anomaly():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT ip, timestamp FROM traffic_logs WHERE timestamp IS NOT NULL")
    records = c.fetchall()
    conn.close()

    if len(records) < 5:
        return jsonify({"message": "Not enough data for anomaly detection"})

    ip_data = {}
    for ip, timestamp in records:
        if ip not in ip_data:
            ip_data[ip] = []
        ip_data[ip].append(timestamp)

    anomalies_by_ip = {}
    repeating_ips = set()

    for ip, timestamps in ip_data.items():
        timestamps.sort()
        if len(timestamps) < 2:
            continue

        intervals = np.diff(timestamps)
        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        threshold = max(mean_interval - (1.5 * std_interval), 0.1)  

        anomalies = [timestamps[i] for i in range(1, len(timestamps)) if intervals[i - 1] < threshold]

        if len(timestamps) > REPEATING_IP_THRESHOLD:
            repeating_ips.add(ip)

        if anomalies:
            anomalies_by_ip[ip] = anomalies
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("UPDATE traffic_logs SET status = 'malicious' WHERE ip = %s", (ip,))
            conn.commit()
            conn.close()
            IP_ANOMALY_COUNT[ip] = IP_ANOMALY_COUNT.get(ip, 0) + 1

    return jsonify({
        "anomalies_by_ip": anomalies_by_ip,
        "repeating_ips": list(repeating_ips),
        "total_ips_with_anomalies": len(anomalies_by_ip),
        "total_repeating_ips": len(repeating_ips)
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
