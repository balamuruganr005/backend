from flask import Flask, request, jsonify, send_file, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time
import matplotlib.pyplot as plt
import io
import sqlite3
import numpy as np
import requests  # For proxy detection
import logging

app = Flask(__name__)
CORS(app)

# Initialize rate limiter (prevents DDoS)
limiter = Limiter(get_remote_address, app=app, default_limits=["500 per minute"])

# Setup logging
logging.basicConfig(level=logging.INFO)

# Function to get SQLite connection (thread-safe)
def get_db_connection():
    if 'db' not in g:
        g.db = sqlite3.connect("traffic_data.db")
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db_connection(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Initialize Database
conn = get_db_connection()
c = conn.cursor()
c.execute("""
    CREATE TABLE IF NOT EXISTS traffic_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        timestamp REAL,
        request_size INTEGER,
        status TEXT DEFAULT 'normal'
    )
""")
c.execute("CREATE INDEX IF NOT EXISTS idx_ip ON traffic_logs (ip)")
conn.commit()
conn.close()

# Define thresholds and tracking
MALICIOUS_IPS = set()
BLOCKED_IPS = set()
IP_WHITELIST = {"127.0.0.1"}  # Add trusted IPs here
IP_ANOMALY_COUNT = {}  
REPEATING_IP_THRESHOLD = 5  
ANOMALY_THRESHOLD = 3  

# Function to insert traffic logs
def insert_traffic_log(ip, request_size, status):
    if ip in IP_WHITELIST:
        status = "whitelisted"
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO traffic_logs (ip, timestamp, request_size, status) VALUES (?, ?, ?, ?)",
        (ip, time.time(), request_size, status),
    )
    conn.commit()

# Function to get all traffic logs
@app.route("/traffic-data", methods=["GET"])
def get_traffic_data():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, ip, timestamp, request_size, status FROM traffic_logs")
    data = [{"id": row[0], "ip": row[1], "time": row[2], "size": row[3], "status": row[4]} for row in c.fetchall()]
    return jsonify({"traffic_logs": data})

# Endpoint to receive traffic logs
@app.route("/log_traffic", methods=["POST"])
def log_traffic():
    data = request.get_json()
    logging.info(f"Received Data: {data}")
    
    if not data or "ip" not in data or "timestamp" not in data or "request_size" not in data or "status" not in data:
        return jsonify({"error": "Invalid data format"}), 400

    try:
        insert_traffic_log(data["ip"], data["request_size"], data["status"])
        return jsonify({"status": "success"}), 200
    except Exception as e:
        logging.error(f"Database Error: {e}")
        return jsonify({"error": str(e)}), 500

# Function to detect anomalies
@app.route("/detect-anomaly", methods=["GET"])
def detect_anomaly():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT ip, timestamp FROM traffic_logs")
    records = c.fetchall()

    if len(records) < 5:
        return jsonify({"message": "Not enough data for anomaly detection"})

    ip_data = {}
    for ip, timestamp in records:
        if ip not in ip_data:
            ip_data[ip] = []
        ip_data[ip].append(timestamp)

    anomalies_by_ip = {}
    repeating_ips = set()
    proxy_ips = set()

    for ip, timestamps in ip_data.items():
        if ip in IP_WHITELIST:
            continue
        
        timestamps.sort()
        intervals = np.diff(timestamps)

        if len(intervals) < 1:
            continue

        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)

        if std_interval == 0:
            continue  

        threshold = mean_interval - (1.5 * std_interval)
        anomalies = [timestamps[i] for i in range(1, len(timestamps)) if intervals[i - 1] < threshold]

        if len(timestamps) > REPEATING_IP_THRESHOLD:
            repeating_ips.add(ip)

        if anomalies:
            anomalies_by_ip[ip] = anomalies
            insert_traffic_log(ip, 0, 'malicious')
            IP_ANOMALY_COUNT[ip] = IP_ANOMALY_COUNT.get(ip, 0) + 1

            if IP_ANOMALY_COUNT[ip] >= ANOMALY_THRESHOLD:
                insert_traffic_log(ip, 0, 'blocked')
                BLOCKED_IPS.add(ip)

    return jsonify({
        "anomalies_by_ip": anomalies_by_ip,
        "repeating_ips": list(repeating_ips),
        "proxy_ips": list(proxy_ips),
        "total_ips_with_anomalies": len(anomalies_by_ip),
        "total_repeating_ips": len(repeating_ips),
        "total_proxy_ips": len(proxy_ips)
    })

# Function to generate traffic graph
@app.route("/traffic_graph", methods=["GET"])
def traffic_graph():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT timestamp FROM traffic_logs")
    timestamps = [row[0] for row in c.fetchall()]
    
    if not timestamps:
        return jsonify({"error": "No traffic data available"})
    
    plt.figure()
    plt.hist(timestamps, bins=20, color='blue', alpha=0.7)
    plt.xlabel("Timestamp")
    plt.ylabel("Request Count")
    plt.title("Traffic Histogram")
    
    img_io = io.BytesIO()
    plt.savefig(img_io, format='png')
    img_io.seek(0)
    
    return send_file(img_io, mimetype='image/png')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
