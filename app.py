from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time
import matplotlib.pyplot as plt
import io
import sqlite3
import numpy as np
import requests  # For proxy detection

app = Flask(__name__)
CORS(app)

# Initialize rate limiter (prevents DDoS)
limiter = Limiter(get_remote_address, app=app, default_limits=["500 per minute"])

# Function to get SQLite connection
def get_db_connection():
    conn = sqlite3.connect("traffic_data.db", check_same_thread=False)
    return conn, conn.cursor()

# Create table if not exists
conn, c = get_db_connection()
c.execute("""
    CREATE TABLE IF NOT EXISTS traffic_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        timestamp REAL,
        request_size INTEGER,
        status TEXT DEFAULT 'normal'
    )
""")
conn.commit()
conn.close()

# Define thresholds and tracking
MALICIOUS_IPS = set()
BLOCKED_IPS = set()
IP_ANOMALY_COUNT = {}  
REPEATING_IP_THRESHOLD = 5  
ANOMALY_THRESHOLD = 3  

# Function to insert traffic logs
def insert_traffic_log(ip, request_size, status):
    conn, cursor = get_db_connection()
    cursor.execute(
        "INSERT INTO traffic_logs (ip, timestamp, request_size, status) VALUES (?, ?, ?, ?)",
        (ip, time.time(), request_size, status),
    )
    conn.commit()
    conn.close()

# Endpoint to receive traffic logs
@app.route("/log_traffic", methods=["POST"])
def log_traffic():
    data = request.get_json()

    if not data:
        return jsonify({"error": "No data received"}), 400

    try:
        insert_traffic_log(data["ip"], data.get("request_size", 0), data.get("status", "normal"))
        return jsonify({"status": "success"}), 200
    except Exception as e:
        print("Database Error:", e)
        return jsonify({"error": str(e)}), 500

@app.route("/", methods=["GET", "POST"])
def home():
    timestamp = time.time()
    ip = request.remote_addr
    request_size = len(str(request.data))
    insert_traffic_log(ip, request_size, "normal")
    return jsonify({"message": "Request logged", "ip": ip, "size": request_size})

@app.route("/traffic-data", methods=["GET"])
def get_traffic_data():
    conn, c = get_db_connection()
    c.execute("SELECT id, ip, timestamp, request_size, status FROM traffic_logs")
    data = [{"id": row[0], "ip": row[1], "time": row[2], "size": row[3], "status": row[4]} for row in c.fetchall()]
    conn.close()
    return jsonify({"traffic_logs": data})

@app.route("/traffic-graph", methods=["GET"])
def traffic_graph():
    conn, c = get_db_connection()
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
    """Detects unusual spikes, repeated IPs, and proxy IPs."""
    conn, c = get_db_connection()
    c.execute("SELECT ip, timestamp FROM traffic_logs")
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
    proxy_ips = set()

    for ip, timestamps in ip_data.items():
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

        # 🚨 Detect repeating IPs
        if len(timestamps) > REPEATING_IP_THRESHOLD:
            repeating_ips.add(ip)

        # 🚨 Detect proxy IPs
        if is_proxy_ip(ip):
            proxy_ips.add(ip)

        if anomalies:
            anomalies_by_ip[ip] = anomalies
            conn, c = get_db_connection()
            c.execute("UPDATE traffic_logs SET status = 'malicious' WHERE ip = ?", (ip,))
            conn.commit()
            conn.close()
            IP_ANOMALY_COUNT[ip] = IP_ANOMALY_COUNT.get(ip, 0) + 1

            # 🚨 Block IP if anomaly count exceeds threshold
            if IP_ANOMALY_COUNT[ip] >= ANOMALY_THRESHOLD:
                conn, c = get_db_connection()
                c.execute("UPDATE traffic_logs SET status = 'blocked' WHERE ip = ?", (ip,))
                conn.commit()
                conn.close()
                BLOCKED_IPS.add(ip)

    return jsonify({
        "anomalies_by_ip": anomalies_by_ip,
        "repeating_ips": list(repeating_ips),
        "proxy_ips": list(proxy_ips),
        "total_ips_with_anomalies": len(anomalies_by_ip),
        "total_repeating_ips": len(repeating_ips),
        "total_proxy_ips": len(proxy_ips)
    })

@app.route("/unblock-ip", methods=["POST"])
def unblock_ip():
    """Manually unblocks an IP if it was wrongly flagged."""
    data = request.json
    ip = data.get("ip")

    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    if ip in BLOCKED_IPS:
        BLOCKED_IPS.remove(ip)
        conn, c = get_db_connection()
        c.execute("UPDATE traffic_logs SET status = 'normal' WHERE ip = ?", (ip,))
        conn.commit()
        conn.close()
        return jsonify({"message": f"IP {ip} has been unblocked"})
    
    return jsonify({"message": "IP is not blocked"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
