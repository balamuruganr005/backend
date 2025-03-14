from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time
import matplotlib.pyplot as plt
import io
import sqlite3
import numpy as np

app = Flask(__name__)
CORS(app)

# Initialize rate limiter (prevents DDoS)
limiter = Limiter(get_remote_address, app=app, default_limits=["500 per minute"])

# Initialize SQLite Database
conn = sqlite3.connect("traffic_data.db", check_same_thread=False)
c = conn.cursor()

# Create table with status column
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

# Define Malicious & Blocked IPs
MALICIOUS_IPS = {"45.140.143.77", "185.220.100.255"}
BLOCKED_IPS = {"81.23.152.244", "222.252.194.204"}
IP_ANOMALY_COUNT = {}  # Track anomaly counts per IP

# Threshold to block an IP automatically
ANOMALY_THRESHOLD = 3  

def get_client_ips():
    """
    Extracts all IPs from X-Forwarded-For header.
    If no header, fallback to remote_addr.
    """
    forwarded = request.headers.get("X-Forwarded-For", None)
    if forwarded:
        return [ip.strip() for ip in forwarded.split(",")]
    return [request.remote_addr]

@app.route("/", methods=["GET", "POST"])
def home():
    """Logs each request and updates the IP status in SQLite."""
    timestamp = time.time()
    ips = get_client_ips()
    request_size = len(str(request.data))  

    for ip in ips:
        status = "normal"
        if ip in BLOCKED_IPS:
            status = "blocked"
        elif ip in MALICIOUS_IPS:
            status = "malicious"

        c.execute("INSERT INTO traffic_logs (ip, timestamp, request_size, status) VALUES (?, ?, ?, ?)", 
                  (ip, timestamp, request_size, status))
        conn.commit()

    return jsonify({"message": "Request logged", "ips": ips, "size": request_size})

@app.route("/traffic-data", methods=["GET"])
def get_traffic_data():
    """Retrieve all logged traffic data from SQLite."""
    c.execute("SELECT id, ip, timestamp, request_size, status FROM traffic_logs")
    data = [{"id": row[0], "ip": row[1], "time": row[2], "size": row[3], "status": row[4]} for row in c.fetchall()]
    return jsonify({"traffic_logs": data})

@app.route("/traffic-graph", methods=["GET"])
def traffic_graph():
    """Generates and returns a graph of traffic over time from SQLite."""
    c.execute("SELECT timestamp FROM traffic_logs")
    data = c.fetchall()

    if not data:
        return jsonify({"error": "No data available"})

    times = [row[0] for row in data]
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
    """Detects unusual spikes in request rate and updates status accordingly."""
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

        if anomalies:
            anomalies_by_ip[ip] = anomalies

            # Mark IP as Malicious
            c.execute("UPDATE traffic_logs SET status = 'malicious' WHERE ip = ?", (ip,))
            conn.commit()

            # Track anomaly counts per IP
            IP_ANOMALY_COUNT[ip] = IP_ANOMALY_COUNT.get(ip, 0) + 1

            # Block IP if anomaly count exceeds threshold
            if IP_ANOMALY_COUNT[ip] >= ANOMALY_THRESHOLD:
                c.execute("UPDATE traffic_logs SET status = 'blocked' WHERE ip = ?", (ip,))
                BLOCKED_IPS.add(ip)  # Add IP to blocked list
                conn.commit()

    return jsonify({
        "anomalies_by_ip": anomalies_by_ip,
        "total_ips_with_anomalies": len(anomalies_by_ip)
    })

@app.route("/unblock-ip", methods=["POST"])
def unblock_ip():
    """Manually unblocks an IP if it was wrongly flagged."""
    data = request.json
    ip = data.get("ip")

    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    if ip in BLOCKED_IPS:
        BLOCKED_IPS.remove(ip)  # Remove from blocked list
        c.execute("UPDATE traffic_logs SET status = 'normal' WHERE ip = ?", (ip,))
        conn.commit()
        return jsonify({"message": f"IP {ip} has been unblocked"})
    
    return jsonify({"message": "IP is not blocked"}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
