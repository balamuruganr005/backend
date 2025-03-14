from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time
import matplotlib.pyplot as plt
import io
import base64
import sqlite3
import numpy as np

app = Flask(__name__)
CORS(app)

# Initialize rate limiter (to prevent DDoS)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per minute"]
)

# Initialize SQLite Database
conn = sqlite3.connect("traffic_data.db", check_same_thread=False)
c = conn.cursor()

# Create table if not exists
c.execute("""
    CREATE TABLE IF NOT EXISTS traffic_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        timestamp REAL,
        request_size INTEGER
    )
""")
conn.commit()

def get_client_ip():
    """Extract real client IP address from request headers."""
    return request.headers.get("X-Forwarded-For", request.remote_addr)

@app.route("/", methods=["GET", "POST"])
def home():
    """Logs each request, stores it in SQLite, and returns a success response."""
    timestamp = time.time()
    ip = get_client_ip()
    request_size = len(str(request.data))  # Approximate request size in bytes

    # Insert into SQLite database
    c.execute("INSERT INTO traffic_logs (ip, timestamp, request_size) VALUES (?, ?, ?)", 
              (ip, timestamp, request_size))
    conn.commit()

    return jsonify({"message": "Request received", "ip": ip, "size": request_size})

@app.route("/traffic-data", methods=["GET"])
def get_traffic_data():
    """Retrieve all logged traffic data from SQLite."""
    c.execute("SELECT id, ip, timestamp, request_size FROM traffic_logs")
    data = [{"id": row[0], "ip": row[1], "time": row[2], "size": row[3]} for row in c.fetchall()]
    return jsonify({"traffic_logs": data})

@app.route("/traffic-graph", methods=["GET"])
def traffic_graph():
    """Generates and returns a graph of traffic over time from SQLite."""

    # Fetch timestamps from SQLite
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

    # Save image to a file and return it
    img_path = "traffic_graph.png"
    plt.savefig(img_path)
    plt.close()
    
    return send_file(img_path, mimetype='image/png')

@app.route("/detect-anomaly", methods=["GET"])
def detect_anomaly():
    """Detects unusual spikes in request rate and groups anomalies by IP."""

    # Fetch timestamps and IPs from the traffic_logs table
    c.execute("SELECT ip, timestamp FROM traffic_logs")
    records = c.fetchall()

    if len(records) < 5:  # Not enough data for anomaly detection
        return jsonify({"message": "Not enough data for anomaly detection"})

    # Organizing data by IP
    ip_data = {}
    for ip, timestamp in records:
        if ip not in ip_data:
            ip_data[ip] = []
        ip_data[ip].append(timestamp)

    anomalies_by_ip = {}

    for ip, timestamps in ip_data.items():
        timestamps = sorted(timestamps)  # Ensure timestamps are in order
        intervals = np.diff(timestamps)  # Time gaps between requests

        if len(intervals) < 1:
            continue  # Skip if there's only one request

        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)

        threshold = mean_interval - (1.5 * std_interval)  # Adjusted sensitivity
        anomalies = [timestamps[i] for i in range(1, len(timestamps)) if intervals[i - 1] < threshold]

        if anomalies:
            anomalies_by_ip[ip] = anomalies

    return jsonify({
        "anomalies_by_ip": anomalies_by_ip,
        "total_ips_with_anomalies": len(anomalies_by_ip)
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
