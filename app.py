from flask import Flask, request, jsonify
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
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per minute"])

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

request_logs = []  # Stores traffic data in memory

def detect_anomaly():
    """Detect anomalies based on moving average"""
    c.execute("SELECT timestamp FROM traffic_logs")
    data = c.fetchall()
    timestamps = [row[0] for row in data]
    
    if len(timestamps) < 10:
        return False  # Not enough data to detect anomalies
    
    moving_avg = np.mean(timestamps[-10:])
    threshold = moving_avg * 1.5  # Example threshold
    
    return timestamps[-1] > threshold

@app.route("/", methods=["GET", "POST"])
@limiter.limit("10 per second")
def home():
    """Logs each request, stores it in SQLite, and returns a success response"""
    timestamp = time.time()
    ip = request.remote_addr
    request_size = len(str(request.data))  # Approximate request size in bytes
    request_logs.append({"time": timestamp, "ip": ip})

    # Insert into SQLite database
    c.execute("INSERT INTO traffic_logs (ip, timestamp, request_size) VALUES (?, ?, ?)", 
              (ip, timestamp, request_size))
    conn.commit()

    # Anomaly detection
    is_anomalous = detect_anomaly()
    
    return jsonify({"message": "Request received", "ip": ip, "size": request_size, "anomaly": is_anomalous})

@app.route("/traffic", methods=["GET"])
def get_traffic():
    """Returns logged traffic data (in-memory logs)"""
    return jsonify(request_logs)

@app.route("/traffic-data", methods=["GET"])
def get_traffic_data():
    """Retrieve all logged traffic data from SQLite"""
    c.execute("SELECT * FROM traffic_logs")
    data = c.fetchall()
    return jsonify({"traffic_logs": data})

@app.route("/traffic-graph", methods=["GET"])
def traffic_graph():
    """Generates and returns a graph of traffic over time from SQLite"""
    
    # Fetch timestamps from SQLite
    c.execute("SELECT timestamp FROM traffic_logs")
    data = c.fetchall()
    
    if not data:
        return jsonify({"error": "No data available"})

    times = [row[0] for row in data]
    timestamps = [time.strftime("%H:%M:%S", time.localtime(t)) for t in times]

    plt.figure(figsize=(10, 5))
    plt.plot(timestamps, range(len(timestamps)), marker="o", linestyle="-", color="b")
    plt.xlabel("Time")
    plt.ylabel("Requests")
    plt.title("Traffic Flow Over Time")
    plt.xticks(rotation=45)

    # Convert plot to image
    img = io.BytesIO()
    plt.savefig(img, format="png")
    img.seek(0)
    img_base64 = base64.b64encode(img.getvalue()).decode()

    return jsonify({"image": f"data:image/png;base64,{img_base64}"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
