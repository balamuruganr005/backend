from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime
import matplotlib.pyplot as plt
import psycopg2
import numpy as np
import requests
import os

app = Flask(__name__)
CORS(app)

# Initialize rate limiter (prevents DDoS)
limiter = Limiter(get_remote_address, app=app, default_limits=["2000 per minute"])

# Load PostgreSQL Database URL
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not set")

def get_db_connection():
    try:
        return psycopg2.connect(DATABASE_URL)
    except Exception as e:
        print(f"Database Connection Error: {e}")
        return None

# Ensure database schema is correct
def update_schema():
    try:
        conn = get_db_connection()
        if conn:
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS traffic_logs (
                    id SERIAL PRIMARY KEY,
                    ip TEXT,
                    timestamp TIMESTAMP DEFAULT NOW(),
                    request_size INTEGER,
                    request_type TEXT,
                    destination_port INTEGER,
                    user_agent TEXT,
                    status TEXT DEFAULT 'normal',
                    country TEXT,
                    city TEXT,
                    latitude REAL,
                    longitude REAL
                )
            """)
            conn.commit()
            c.close()
            conn.close()
    except Exception as e:
        print(f"Error updating schema: {e}")

update_schema()  # Run once when the app starts

# Home route
@app.route("/")
def home():
    return jsonify({"message": "Welcome to DDoS-Proto Traffic Monitor API"}), 200

# Track malicious IPs
MALICIOUS_IPS = set()
IP_ANOMALY_COUNT = {}
REPEATING_IP_THRESHOLD = 5

def get_geolocation(ip):
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/")
        data = response.json()
        return data.get("country_name"), data.get("city"), data.get("latitude"), data.get("longitude")
    except Exception as e:
        print(f"Error fetching geolocation: {e}")
        return None, None, None, None

def log_traffic(ip, request_size, request_type, destination_port, user_agent):
    global IP_ANOMALY_COUNT, MALICIOUS_IPS

    timestamp = datetime.now()
    status = "normal"

    IP_ANOMALY_COUNT[ip] = IP_ANOMALY_COUNT.get(ip, 0) + 1
    if IP_ANOMALY_COUNT[ip] > REPEATING_IP_THRESHOLD:
        status = "malicious"
        MALICIOUS_IPS.add(ip)

    country, city, latitude, longitude = get_geolocation(ip)

    try:
        conn = get_db_connection()
        if conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO traffic_logs (ip, timestamp, request_size, request_type, destination_port, user_agent, status, country, city, latitude, longitude)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (ip, timestamp, request_size, request_type, destination_port, user_agent, status, country, city, latitude, longitude))
            conn.commit()
            c.close()
            conn.close()
    except Exception as e:
        print(f"Error logging traffic: {e}")

@app.route("/track", methods=["POST"])
def track_request():
    data = request.json
    ip = data.get("ip", request.remote_addr)
    request_size = data.get("request_size", 0)
    request_type = data.get("request_type", "unknown")
    destination_port = data.get("destination_port", 80)
    user_agent = request.headers.get("User-Agent", "unknown")

    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    log_traffic(ip, request_size, request_type, destination_port, user_agent)
    return jsonify({"message": "Traffic logged successfully", "ip": ip, "status": "logged"}), 200

@app.route("/traffic-data", methods=["GET"])
def get_traffic_data():
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500

        c = conn.cursor()
        c.execute("SELECT ip, timestamp, request_size, request_type, destination_port, user_agent, status FROM traffic_logs ORDER BY timestamp DESC LIMIT 100")
        data = c.fetchall()
        conn.close()

        traffic_list = [{
            "ip": row[0],
            "timestamp": row[1].strftime("%Y-%m-%d %H:%M:%S"),
            "request_size": row[2],
            "request_type": row[3],
            "destination_port": row[4],
            "user_agent": row[5],
            "status": row[6],
        } for row in data]

        return jsonify({"traffic_logs": traffic_list}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/traffic-graph", methods=["GET"])
def traffic_graph():
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        c = conn.cursor()
        c.execute("SELECT timestamp FROM traffic_logs ORDER BY timestamp ASC")
        data = c.fetchall()
        conn.close()

        if not data:
            return jsonify({"error": "No data available"}), 500

        times = [row[0].strftime("%H:%M:%S") for row in data if isinstance(row[0], datetime)]

        plt.figure(figsize=(10, 5))
        plt.step(times, range(len(times)), marker="o", linestyle="-", color="b")
        plt.xlabel("Time")
        plt.ylabel("Requests")
        plt.title("Traffic Flow Over Time")
        plt.xticks(rotation=45)

        img_path = "/tmp/traffic_graph.png"
        plt.savefig(img_path)
        plt.close()

        return send_file(img_path, mimetype="image/png")
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
        intervals = np.diff([t.timestamp() for t in timestamps])
        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        threshold = max(mean_interval - (1.5 * std_interval), 0.1)  

        anomalies = [timestamps[i] for i in range(1, len(timestamps)) if intervals[i - 1] < threshold]

        if len(timestamps) > REPEATING_IP_THRESHOLD:
            repeating_ips.add(ip)

        if anomalies:
            anomalies_by_ip[ip] = [t.strftime("%Y-%m-%d %H:%M:%S") for t in anomalies]

    return jsonify({"anomalies_by_ip": anomalies_by_ip, "repeating_ips": list(repeating_ips)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
