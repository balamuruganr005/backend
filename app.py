from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime
import matplotlib.pyplot as plt
import io
import psycopg2
import numpy as np
import requests
import os

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Rate limiting setup to prevent DDoS
limiter = Limiter(get_remote_address, app=app, default_limits=["500 per minute"])

# Load PostgreSQL Database URL from environment variable
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not set")

# Database connection function
def get_db_connection():
    try:
        return psycopg2.connect(DATABASE_URL)
    except Exception as e:
        app.logger.error(f"Database Connection Error: {e}")
        return None

# Create traffic_logs table if it doesn't exist
def create_db_table():
    try:
        conn = get_db_connection()
        if conn:
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS traffic_logs (
                    id SERIAL PRIMARY KEY,
                    ip TEXT,
                    timestamp REAL,
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
        else:
            raise Exception("Failed to connect to the database")
    except Exception as e:
        app.logger.error(f"Error setting up database: {e}")

# Fetch geolocation data
def get_geolocation(ip):
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/")
        data = response.json()
        return data.get("country_name"), data.get("city"), data.get("latitude"), data.get("longitude")
    except Exception as e:
        app.logger.error(f"Error fetching geolocation: {e}")
        return None, None, None, None

# Function to log traffic data to the database
def log_traffic(ip, request_size, request_type, destination_port, user_agent):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    status = "normal"

    # Detect malicious traffic by tracking repeating IPs
    IP_ANOMALY_COUNT[ip] = IP_ANOMALY_COUNT.get(ip, 0) + 1
    if IP_ANOMALY_COUNT[ip] > REPEATING_IP_THRESHOLD:
        status = "malicious"
        MALICIOUS_IPS.add(ip)

    # Get geolocation information
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
        app.logger.error(f"Error logging traffic: {e}")

# Function to check and update the schema if necessary
def update_and_check_schema():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'traffic_logs';")
        existing_columns = {row[0] for row in cur.fetchall()}
        required_columns = {
            "request_type": "TEXT",
            "destination_port": "INTEGER",
            "country": "TEXT",
            "city": "TEXT",
            "user_agent": "TEXT"
        }
        for column, datatype in required_columns.items():
            if column not in existing_columns:
                cur.execute(f"ALTER TABLE traffic_logs ADD COLUMN {column} {datatype};")
                app.logger.info(f"✅ Added missing column: {column}")
        conn.commit()
        cur.close()
        conn.close()
        app.logger.info("✅ Schema update and check completed successfully!")
    except Exception as e:
        app.logger.error(f"❌ Error updating schema: {e}")

# Define anomaly detection and logging
def detect_anomalies():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT ip, timestamp FROM traffic_logs WHERE timestamp IS NOT NULL")
    records = c.fetchall()
    conn.close()

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

    return anomalies_by_ip, list(repeating_ips)

# Routes for the Flask app

@app.route("/test_db", methods=['GET'])
def test_db():
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT NOW();")
        result = c.fetchone()
        conn.close()
        return jsonify({"status": "success", "db_time": result[0]})
    except Exception as e:
        app.logger.error(f"Database test error: {e}")
        return jsonify({"status": "error", "message": str(e)})

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

        traffic_list = []
        for row in data:
            traffic_list.append({
                "ip": row[0],
                "timestamp": row[1],
                "request_size": row[2],
                "request_type": row[3],
                "destination_port": row[4],
                "user_agent": row[5],
                "status": row[6],
            })

        return jsonify({"traffic_logs": traffic_list}), 200
    except Exception as e:
        app.logger.error(f"Error in /traffic-data: {e}")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route("/traffic-graph", methods=["GET"])
def traffic_graph():
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500

        c = conn.cursor()
        c.execute("SELECT timestamp FROM traffic_logs")
        data = c.fetchall()
        conn.close()

        if not data:
            return jsonify({"error": "No data available"}), 500

        times = [datetime.utcfromtimestamp(t[0]).strftime("%H:%M:%S") for t in data if isinstance(t[0], (float, int))]

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
        app.logger.error(f"Error in /traffic-graph: {e}")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route("/track", methods=["POST"])
@limiter.limit("10 per minute")
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

@app.route("/detect-anomaly", methods=["GET"])
def detect_anomaly():
    anomalies_by_ip, repeating_ips = detect_anomalies()
    return jsonify({
        "anomalies_by_ip": anomalies_by_ip,
        "repeating_ips": repeating_ips,
        "total_ips_with_anomalies": len(anomalies_by_ip),
        "total_repeating_ips": len(repeating_ips)
    })

if __name__ == "__main__":
    create_db_table()  # Initialize DB table and schema update
    update_and_check_schema()  # Ensure schema is up-to-date
    app.run(host="0.0.0.0", port=5000, debug=True)
