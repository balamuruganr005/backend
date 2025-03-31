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

app = Flask(__name__)
CORS(app)

# Rate limiter to prevent excessive requests
limiter = Limiter(get_remote_address, app=app, default_limits=["2000 per minute"])

# Load Database URL
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not set")

def get_db_connection():
    try:
        return psycopg2.connect(DATABASE_URL)
    except Exception as e:
        print(f"Database Connection Error: {e}")
        return None

# Create or update database schema
try:
    conn = get_db_connection()
    if conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id SERIAL PRIMARY KEY,
                ip TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
        cur.close()
        conn.close()
except Exception as e:
    print(f"Error setting up database: {e}")

@app.route("/test-db", methods=["GET"])
def test_db():
    try:
        conn = get_db_connection()
        if conn:
            cur = conn.cursor()
            cur.execute("SELECT 1")  # Simple query to check connection
            cur.close()
            conn.close()
            return jsonify({"message": "Database connection successful"}), 200
        else:
            return jsonify({"error": "Database connection failed"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Function to fetch IP geolocation
def get_geolocation(ip):
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/")
        data = response.json()
        return data.get("country_name"), data.get("city"), data.get("latitude"), data.get("longitude")
    except Exception as e:
        print(f"Error fetching geolocation: {e}")
        return None, None, None, None

# Log traffic request
def log_traffic(ip, request_size, request_type, destination_port, user_agent):
    timestamp = datetime.now()
    country, city, latitude, longitude = get_geolocation(ip)
    try:
        conn = get_db_connection()
        if conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO traffic_logs (ip, timestamp, request_size, request_type, destination_port, user_agent, country, city, latitude, longitude)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (ip, timestamp, request_size, request_type, destination_port, user_agent, country, city, latitude, longitude))
            conn.commit()
            cur.close()
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
    log_traffic(ip, request_size, request_type, destination_port, user_agent)
    return jsonify({"message": "Traffic logged successfully", "ip": ip}), 200

@app.route("/", methods=["GET", "POST"])
def home():
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ip = request.remote_addr
    request_size = len(str(request.data))
    log_traffic(ip, request_size, "normal", 80, request.headers.get("User-Agent", "unknown"))
    return jsonify({"message": "Request logged", "ip": ip, "size": request_size})


@app.route("/traffic-data", methods=["GET"])
def get_traffic_data():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT ip, timestamp, request_size, request_type, destination_port, user_agent, status FROM traffic_logs ORDER BY timestamp DESC LIMIT 100")
        data = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({"traffic_logs": [{
            "ip": row[0],
            "timestamp": row[1].strftime('%Y-%m-%d %H:%M:%S'),
            "request_size": row[2],
            "request_type": row[3],
            "destination_port": row[4],
            "user_agent": row[5],
            "status": row[6]
        } for row in data]}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/detect-anomaly", methods=["GET"])
def detect_anomaly():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT ip, COUNT(*) FROM traffic_logs GROUP BY ip HAVING COUNT(*) > 5")
        anomalies = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({"anomalies": [{"ip": row[0], "count": row[1]} for row in anomalies]}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/traffic-graph", methods=["GET"])
def traffic_graph():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT timestamp FROM traffic_logs")
        data = cur.fetchall()
        cur.close()
        conn.close()
        times = [row[0].strftime('%H:%M:%S') for row in data]
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
