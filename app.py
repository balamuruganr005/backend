from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time
import matplotlib.pyplot as plt
import io
import psycopg2
import numpy as np
import requests
import os

app = Flask(__name__)
CORS(app)

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

# Create table if not exists
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
        unusual_user_agent BOOLEAN
    )
""")
conn.commit()

# Define Malicious & Blocked IPs
MALICIOUS_IPS = {"45.140.143.77", "185.220.100.255"}
BLOCKED_IPS = {"81.23.152.244", "222.252.194.204"}

def get_client_ips():
    """Extracts all IPs from X-Forwarded-For header."""
    forwarded = request.headers.get("X-Forwarded-For", None)
    if forwarded:
        return [ip.strip() for ip in forwarded.split(",")]
    return [request.remote_addr]  # Single IP in list format

def get_location(ip):
    """Returns location based on IP address using a free API."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}").json()
        return response.get("country", "unknown")
    except requests.RequestException:
        return "unknown"

@app.route("/", methods=["GET", "POST"])
def home():
    """Logs each request, stores it in PostgreSQL, and returns a success response."""
    timestamp = time.time()
    ips = get_client_ips()
    request_size = len(str(request.data))  # Approximate request size in bytes
    user_agent = request.headers.get("User-Agent", "unknown")
    request_type = request.method

    for ip in ips:
        status = "normal"
        high_request_rate = False
        small_payload = False
        large_payload = False
        spike_in_requests = False
        repeated_access = False
        unusual_user_agent = False
        missing_invalid_headers = False

        # Check if the IP exceeded the request rate in the last 60 seconds
        try:
            c.execute("SELECT COUNT(*) FROM traffic_logs WHERE ip = %s AND timestamp > %s", (ip, timestamp - 60))
            request_count = c.fetchone()[0]

            if request_count > 100:  # If more than 100 requests in the last minute, flag as high request rate
                high_request_rate = True
                status = "malicious"
                request_size = 1500  # Correcting the request size for malicious IPs as per the rule
        except Exception as e:
            print(f"Error checking request rate for IP {ip}: {e}")

        if ip in MALICIOUS_IPS:
            status = "malicious"
        elif ip in BLOCKED_IPS:
            status = "blocked"

        # Additional rules for small/large payload, repeated access, etc.
        if request_size < 500:
            small_payload = True
        elif request_size > 1500:
            large_payload = True

        location = get_location(ip)

        try:
            # Insert into PostgreSQL database
            c.execute("""
                INSERT INTO traffic_logs (ip, timestamp, request_size, status, location, user_agent, request_type, 
                                          high_request_rate, small_payload, large_payload, spike_in_requests, 
                                          repeated_access, unusual_user_agent, missing_invalid_headers)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (ip, timestamp, request_size, status, location, user_agent, request_type, high_request_rate, 
                  small_payload, large_payload, spike_in_requests, repeated_access, unusual_user_agent, 
                  missing_invalid_headers))
            conn.commit()
        except Exception as e:
            print(f"Error inserting log for IP {ip}: {e}")
            conn.rollback()

    return jsonify({"message": "Request logged", "ips": ips, "size": request_size})


@app.route("/traffic-data", methods=["GET"])
def get_traffic_data():
    """Retrieve all logged traffic data from PostgreSQL, including new detection factors."""
    c.execute("""
        SELECT 
            id, 
            ip, 
            timestamp, 
            request_size, 
            status, 
            location, 
            user_agent, 
            request_type,
            high_request_rate,
            small_payload,
            large_payload,
            spike_in_requests,
            repeated_access,
            unusual_user_agent,
            missing_invalid_headers
        FROM traffic_logs
    """)
    data = [{
        "id": row[0],
        "ip": row[1],
        "time": row[2],
        "size": row[3],
        "status": row[4],
        "location": row[5],
        "user_agent": row[6],
        "request_type": row[7],
        "high_request_rate": row[8],
        "small_payload": row[9],
        "large_payload": row[10],
        "spike_in_requests": row[11],
        "repeated_access": row[12],
        "unusual_user_agent": row[13],
        "missing_invalid_headers": row[14]
    } for row in c.fetchall()]

    return jsonify({"traffic_logs": data})


@app.route("/traffic-graph", methods=["GET"])
def traffic_graph():
    """Generates and returns a graph of traffic over time from PostgreSQL."""
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
    """Detects unusual spikes in request rate and groups anomalies by IP"""
    c.execute("SELECT ip, timestamp FROM traffic_logs")
    records = c.fetchall()

    if len(records) < 5:  # Not enough data for anomaly detection
        return jsonify({"message": "Not enough data for anomaly detection"})

    ip_data = {}  # Group requests by IP
    for ip, timestamp in records:
        if ip not in ip_data:
            ip_data[ip] = []
        ip_data[ip].append(timestamp)

    anomalies_by_ip = {}
    for ip, timestamps in ip_data.items():
        if len(timestamps) >= 3:  # Rule: IP repeated 3 or more times is suspicious
            anomalies_by_ip[ip] = "Repeated IP detected"

    # Add all malicious IPs to anomalies
    for ip in MALICIOUS_IPS:
        anomalies_by_ip[ip] = "Malicious IP detected"

    return jsonify({
        "anomalies_by_ip": anomalies_by_ip,
        "total_ips_with_anomalies": len(anomalies_by_ip)
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
