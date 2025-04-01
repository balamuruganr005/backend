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
    try:
        # Simulating an API response
        response = {
            "country": "USA",
            "city": "New York"
        }
        return response.get("country", "Unknown"), response.get("city", "Unknown")
    except Exception:
        return "Unknown", "Unknown"


@app.route('/')
def home():
    conn = sqlite3.connect('traffic.db')  # Connect to SQLite database
    c = conn.cursor()

    ip = request.remote_addr  # Get IP address from request
    timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')  # Current timestamp
    request_size = request.content_length if request.content_length else 0  # Get request size
    status = "normal"  # Placeholder (replace with actual logic)
    user_agent = request.headers.get('User-Agent', 'Unknown')  # Get User-Agent header
    request_type = request.method  # GET, POST, etc.
    
    # Traffic behavior analysis (placeholders for now)
    high_request_rate = False  
    small_payload = request_size < 500  
    large_payload = request_size > 10000  
    spike_in_requests = False  
    repeated_access = False  
    unusual_user_agent = "bot" in user_agent.lower()  # Simple check for bots
    invalid_headers = False  
    
    # Get location details (handle cases where function returns more than 2 values)
    location_data = get_location(ip)
    if isinstance(location_data, tuple) and len(location_data) == 2:
        country, city = location_data
    else:
        country, city = "Unknown", "Unknown"  

    # Get destination port (Render might not provide this reliably)
    destination_port = request.environ.get('REMOTE_PORT', 'Unknown')

    # Insert into SQLite database
    c.execute("""
        INSERT INTO traffic_logs 
        (ip, timestamp, request_size, status, user_agent, request_type, 
         high_request_rate, small_payload, large_payload, spike_in_requests, 
         repeated_access, unusual_user_agent, invalid_headers, destination_port, country, city) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (ip, timestamp, request_size, status, user_agent, request_type, 
          high_request_rate, small_payload, large_payload, spike_in_requests, 
          repeated_access, unusual_user_agent, invalid_headers, destination_port, country, city))

    conn.commit()
    conn.close()

    return jsonify({"message": "Traffic data logged successfully"}), 200


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
