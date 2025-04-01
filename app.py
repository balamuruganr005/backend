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

# Create table if not exists (updated to match all 18 columns)
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
        unusual_user_agent BOOLEAN,
        invalid_headers BOOLEAN,
        destination_port TEXT,
        country TEXT,
        city TEXT
    )
""")
conn.commit()

# Define Malicious & Blocked IPs
MALICIOUS_IPS = {"45.140.143.77", "185.220.100.255"}
BLOCKED_IPS = {"81.23.152.244", "222.252.194.204"}

def rate_limiter(ip, trust_score):
    current_time = time.time()

    # If the user is trusted (score > 0.9), allow instantly
    if trust_score >= 0.9:
        user_last_request[ip] = current_time
        return True  # ✅ Full Priority

    # If the user is suspicious (score 0.5-0.9), introduce delay
    elif 0.5 <= trust_score < 0.9:
        if ip in user_last_request and (current_time - user_last_request[ip] < 2):  # Delay 2s
            return False  # ⚠️ Limited Priority
        user_last_request[ip] = current_time
        return True

    # If attacker (score < 0.5), block
    else:
        return False  # ❌ No Priority

@app.route("/check_access", methods=["POST"])
def check_access():
    data = request.json
    ip = data.get("ip")
    trust_score = data.get("trust_score")  # This should come from the DNN

    allowed = rate_limiter(ip, trust_score)

    return jsonify({"ip": ip, "allowed": allowed})

def get_client_ips():
    """
    Extracts all IPs from X-Forwarded-For header.
    If no header, fallback to remote_addr.
    """
    forwarded = request.headers.get("X-Forwarded-For", None)
    if forwarded:
        return [ip.strip() for ip in forwarded.split(",")]  # Return list of IPs
    return [request.remote_addr]  # Single IP in list format

def get_location(ip):
    """Returns location based on IP address using a free API."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}").json()
        return response.get("country", "unknown"), response.get("city", "unknown")
    except requests.RequestException:
        return "unknown", "unknown"

@app.route("/", methods=["GET", "POST"])
def home():
    """Logs each request, stores it in PostgreSQL, and returns a success response."""
    timestamp = time.time()
    ips = get_client_ips()
    request_size = len(str(request.data))  # Approximate request size in bytes
    user_agent = request.headers.get("User-Agent", "unknown")
    request_type = request.method

     for ip in ips:
        status = "normal"  # Default status
        
        # Rule 1: Check for small request size
        if request_size < 50:  # Threshold for suspiciously small requests
            status = "suspicious"  # Flag small requests as suspicious
        # Rule 2: Check for large request size (could indicate a DDoS or resource request)
        elif request_size > 5000:  # Arbitrary large size threshold (can be adjusted)
            status = "suspicious"  # Flag large requests as suspicious
            
        # Rule 3: Check for repeated requests from the same IP (could indicate scanning or brute-force attempts)
        # This requires analyzing request frequency over time
        c.execute("""
            SELECT COUNT(*) FROM traffic_logs WHERE ip = %s AND timestamp > %s
        """, (ip, time.time() - 60))  # Check for requests from the last 60 seconds
        request_count = c.fetchone()[0]
        if request_count > 50:  # Arbitrary threshold for repeated requests (adjust as needed)
            status = "suspicious"
        
        # Rule 4: Known malicious IPs
        if ip in MALICIOUS_IPS:
            status = "malicious"
            request_size = 1500  # Correcting the request size for malicious IPs
        # Rule 5: Blocked IPs
        elif ip in BLOCKED_IPS:
            status = "blocked"

        # Rule 6: Unusual user agent strings (could be part of an attack attempt)
        if "bot" in user_agent.lower() or "crawl" in user_agent.lower():
            status = "suspicious"  # Flag bots or crawlers as suspicious

        # Rule 7: Extremely high request rate in a short period (could indicate DDoS)
        c.execute("""
            SELECT COUNT(*) FROM traffic_logs WHERE timestamp > %s
        """, (time.time() - 5))  # Check the request rate in the last 5 seconds
        recent_requests = c.fetchone()[0]
        if recent_requests > 100:  # Arbitrary threshold for rapid request bursts (adjust as needed)
            status = "malicious"  # Flag rapid request bursts as malicious

        location, city = get_location(ip)
        # Traffic behavior analysis
        high_request_rate = False  # Placeholder for actual logic
        small_payload = request_size < 500  # Example logic
        large_payload = request_size > 10000  # Example logic
        spike_in_requests = False  # Placeholder for actual logic
        repeated_access = False  # Placeholder for actual logic
        unusual_user_agent = "bot" in user_agent.lower()  # Simple check for bots
        invalid_headers = False  # Placeholder for actual logic
        destination_port = request.environ.get('REMOTE_PORT', 'Unknown')  # Get destination port

        # Insert into PostgreSQL database
        c.execute("""
            INSERT INTO traffic_logs 
            (ip, timestamp, request_size, status, location, user_agent, request_type, 
            high_request_rate, small_payload, large_payload, spike_in_requests, 
            repeated_access, unusual_user_agent, invalid_headers, destination_port, country, city) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (ip, timestamp, request_size, status, location, user_agent, request_type, 
              high_request_rate, small_payload, large_payload, spike_in_requests, 
              repeated_access, unusual_user_agent, invalid_headers, destination_port, 
              "unknown", city))
        conn.commit()

    return jsonify({"message": "Request logged", "ips": ips, "size": request_size})

@app.route("/traffic-data", methods=["GET"])
def get_traffic_data():
    """Retrieve all logged traffic data from PostgreSQL."""
    c.execute("""
        SELECT id, ip, timestamp, request_size, status, location, user_agent, 
        request_type, high_request_rate, small_payload, large_payload, spike_in_requests, 
        repeated_access, unusual_user_agent, invalid_headers, destination_port, country, city 
        FROM traffic_logs
    """)
    data = [{"id": row[0], "ip": row[1], "time": row[2], "size": row[3], "status": row[4], 
             "location": row[5], "user_agent": row[6], "request_type": row[7], 
             "high_request_rate": row[8], "small_payload": row[9], "large_payload": row[10], 
             "spike_in_requests": row[11], "repeated_access": row[12], "unusual_user_agent": row[13], 
             "invalid_headers": row[14], "destination_port": row[15], "country": row[16], "city": row[17]} 
            for row in c.fetchall()]
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
