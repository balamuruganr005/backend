from flask import Flask, jsonify, request
import sqlite3
from datetime import datetime

app = Flask(__name__)

# Function to connect to the SQLite database
def get_db_connection():
    conn = sqlite3.connect('traffic_logs.db')  # Creates a local SQLite database file
    return conn

# Create table if it doesn't exist
def create_table():
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                timestamp TEXT,
                request_size INTEGER,
                request_type TEXT,
                destination_port INTEGER,
                user_agent TEXT,
                status TEXT,
                country TEXT,
                city TEXT,
                latitude REAL,
                longitude REAL
            )
        """)
        conn.commit()
        conn.close()
        print("✅ Table created or already exists.")
    except Exception as e:
        print(f"❌ Error creating table: {e}")

# Run this once when the app starts
create_table()

# Function to log traffic data
def log_traffic(ip, request_size, request_type, destination_port, user_agent):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    status = "normal"  # Adjust status based on your logic

    # Example: Hardcoded geolocation data (replace with real logic if needed)
    country, city, latitude, longitude = "Country", "City", 0.0, 0.0

    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            INSERT INTO traffic_logs (ip, timestamp, request_size, request_type, destination_port, user_agent, status, country, city, latitude, longitude)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip, timestamp, request_size, request_type, destination_port, user_agent, status, country, city, latitude, longitude))
        conn.commit()
        conn.close()
        print(f"✅ Logged traffic data for IP: {ip}")
    except Exception as e:
        print(f"❌ Error logging traffic: {e}")

# Route to log traffic data
@app.route("/track", methods=["POST"])
def track_traffic():
    data = request.get_json()

    # Extracting data from the request body
    ip = data.get("ip")
    request_size = data.get("request_size")
    request_type = data.get("request_type")
    destination_port = data.get("destination_port")
    user_agent = data.get("user_agent")

    if not all([ip, request_size, request_type, destination_port, user_agent]):
        return jsonify({"error": "Missing required fields"}), 400

    # Log the traffic data
    log_traffic(ip, request_size, request_type, destination_port, user_agent)

    return jsonify({"message": "Traffic logged successfully"}), 201

# Route to get the traffic data
@app.route("/traffic-data", methods=["GET"])
def get_traffic_data():
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM traffic_logs ORDER BY timestamp DESC LIMIT 100")
        data = c.fetchall()
        conn.close()

        traffic_logs = []
        for row in data:
            traffic_logs.append({
                "id": row[0],
                "ip": row[1],
                "timestamp": row[2],
                "request_size": row[3],
                "request_type": row[4],
                "destination_port": row[5],
                "user_agent": row[6],
                "status": row[7],
                "country": row[8],
                "city": row[9],
                "latitude": row[10],
                "longitude": row[11],
            })

        return jsonify({"traffic_logs": traffic_logs}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Run the app
if __name__ == "__main__":
    app.run(debug=True)
