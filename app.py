import sqlite3
from flask import Flask, jsonify, request
from datetime import datetime

app = Flask(__name__)

# Create a connection to the SQLite database
def get_db_connection():
    conn = sqlite3.connect('traffic_logs.db')
    conn.row_factory = sqlite3.Row
    return conn

# Create the traffic_logs table if it doesn't exist
def initialize_db():
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

# Initialize database when the app starts
initialize_db()

# Add some test data if the table is empty
def insert_test_data():
    conn = get_db_connection()
    c = conn.cursor()

    # Insert sample data if the table is empty
    c.execute("SELECT COUNT(*) FROM traffic_logs;")
    count = c.fetchone()[0]
    
    if count == 0:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        c.execute("""
            INSERT INTO traffic_logs (ip, timestamp, request_size, request_type, destination_port, user_agent, status, country, city, latitude, longitude)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, ('127.0.0.1', timestamp, 1234, 'GET', 80, 'Mozilla/5.0', 'normal', 'USA', 'New York', 40.7128, -74.0060))
        
        conn.commit()

    conn.close()

# Insert test data when app starts
insert_test_data()

# Route to fetch and display traffic data
@app.route('/traffic-data', methods=['GET'])
def get_traffic_data():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM traffic_logs;")
    traffic_data = c.fetchall()
    conn.close()
    
    # Convert data to JSON format
    data = []
    for row in traffic_data:
        data.append({
            "id": row["id"],
            "ip": row["ip"],
            "timestamp": row["timestamp"],
            "request_size": row["request_size"],
            "request_type": row["request_type"],
            "destination_port": row["destination_port"],
            "user_agent": row["user_agent"],
            "status": row["status"],
            "country": row["country"],
            "city": row["city"],
            "latitude": row["latitude"],
            "longitude": row["longitude"]
        })
    
    return jsonify(data)

# Route to insert traffic data
from flask import request
import requests

@app.route('/insert-traffic-data', methods=['POST'])
def insert_traffic_data():
    try:
        # Get client IP address
        ip = request.remote_addr

        # Get geolocation (optional)
        location_data = requests.get(f"https://ipapi.co/{ip}/json/").json()
        country = location_data.get("country_name", "Unknown")
        city = location_data.get("city", "Unknown")
        latitude = location_data.get("latitude", 0.0)
        longitude = location_data.get("longitude", 0.0)

        # Default values
        request_size = 512
        request_type = "GET"
        destination_port = 443
        user_agent = request.headers.get("User-Agent", "Unknown")
        status = "normal"
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            INSERT INTO traffic_logs (ip, timestamp, request_size, request_type, destination_port, user_agent, status, country, city, latitude, longitude)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip, timestamp, request_size, request_type, destination_port, user_agent, status, country, city, latitude, longitude))

        conn.commit()
        conn.close()

        return jsonify({"message": "Visitor data inserted successfully!"})

    except Exception as e:
        return jsonify({"error": f"Error inserting data: {str(e)}"})

if __name__ == '__main__':
    app.run(debug=True)
