from flask import Flask, jsonify
import sqlite3
from datetime import datetime

app = Flask(__name__)

# Create a connection to the SQLite database
def get_db_connection():
    conn = sqlite3.connect('traffic_logs.db')
    conn.row_factory = sqlite3.Row
    return conn

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
@app.route('/insert-traffic-data', methods=['POST'])
def insert_traffic_data():
    try:
        ip = '127.0.0.1'
        request_size = 1234
        request_type = 'GET'
        destination_port = 80
        user_agent = 'Mozilla/5.0'
        status = 'normal'
        country = 'USA'
        city = 'New York'
        latitude = 40.7128
        longitude = -74.0060
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            INSERT INTO traffic_logs (ip, timestamp, request_size, request_type, destination_port, user_agent, status, country, city, latitude, longitude)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip, timestamp, request_size, request_type, destination_port, user_agent, status, country, city, latitude, longitude))

        conn.commit()
        conn.close()

        return jsonify({"message": "Data inserted successfully!"})

    except Exception as e:
        return jsonify({"error": f"Error inserting data: {str(e)}"})


if __name__ == '__main__':
    app.run(debug=True)
