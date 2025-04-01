from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

def get_location(ip):
    response = requests.get(f'http://ipinfo.io/{ip}/json')
    data = response.json()
    return data.get('country', 'Unknown'), data.get('city', 'Unknown'), data.get('loc', '0,0').split(',')

# Example usage
country, city, loc = get_location(ip)
latitude, longitude = loc


def initialize_database():
    conn = sqlite3.connect('traffic_logs.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            request_size INTEGER,
            request_type TEXT,
            port INTEGER,
            user_agent TEXT,
            status TEXT,
            country TEXT,
            city TEXT,
            latitude REAL,
            longitude REAL
        )
    ''')
    conn.commit()
    conn.close()

# Call this function at the start of your app
initialize_database()

def log_traffic():
    conn = sqlite3.connect('traffic_logs.db')
    c = conn.cursor()

    ip = request.remote_addr  # Get the IP address of the incoming request
    request_size = len(request.data)  # Size of the request
    request_type = request.method  # HTTP request method (GET, POST, etc.)
    user_agent = request.headers.get('User-Agent')  # User-Agent from the request header

    # For now, use placeholders for status, location, etc.
    status = 'normal'  # Assuming normal, can be modified as per DDoS detection
    country = 'Unknown'  # Default placeholder, can be modified
    city = 'Unknown'  # Default placeholder, can be modified
    latitude = None  # Can use IP geolocation if necessary
    longitude = None  # Can use IP geolocation if necessary

    # Print the captured details for debugging
    print(f"Captured Traffic: IP={ip}, Request Type={request_type}, Size={request_size}, User-Agent={user_agent}")

    # Insert traffic data into the SQLite database
    c.execute('''
        INSERT INTO traffic_logs (ip, request_size, request_type, user_agent, status, country, city, latitude, longitude)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (ip, request_size, request_type, user_agent, status, country, city, latitude, longitude))

    conn.commit()  # Commit the changes to the database
    conn.close()  # Close the connection

@app.route("/traffic-data", methods=["GET"])
def get_traffic_data():
    conn = sqlite3.connect('traffic_logs.db')
    c = conn.cursor()
    c.execute("SELECT * FROM traffic_logs")
    data = c.fetchall()
    conn.close()
    
    return jsonify(data)

@app.route('/insert-traffic-data', methods=['POST'])
def insert_traffic_data():
    log_traffic()  # Log traffic for the incoming request
    return jsonify({"message": "Traffic data inserted successfully."}), 200


if __name__ == "__main__":
    app.run(debug=True)
