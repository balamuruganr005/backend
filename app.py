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


# Middleware to log every request
def log_traffic():
    conn = sqlite3.connect('traffic_logs.db')
    c = conn.cursor()

    # Example data capture (make sure you're capturing everything you need)
    ip = request.remote_addr
    request_size = len(request.data)  # Or appropriate size calculation
    request_type = request.method
    user_agent = request.headers.get('User-Agent')
    status = 'normal'  # Assuming normal, replace if you can track status
    country = 'USA'  # Can be fetched using an API like ipstack if required
    city = 'New York'  # Likewise, can be dynamically fetched
    latitude = 40.7128  # Optional, dynamic latitude
    longitude = -74.0060  # Optional, dynamic longitude

    # Insert traffic data into database
    c.execute('''
        INSERT INTO traffic_logs (ip, request_size, request_type, user_agent, status, country, city, latitude, longitude)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (ip, request_size, request_type, user_agent, status, country, city, latitude, longitude))

    conn.commit()
    conn.close()

@app.route("/traffic-data", methods=["GET"])
def get_traffic_data():
    conn = sqlite3.connect('traffic_logs.db')
    c = conn.cursor()
    c.execute("SELECT * FROM traffic_logs")
    data = c.fetchall()
    conn.close()
    
    return jsonify(data)

if __name__ == "__main__":
    app.run(debug=True)
