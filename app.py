from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)


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
@app.before_request
def log_traffic():
    conn = sqlite3.connect('traffic_logs.db')
    c = conn.cursor()

    ip = request.remote_addr
    request_size = request.content_length if request.content_length else 0
    request_type = request.method
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    # Store in the database
    c.execute("INSERT INTO traffic_logs (ip, request_size, request_type, user_agent) VALUES (?, ?, ?, ?)",
              (ip, request_size, request_type, user_agent))
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
