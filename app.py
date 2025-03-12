from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import time
import matplotlib.pyplot as plt
import io
import sqlite3

app = Flask(__name__)
CORS(app)

# Initialize SQLite Database
def init_db():
    with sqlite3.connect("traffic_data.db") as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                timestamp REAL,
                request_size INTEGER
            )
        """)
        conn.commit()

init_db()

@app.route("/", methods=["GET", "POST"])
def home():
    """Logs each request, stores it in SQLite, and returns a success response"""
    timestamp = time.time()
    ip = request.remote_addr
    request_size = len(str(request.data))  # Approximate request size in bytes

    with sqlite3.connect("traffic_data.db") as conn:
        c = conn.cursor()
        c.execute("INSERT INTO traffic_logs (ip, timestamp, request_size) VALUES (?, ?, ?)", 
                  (ip, timestamp, request_size))
        conn.commit()

    return jsonify({"message": "Request received", "ip": ip, "size": request_size})

@app.route("/traffic", methods=["GET"])
def get_traffic():
    """Retrieve logged traffic data from SQLite"""
    with sqlite3.connect("traffic_data.db") as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM traffic_logs")
        data = c.fetchall()
    
    return jsonify({"traffic_logs": data})

@app.route("/traffic-graph", methods=["GET"])
def traffic_graph():
    """Generates and returns a graph of traffic over time from SQLite"""
    with sqlite3.connect("traffic_data.db") as conn:
        c = conn.cursor()
        c.execute("SELECT timestamp FROM traffic_logs")
        data = c.fetchall()

    if not data:
        return jsonify({"error": "No data available"})

    times = [row[0] for row in data]
    timestamps = [time.strftime("%H:%M:%S", time.localtime(t)) for t in times]

    plt.figure(figsize=(10, 5))
    plt.plot(timestamps, range(len(timestamps)), marker="o", linestyle="-", color="b")
    plt.xlabel("Time")
    plt.ylabel("Requests")
    plt.title("Traffic Flow Over Time")
    plt.xticks(rotation=45)

    # Save plot to a BytesIO object
    img = io.BytesIO()
    plt.savefig(img, format="png")
    img.seek(0)

    return send_file(img, mimetype="image/png")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
