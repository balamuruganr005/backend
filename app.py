from flask import Flask, request, jsonify
from flask_cors import CORS
import time
import matplotlib.pyplot as plt
import io
import base64

app = Flask(__name__)
CORS(app)

request_logs = []  # Stores traffic data

@app.route("/", methods=["GET", "POST"])
def home():
    """Logs each request and returns a success response"""
    timestamp = time.time()
    ip = request.remote_addr
    request_logs.append({"time": timestamp, "ip": ip})
    return jsonify({"message": "Request received", "ip": ip})

@app.route("/traffic", methods=["GET"])
def get_traffic():
    """Returns logged traffic data"""
    return jsonify(request_logs)

@app.route("/traffic-graph", methods=["GET"])
def traffic_graph():
    """Generates and returns a graph of traffic over time"""
    if not request_logs:
        return jsonify({"error": "No data available"})

    times = [log["time"] for log in request_logs]
    timestamps = [time.strftime("%H:%M:%S", time.localtime(t)) for t in times]
    
    plt.figure(figsize=(10, 5))
    plt.plot(timestamps, range(len(timestamps)), marker="o", linestyle="-", color="b")
    plt.xlabel("Time")
    plt.ylabel("Requests")
    plt.title("Traffic Flow Over Time")
    plt.xticks(rotation=45)
    
    # Convert plot to image
    img = io.BytesIO()
    plt.savefig(img, format="png")
    img.seek(0)
    img_base64 = base64.b64encode(img.getvalue()).decode()
    
    return jsonify({"image": f"data:image/png;base64,{img_base64}"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
