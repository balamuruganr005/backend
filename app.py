
from flask import Flask, request, jsonify
from flask_cors import CORS  # Import CORS
import time

app = Flask(__name__)
CORS(app)  # Allow requests from any website

request_logs = []

@app.route("/", methods=["GET", "POST"])
def home():
    timestamp = time.time()
    ip = request.remote_addr
    request_logs.append({"time": timestamp, "ip": ip})
    return jsonify({"message": "Request received", "ip": ip})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
