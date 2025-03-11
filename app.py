from flask import Flask, request, jsonify
import time

app = Flask(__name__)  # Make sure 'app' is used here

request_logs = []

@app.route("/", methods=["GET", "POST"])
def home():
    timestamp = time.time()
    ip = request.remote_addr
    request_logs.append({"time": timestamp, "ip": ip})
    return jsonify({"message": "Request received", "ip": ip})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)  # Use any port (Render will assign automatically)
