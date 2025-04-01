from flask import Flask, jsonify
import psycopg2
import os

app = Flask(__name__)

# Load PostgreSQL Database URL
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not set")

def get_db_connection():
    try:
        return psycopg2.connect(DATABASE_URL)
    except Exception as e:
        print(f"Database Connection Error: {e}")
        return None
@app.route("/test-insert", methods=["GET"])
def test_insert():
    ip = "127.0.0.1"  # Test IP address
    request_size = 1234  # Test request size
    request_type = "GET"  # Test request type
    destination_port = 80  # Test port
    user_agent = "Mozilla/5.0"  # Test User-Agent
    status = "normal"  # Test status

    # Try inserting a test record
    try:
        conn = get_db_connection()
        if conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO traffic_logs (ip, timestamp, request_size, request_type, destination_port, user_agent, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (ip, datetime.now(), request_size, request_type, destination_port, user_agent, status))
            conn.commit()
            c.close()
            conn.close()
            return jsonify({"message": "Test data inserted successfully!"}), 200
        else:
            return jsonify({"error": "Database connection failed"}), 500
    except Exception as e:
        return jsonify({"error": f"Error inserting data: {e}"}), 500


@app.route("/traffic-data", methods=["GET"])
def get_traffic_data():
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500

        c = conn.cursor()
        c.execute("""
            SELECT ip, timestamp, request_size, request_type, destination_port, user_agent, status
            FROM traffic_logs
            ORDER BY timestamp DESC
            LIMIT 100
        """)
        data = c.fetchall()
        conn.close()

        # Convert data into JSON format
        traffic_list = [
            {
                "ip": row[0],
                "timestamp": row[1],
                "request_size": row[2],
                "request_type": row[3],
                "destination_port": row[4],
                "user_agent": row[5],
                "status": row[6],
            }
            for row in data
        ]

        return jsonify({"traffic_logs": traffic_list}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
