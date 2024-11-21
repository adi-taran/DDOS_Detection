from flask import render_template, request, jsonify
from app import app
from collections import Counter
import numpy as np
import time

# In-memory traffic logs
traffic_logs = []

@app.route('/')
def index():
    return render_template('index.html')

# API to simulate data packet reception
@app.route('/send_data', methods=['POST'])
def send_data():
    global traffic_logs
    ip = request.form.get('ip', '127.0.0.1')  # Default IP if none provided
    timestamp = time.time()
    traffic_logs.append((ip, timestamp))
    return jsonify({"message": "Data packet received", "ip": ip, "timestamp": timestamp})

# Analyze entropy and detect DDoS
@app.route('/analyze_entropy', methods=['GET'])
def analyze_entropy():
    global traffic_logs
    ips = [log[0] for log in traffic_logs]  # Extract IPs from logs
    ip_counts = Counter(ips)  # Frequency of each IP
    probabilities = [count / len(ips) for count in ip_counts.values()]
    entropy = -sum(p * np.log2(p) for p in probabilities if p > 0)

    # Threshold for DDoS detection
    if entropy < 1.0:
        status = "Potential DDoS Attack Detected"
    else:
        status = "Normal Traffic"

    return render_template('result.html', entropy=entropy, status=status, logs=dict(ip_counts))
