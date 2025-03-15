from flask import Flask, jsonify, request
import logging
from api.logger import logger  # Import logger

# Set up logging
logging.basicConfig(level=logging.INFO)

from flask_sqlalchemy import SQLAlchemy
from api.fetch_osint import fetch_osint_data  # Removed unused imports
from src.risk_analysis import analyze_risk

from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from api.models import db, User  # Import the User model
import datetime
import random

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})  # Enable CORS for all routes

@app.route('/api/*', methods=['OPTIONS'])
def handle_options():
    response = jsonify({})
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3000')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
    return response


app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://shopsmart:123456789@localhost:5432/shopsmart'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# User Registration
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password)

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400

# User Login
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        return jsonify({"message": "Login successful", "user_id": user.id, "username": user.username}), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 401

# Fetch User Account Details
@app.route('/api/user/<int:user_id>', methods=['GET'])
def get_user_details(user_id):
    user = User.query.get(user_id)
    if user:
        return jsonify({"id": user.id, "username": user.username}), 200
    else:
        return jsonify({"error": "User not found"}), 404

@app.route('/api/abuseipdb', methods=['GET'])
def check_ip_abuse_route():
    ip_address = request.args.get('ip_address')
    api_key = request.headers.get('API-Key')
    
    if not ip_address or not api_key:
        return jsonify({"error": "IP address and API key are required"}), 400
    
    result = check_ip_abuse(api_key, ip_address)
    return jsonify(result)

@app.route('/favicon.ico')
def favicon():
    return app.send_static_file('static/favicon.ico')

@app.route('/api/spiderfoot/threat-logs', methods=['GET'])
def get_threat_logs():
    try:
        # Fetch OSINT data and analyze risk
        osint_data = fetch_osint_data()
        if not isinstance(osint_data, dict) or 'events' not in osint_data:
            logger.error("Invalid OSINT data structure received from Spiderfoot.")  # Log error for invalid OSINT data
            return jsonify({"error": "Invalid OSINT data structure."}), 500

        risk_analysis = analyze_risk(osint_data['events'])  # Pass only the events for risk analysis
        
        # Combine OSINT data with risk analysis
        threat_logs = [
            {"event": event, "risk": risk}
            for event, risk in zip(osint_data.get('events', []), risk_analysis)
        ]
        return jsonify(threat_logs)
    except Exception as e:
        logger.error(f"Failed to fetch threat logs: {str(e)}")  # Log the error
        return jsonify({"error": f"Failed to fetch threat logs: {str(e)}"}), 500

@app.route('/api/risk-scores', methods=['GET'])
def get_risk_scores():
    logger.info("Fetching risk scores...")  # Log the action
    osint_data = fetch_osint_data()
    logger.info(f"OSINT data fetched: {osint_data}")  # Log the fetched data

    threat_descriptions = [event["description"] for event in osint_data.get("events", []) if event.get("description")]
    
    if not threat_descriptions:
        return jsonify({"message": "No valid threat descriptions found, using default data."}), 200

    risk_scores = analyze_risk(threat_descriptions)
    return jsonify(risk_scores)

@app.route('/api/real-time-alerts', methods=['GET'])
def get_real_time_alerts():
    # More descriptive alerts
    real_time_alerts = [
        "Alert: Suspicious login attempt detected from unusual location.",
        "Alert: New malware signature detected in outbound network traffic.",
        "Alert: Unusual outbound traffic detected to known malicious IP.",
        "Alert: Multiple failed authentication attempts for admin account.",
        "Alert: Suspicious file download detected on marketing workstation."
    ]
    return jsonify(real_time_alerts)

@app.route('/api/osint', methods=['GET'])
def osint_data():
    return jsonify({"message": "OSINT data endpoint"})

if __name__ == '__main__':
    # Initialize the database
    @app.before_request
    def create_tables():
        db.create_all()  # Create tables

    app.run(debug=True, host='0.0.0.0', port=5002)  # Changed port to 5002
    logger.info("Application is running on port 5002")  # Log application start
