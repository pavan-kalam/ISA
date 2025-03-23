from flask import Flask, jsonify, request
import logging
from api.logger import logger
from flask_sqlalchemy import SQLAlchemy
from api.fetch_osint import fetch_osint_data
from src.api.risk_analysis import analyze_risk
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from api.models import db, User, TvaMapping, ThreatData
from src.api.risk_prioritization import RiskPrioritizer
from src.api.incident_response import IncidentResponder
from datetime import datetime
from time import time
from datetime import timedelta

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://shopsmart:123456789@localhost:5432/shopsmart'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Initialize risk prioritizer and incident responder
risk_prioritizer = RiskPrioritizer()
incident_responder = IncidentResponder()

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

@app.route('/api/user/<int:user_id>', methods=['GET'])
def get_user_details(user_id):
    user = User.query.get(user_id)
    if user:
        return jsonify({"id": user.id, "username": user.username}), 200
    else:
        return jsonify({"error": "User not found"}), 404

@app.route('/api/spiderfoot/threat-logs', methods=['GET'])
def get_threat_logs():
    try:
        start_time = time()
        osint_data = fetch_osint_data()
        logger.info(f"fetch_osint_data took {time() - start_time:.2f} seconds")
        
        if not isinstance(osint_data, dict) or 'events' not in osint_data:
            logger.error("Invalid OSINT data structure received.")
            return jsonify({"error": "Invalid OSINT data structure."}), 500

        events = osint_data['events']
        threat_descriptions = [event["description"] for event in events]
        risk_scores = analyze_risk(threat_descriptions)
        
        # Fetch TVA mappings
        tva_mappings = [
            {
                'threat_name': tva.threat_name,
                'likelihood': tva.likelihood,
                'impact': tva.impact
            } for tva in TvaMapping.query.all()
        ]

        # Fetch threat data from the database for recency
        threats_with_metadata = []
        for event, risk_score in zip(events, risk_scores):
            threat_entry = ThreatData.query.filter_by(description=event['description']).order_by(ThreatData.created_at.desc()).first()
            created_at = threat_entry.created_at if threat_entry else None
            threats_with_metadata.append({
                'description': event['description'],
                'threat_type': event['threat_type'],
                'risk_score': risk_score,
                'created_at': created_at
            })

        # Prioritize threats
        prioritized_threats = risk_prioritizer.prioritize_threats(threats_with_metadata, tva_mappings)

        # Generate response plans
        threat_logs = []
        for threat in prioritized_threats:
            response_plan = incident_responder.generate_response_plan(threat)
            threat_logs.append({
                'log': f"{threat['description']} (Risk: {threat['risk_score']}, Priority: {threat['priority_score']:.2f})",
                'response_plan': response_plan
            })

        return jsonify(threat_logs if threat_logs else [{"log": "No threat logs available", "response_plan": {}}])
    except Exception as e:
        logger.error(f"Failed to fetch threat logs: {str(e)}")
        return jsonify([{"log": "Hardcoded Threat Log 1", "response_plan": {}}, {"log": "Hardcoded Threat Log 2", "response_plan": {}}]), 200

@app.route('/api/risk-scores', methods=['GET'])
def get_risk_scores():
    try:
        osint_data = fetch_osint_data()
        threat_descriptions = [event["description"] for event in osint_data.get("events", [])]
        risk_scores = analyze_risk(threat_descriptions)
        return jsonify(risk_scores if risk_scores else [50, 75, 90])
    except Exception as e:
        logger.error(f"Failed to fetch risk scores: {str(e)}")
        return jsonify([50, 75, 90]), 200

@app.route('/api/real-time-alerts', methods=['GET'])
def get_real_time_alerts():
    try:
        # Fetch recent alerts from threat_data (last 24 hours)
        alerts = ThreatData.query.filter(ThreatData.created_at >= datetime.now() - timedelta(hours=24)).all()
        alert_threats = [
            {
                'description': alert.description,
                'threat_type': alert.threat_type,
                'risk_score': alert.risk_score,
                'created_at': alert.created_at
            } for alert in alerts
        ]

        # Fetch TVA mappings
        tva_mappings = [
            {
                'threat_name': tva.threat_name,
                'likelihood': tva.likelihood,
                'impact': tva.impact
            } for tva in TvaMapping.query.all()
        ]

        # Prioritize alerts
        prioritized_alerts = risk_prioritizer.prioritize_threats(alert_threats, tva_mappings)

        # Generate response plans
        real_time_alerts = []
        for alert in prioritized_alerts:
            response_plan = incident_responder.generate_response_plan(alert)
            real_time_alerts.append({
                'alert': f"{alert['description']} (Priority: {alert['priority_score']:.2f})",
                'response_plan': response_plan
            })

        return jsonify(real_time_alerts if real_time_alerts else [
            {"alert": "No real-time alerts available", "response_plan": {}}
        ])
    except Exception as e:
        logger.error(f"Failed to fetch real-time alerts: {str(e)}")
        return jsonify([
            {"alert": "Hardcoded Alert 1", "response_plan": {}},
            {"alert": "Hardcoded Alert 2", "response_plan": {}}
        ]), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5002)
    logger.info("Application is running on port 5002")