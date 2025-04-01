# # src/api/app.py (at the top)
# import importlib
# import api.spiderfoot
# importlib.reload(api.spiderfoot)
# # src/api/app.py
# from flask import Flask, jsonify, request
# import logging
# from api.logger import logger
# from flask_sqlalchemy import SQLAlchemy
# from flask_migrate import Migrate
# from flask_cors import CORS
# from werkzeug.security import generate_password_hash, check_password_hash
# from api.models import db, User, TvaMapping, ThreatData, AlertLog
# from api.fetch_osint import fetch_osint_data
# from src.api.risk_analysis import analyze_risk
# from src.api.risk_prioritization import RiskPrioritizer
# from src.api.incident_response import IncidentResponder
# from api.alerts import send_alert_if_high_risk
# from api.cba_analysis import suggest_mitigation
# from api.api_optimizer import get_threat_data
# from datetime import datetime, timedelta
# from time import time
# import threading
# from api.models import db, Asset


# logging.basicConfig(level=logging.INFO)

# app = Flask(__name__)

# # Enable CORS for frontend
# CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://shopsmart:123456789@localhost:5432/shopsmart'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# db.init_app(app)

# migrate = Migrate(app, db)

# risk_prioritizer = RiskPrioritizer()
# incident_responder = IncidentResponder()
# lock = threading.Lock()

# with app.app_context():
#     db.create_all()

# @app.route('/api/register', methods=['POST'])
# def register():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')

#     if not username or not password:
#         return jsonify({"error": "Username and password are required"}), 400

#     if User.query.filter_by(username=username).first():
#         return jsonify({"error": "Username already exists"}), 400

#     hashed_password = generate_password_hash(password)
#     new_user = User(username=username, password_hash=hashed_password)

#     try:
#         db.session.add(new_user)
#         db.session.commit()
#         return jsonify({"message": "User registered successfully"}), 201
#     except Exception as e:
#         db.session.rollback()
#         logger.error(f"Failed to register user: {str(e)}")
#         return jsonify({"error": str(e)}), 400

# @app.route('/api/login', methods=['POST'])
# def login():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')

#     if not username or not password:
#         return jsonify({"error": "Username and password are required"}), 400

#     user = User.query.filter_by(username=username).first()
#     if user and check_password_hash(user.password_hash, password):
#         return jsonify({"message": "Login successful", "user_id": user.id, "username": user.username}), 200
#     else:
#         return jsonify({"error": "Invalid username or password"}), 401

# @app.route('/api/user/<int:user_id>', methods=['GET'])
# def get_user_details(user_id):
#     user = User.query.get(user_id)
#     if user:
#         return jsonify({"id": user.id, "username": user.username}), 200
#     else:
#         return jsonify({"error": "User not found"}), 404

# @app.route('/api/assets', methods=['GET'])
# def get_assets():
#     try:
#         assets = Asset.query.all()
#         assets_list = [
#             {
#                 "id": asset.id,
#                 "name": asset.name,
#                 "type": asset.type,
#                 "identifier": asset.identifier  # Explicitly include identifier
#             }
#             for asset in assets
#         ]
#         logger.info(f"Fetched {len(assets_list)} assets")
#         return jsonify(assets_list), 200
#     except Exception as e:
#         logger.error(f"Failed to fetch assets: {str(e)}")
#         return jsonify({"error": str(e)}), 500
    
# # src/api/app.py (modify the /api/spiderfoot/threat-logs endpoint)
# # src/api/app.py
# @app.route('/api/spiderfoot/threat-logs', methods=['GET'])
# def get_threat_logs():
#     with lock:
#         try:
#             start_time = time()
#             asset_name = request.args.get('query', None)
#             if not asset_name:
#                 logger.warning("No asset name provided in query")
#                 return jsonify([{"log": "No asset specified", "response_plan": {}}]), 200

#             asset = Asset.query.filter_by(name=asset_name).first()
#             if not asset:
#                 logger.warning(f"Asset '{asset_name}' not found, falling back to default query")
#                 # Fallback to a default identifier or return empty result
#                 return jsonify([{"log": f"Asset '{asset_name}' not found", "response_plan": {}}]), 200

#             query = asset.identifier if asset.identifier else asset_name
#             asset_type = asset.type.lower()

#             # Select SpiderFoot modules based on asset type
#             modules = "sfp_spider,sfp_http"  # Default modules
#             if asset_type == "hardware":
#                 modules = "sfp_spider,sfp_portscan,sfp_dnsresolve"
#             elif asset_type == "software" or asset_type == "data" or asset_type == "process":
#                 modules = "sfp_spider,sfp_http,sfp_dnsresolve,sfp_whois"
#             elif asset_type == "people":
#                 modules = "sfp_spider,sfp_email,sfp_social"

#             logger.info(f"Querying SpiderFoot for asset '{asset_name}' (type: {asset_type}) with identifier '{query}' using modules '{modules}'")
#             osint_data = get_threat_data(query, modules=modules)
#             logger.info(f"get_threat_data for query '{query}' took {time() - start_time:.2f} seconds")

#             if not isinstance(osint_data, dict) or 'events' not in osint_data:
#                 logger.error(f"Invalid OSINT data structure: {osint_data}")
#                 raise ValueError("Invalid OSINT data structure received")

#             events = osint_data.get('events', [])
#             if not events:
#                 logger.warning(f"No events returned from SpiderFoot for {asset_name}")
#                 return jsonify([{"log": f"No threat logs available for {asset_name}", "response_plan": {}}]), 200

#             threat_descriptions = [event.get("description", "Unknown") for event in events]
#             risk_scores = analyze_risk(threat_descriptions)

#             tva_mappings = [
#                 {'threat_name': tva.threat_name, 'likelihood': tva.likelihood, 'impact': tva.impact}
#                 for tva in TvaMapping.query.all()
#             ]

#             processed_threats = set()
#             threats_with_metadata = []
#             for event, risk_score in zip(events, risk_scores):
#                 desc = event.get('description', 'Unknown')
#                 if desc in processed_threats:
#                     continue
#                 processed_threats.add(desc)
#                 threat_entry = ThreatData.query.filter_by(description=desc).order_by(ThreatData.created_at.desc()).first()
#                 created_at = threat_entry.created_at if threat_entry else datetime.utcnow()
#                 threats_with_metadata.append({
#                     'description': desc,
#                     'threat_type': event.get('threat_type', 'Other'),
#                     'risk_score': risk_score,
#                     'created_at': created_at
#                 })

#             prioritized_threats = risk_prioritizer.prioritize_threats(threats_with_metadata, tva_mappings)
#             threat_logs = []

#             for threat in prioritized_threats[:10]:
#                 send_alert_if_high_risk(threat['description'], threat['risk_score'])
#                 response_plan = incident_responder.generate_response_plan(threat)
#                 cba_info = suggest_mitigation(threat['description'], threat['risk_score'])
#                 threat_logs.append({
#                     'log': f"{threat['description']} (Risk: {threat['risk_score']}, Priority: {threat['priority_score']:.2f})",
#                     'response_plan': response_plan,
#                     'cba': cba_info
#                 })

#             return jsonify(threat_logs), 200
#         except Exception as e:
#             logger.error(f"Failed to fetch threat logs: {str(e)}")
#             return jsonify([{"log": f"Error: {str(e)}", "response_plan": {}}]), 500
# # Update get_threat_data to accept modules parameter
# def get_threat_data(query, modules="sfp_spider,sfp_http"):
#     try:
#         spiderfoot_data = fetch_spiderfoot_data(query, modules=modules)
#         return spiderfoot_data
#     except Exception as e:
#         logger.error(f"Error in get_threat_data: {str(e)}")
#         return {"events": []}
        
# @app.route('/api/risk-scores', methods=['GET'])
# def get_risk_scores():
#     try:
#         osint_data = get_threat_data("localhost:5002")
#         threat_descriptions = [event.get("description", "Unknown") for event in osint_data.get("events", [])]
#         risk_scores = analyze_risk(threat_descriptions)
#         return jsonify(risk_scores if risk_scores else [50, 75, 90])
#     except Exception as e:
#         logger.error(f"Failed to fetch risk scores: {str(e)}")
#         return jsonify([50, 75, 90]), 200

# # src/api/app.py
# @app.route('/api/real-time-alerts', methods=['GET'])
# def get_real_time_alerts():
#     try:
#         asset_name = request.args.get('query', 'localhost:5002')
#         asset = Asset.query.filter_by(name=asset_name).first()
#         query = asset.identifier if asset and asset.identifier else asset_name

#         alerts = Alert.query.order_by(Alert.created_at.desc()).limit(10).all()
#         filtered_alerts = [
#             alert for alert in alerts
#             if query.lower() in alert.description.lower()
#         ]
#         alerts_list = [
#             {
#                 "alert": f"{alert.description} (Risk: {alert.risk_score}, Type: {alert.risk_type})",
#                 "response_plan": incident_responder.generate_response_plan({
#                     "description": alert.description,
#                     "risk_score": alert.risk_score,
#                     "threat_type": alert.threat_type
#                 })
#             }
#             for alert in filtered_alerts
#         ]
#         logger.info(f"Fetched {len(alerts_list)} real-time alerts for query '{query}'")
#         return jsonify(alerts_list), 200
#     except Exception as e:
#         logger.error(f"Failed to fetch real-time alerts: {str(e)}")
#         return jsonify([]), 200





# # src/api/app.py (at the top)
# import importlib
# import api.spiderfoot
# importlib.reload(api.spiderfoot)

# # src/api/app.py
# from flask import Flask, jsonify, request
# import logging
# from api.logger import logger
# from flask_sqlalchemy import SQLAlchemy
# from flask_migrate import Migrate
# from flask_cors import CORS
# from werkzeug.security import generate_password_hash, check_password_hash
# from api.models import db, User, TvaMapping, ThreatData, AlertLog
# from api.fetch_osint import fetch_osint_data
# from api.spiderfoot import fetch_spiderfoot_data
# from src.api.risk_analysis import analyze_risk
# from src.api.risk_prioritization import RiskPrioritizer
# from src.api.incident_response import IncidentResponder
# from api.alerts import send_alert_if_high_risk
# from api.cba_analysis import suggest_mitigation
# from api.api_optimizer import get_threat_data
# from datetime import datetime, timedelta
# from time import time
# import threading
# from api.models import db, Asset

# logging.basicConfig(level=logging.INFO)
# app = Flask(__name__)

# # Enable CORS for frontend
# CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://shopsmart:123456789@localhost:5432/shopsmart'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# db.init_app(app)
# migrate = Migrate(app, db)

# risk_prioritizer = RiskPrioritizer()
# incident_responder = IncidentResponder()
# lock = threading.Lock()

# with app.app_context():
#     db.create_all()

# @app.route('/api/register', methods=['POST'])
# def register():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')
#     if not username or not password:
#         return jsonify({"error": "Username and password are required"}), 400
#     if User.query.filter_by(username=username).first():
#         return jsonify({"error": "Username already exists"}), 400
#     hashed_password = generate_password_hash(password)
#     new_user = User(username=username, password_hash=hashed_password)
#     try:
#         db.session.add(new_user)
#         db.session.commit()
#         return jsonify({"message": "User registered successfully"}), 201
#     except Exception as e:
#         db.session.rollback()
#         logger.error(f"Failed to register user: {str(e)}")
#         return jsonify({"error": str(e)}), 400

# @app.route('/api/login', methods=['POST'])
# def login():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')
#     if not username or not password:
#         return jsonify({"error": "Username and password are required"}), 400
#     user = User.query.filter_by(username=username).first()
#     if user and check_password_hash(user.password_hash, password):
#         return jsonify({"message": "Login successful", "user_id": user.id, "username": user.username}), 200
#     else:
#         return jsonify({"error": "Invalid username or password"}), 401

# @app.route('/api/user/<int:user_id>', methods=['GET'])
# def get_user_details(user_id):
#     user = User.query.get(user_id)
#     if user:
#         return jsonify({"id": user.id, "username": user.username}), 200
#     else:
#         return jsonify({"error": "User not found"}), 404

# @app.route('/api/assets', methods=['GET'])
# def get_assets():
#     try:
#         assets = Asset.query.all()
#         assets_list = [
#             {
#                 "id": asset.id,
#                 "name": asset.name,
#                 "type": asset.type,
#                 "identifier": asset.identifier
#             }
#             for asset in assets
#         ]
#         logger.info(f"Fetched {len(assets_list)} assets")
#         return jsonify(assets_list), 200
#     except Exception as e:
#         logger.error(f"Failed to fetch assets: {str(e)}")
#         return jsonify({"error": str(e)}), 500

# @app.route('/api/spiderfoot/threat-logs', methods=['GET'])
# def get_threat_logs():
#     with lock:
#         try:
#             start_time = time()
#             query = request.args.get('query', 'localhost:5002')
#             osint_data = get_threat_data(query)
#             logger.info(f"get_threat_data for query '{query}' took {time() - start_time:.2f} seconds")
#             if not isinstance(osint_data, dict) or 'events' not in osint_data:
#                 logger.error(f"Invalid OSINT data structure: {osint_data}")
#                 raise ValueError("Invalid OSINT data structure received")
#             events = osint_data.get('events', [])
#             if not events:
#                 logger.warning("No events returned from SpiderFoot")
#                 return jsonify([{"log": "No threat logs available from SpiderFoot", "response_plan": {}}]), 200
#             threat_descriptions = [event.get("description", "Unknown") for event in events]
#             risk_scores = analyze_risk(threat_descriptions)
#             tva_mappings = [
#                 {'threat_name': tva.threat_name, 'likelihood': tva.likelihood, 'impact': tva.impact}
#                 for tva in TvaMapping.query.all()
#             ]
#             processed_threats = set()
#             threats_with_metadata = []
#             for event, risk_score in zip(events, risk_scores):
#                 desc = event.get('description', 'Unknown')
#                 if desc in processed_threats:
#                     continue
#                 processed_threats.add(desc)
#                 threat_entry = ThreatData.query.filter_by(description=desc).order_by(ThreatData.created_at.desc()).first()
#                 created_at = threat_entry.created_at if threat_entry else datetime.utcnow()
#                 threats_with_metadata.append({
#                     'description': desc,
#                     'threat_type': event.get('threat_type', 'Other'),
#                     'risk_score': risk_score,
#                     'created_at': created_at
#                 })

#             prioritized_threats = risk_prioritizer.prioritize_threats(threats_with_metadata, tva_mappings)
#             threat_logs = []
#             for threat in prioritized_threats[:10]:
#                 send_alert_if_high_risk(threat['description'], threat['risk_score'], threat['threat_type'])
#                 response_plan = incident_responder.generate_response_plan(threat)
#                 cba_info = suggest_mitigation(threat['description'], threat['risk_score'])
#                 threat_logs.append({
#                     'log': f"{threat['description']} (Risk: {threat['risk_score']}, Priority: {threat['priority_score']:.2f})",
#                     'response_plan': response_plan,
#                     'cba': cba_info
#                 })
#             return jsonify(threat_logs), 200
#         except Exception as e:
#             logger.error(f"Failed to fetch threat logs: {str(e)}")
#             return jsonify([{"log": f"Error: {str(e)}", "response_plan": {}}]), 500

# def get_threat_data(query, modules="sfp_spider,sfp_http"):
#     try:
#         spiderfoot_data = fetch_spiderfoot_data(query, modules=modules)
#         return spiderfoot_data
#     except Exception as e:
#         logger.error(f"Error in get_threat_data: {str(e)}")
#         return {"events": []}

# @app.route('/api/risk-scores', methods=['GET'])
# def get_risk_scores():
#     try:
#         osint_data = get_threat_data("localhost:5002")
#         threat_descriptions = [event.get("description", "Unknown") for event in osint_data.get("events", [])]
#         risk_scores = analyze_risk(threat_descriptions)
#         return jsonify(risk_scores if risk_scores else [50, 75, 90])
#     except Exception as e:
#         logger.error(f"Failed to fetch risk scores: {str(e)}")
#         return jsonify([50, 75, 90]), 200

# @app.route('/api/real-time-alerts', methods=['GET'])
# def get_real_time_alerts():
#     try:
#         asset_name = request.args.get('query', 'localhost:5002')
#         asset = Asset.query.filter_by(name=asset_name).first()
#         query = asset.identifier if asset and asset.identifier else asset_name
#         alerts = AlertLog.query.order_by(AlertLog.created_at.desc()).limit(10).all()
#         filtered_alerts = [
#             alert for alert in alerts
#             if query.lower() in alert.threat.lower()
#         ]
#         alerts_list = [
#             {
#                 "alert": f"{alert.threat} (Risk: {alert.risk_score}, Type: {alert.alert_type})",
#                 "response_plan": incident_responder.generate_response_plan({
#                     "description": alert.threat,
#                     "risk_score": alert.risk_score,
#                     "threat_type": alert.threat_type
#                 })
#             }
#             for alert in filtered_alerts
#         ]
#         logger.info(f"Fetched {len(alerts_list)} real-time alerts for query '{query}'")
#         return jsonify(alerts_list), 200
#     except Exception as e:
#         logger.error(f"Failed to fetch real-time alerts: {str(e)}")
#         return jsonify([]), 200

# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=5002)
#     logger.info("Application is running on port 5002")





# # src/api/app.py
# from flask import Flask, jsonify, request
# import logging
# from api.logger import logger
# from flask_sqlalchemy import SQLAlchemy
# from flask_migrate import Migrate
# from flask_cors import CORS
# from werkzeug.security import generate_password_hash, check_password_hash
# from api.models import db, User, TvaMapping, ThreatData, AlertLog
# from api.fetch_osint import fetch_osint_data
# from src.api.risk_analysis import analyze_risk
# from src.api.risk_prioritization import RiskPrioritizer
# from src.api.incident_response import IncidentResponder
# from api.alerts import send_alert_if_high_risk
# from api.cba_analysis import suggest_mitigation
# from api.api_optimizer import get_threat_data
# from datetime import datetime, timedelta
# from time import time
# import threading

# logging.basicConfig(level=logging.INFO)

# app = Flask(__name__)

# # Ensure CORS is enabled for all /api/* routes
# CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://shopsmart:123456789@localhost:5432/shopsmart'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# db.init_app(app)

# # Initialize Flask-Migrate
# migrate = Migrate(app, db)

# risk_prioritizer = RiskPrioritizer()
# incident_responder = IncidentResponder()
# last_processed_threats = set()  # Deduplication
# lock = threading.Lock()  # Thread safety

# with app.app_context():
#     db.create_all()

# @app.route('/api/register', methods=['POST'])
# def register():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')

#     if not username or not password:
#         return jsonify({"error": "Username and password are required"}), 400

#     # Check if user already exists
#     if User.query.filter_by(username=username).first():
#         return jsonify({"error": "Username already exists"}), 400

#     hashed_password = generate_password_hash(password)
#     new_user = User(username=username, password_hash=hashed_password)

#     try:
#         db.session.add(new_user)
#         db.session.commit()
#         return jsonify({"message": "User registered successfully"}), 201
#     except Exception as e:
#         db.session.rollback()
#         logger.error(f"Failed to register user: {str(e)}")
#         return jsonify({"error": str(e)}), 400

# @app.route('/api/login', methods=['POST'])
# def login():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')

#     if not username or not password:
#         return jsonify({"error": "Username and password are required"}), 400

#     user = User.query.filter_by(username=username).first()
#     if user and check_password_hash(user.password_hash, password):
#         return jsonify({"message": "Login successful", "user_id": user.id, "username": user.username}), 200
#     else:
#         return jsonify({"error": "Invalid username or password"}), 401

# @app.route('/api/user/<int:user_id>', methods=['GET'])
# def get_user_details(user_id):
#     user = User.query.get(user_id)
#     if user:
#         return jsonify({"id": user.id, "username": user.username}), 200
#     else:
#         return jsonify({"error": "User not found"}), 404

# @app.route('/api/spiderfoot/threat-logs', methods=['GET'])
# def get_threat_logs():
#     with lock:
#         try:
#             start_time = time()
#             osint_data = get_threat_data("localhost:5002")
#             logger.info(f"get_threat_data took {time() - start_time:.2f} seconds")

#             if not isinstance(osint_data, dict) or 'events' not in osint_data:
#                 logger.error("Invalid OSINT data structure received.")
#                 return jsonify([
#                     {
#                         "log": "No threat logs available due to invalid OSINT data",
#                         "response_plan": {
#                             "threat_type": "Other",
#                             "description": "No response plan available",
#                             "priority": "Low",
#                             "mitigation_strategies": [],
#                             "response_steps": []
#                         },
#                         "cba": {}
#                     }
#                 ]), 200

#             events = osint_data['events']
#             if not isinstance(events, list):
#                 logger.error("OSINT data 'events' is not a list.")
#                 return jsonify([
#                     {
#                         "log": "No threat logs available due to invalid events data",
#                         "response_plan": {
#                             "threat_type": "Other",
#                             "description": "No response plan available",
#                             "priority": "Low",
#                             "mitigation_strategies": [],
#                             "response_steps": []
#                         },
#                         "cba": {}
#                     }
#                 ]), 200

#             threat_descriptions = [event["description"] for event in events]
#             risk_scores = analyze_risk(threat_descriptions)

#             tva_mappings = [
#                 {'threat_name': tva.threat_name, 'likelihood': tva.likelihood, 'impact': tva.impact}
#                 for tva in TvaMapping.query.all()
#             ]

#             threats_with_metadata = []
#             for event, risk_score in zip(events, risk_scores):
#                 if event['description'] in last_processed_threats:
#                     continue  # Skip already processed threats
#                 last_processed_threats.add(event['description'])
#                 threat_entry = ThreatData.query.filter_by(description=event['description']).order_by(ThreatData.created_at.desc()).first()
#                 created_at = threat_entry.created_at if threat_entry else None
#                 threats_with_metadata.append({
#                     'description': event['description'],
#                     'threat_type': event['threat_type'],
#                     'risk_score': risk_score,
#                     'created_at': created_at
#                 })

#             prioritized_threats = risk_prioritizer.prioritize_threats(threats_with_metadata, tva_mappings)
#             threat_logs = []

#             for threat in prioritized_threats[:10]:  # Limit to 10 to prevent overload
#                 send_alert_if_high_risk(threat['description'], threat['risk_score'])
#                 response_plan = incident_responder.generate_response_plan(threat)
#                 # Log the response_plan for debugging
#                 logger.info(f"Generated response_plan for threat {threat['description']}: {response_plan}")
#                 # Ensure response_plan has mitigation_strategies and response_steps as arrays
#                 if not isinstance(response_plan.get('mitigation_strategies'), list):
#                     logger.warning(f"mitigation_strategies is not a list for threat {threat['description']}: {response_plan.get('mitigation_strategies')}")
#                     response_plan['mitigation_strategies'] = []
#                 if not isinstance(response_plan.get('response_steps'), list):
#                     logger.warning(f"response_steps is not a list for threat {threat['description']}: {response_plan.get('response_steps')}")
#                     response_plan['response_steps'] = []
#                 cba_info = suggest_mitigation(threat['description'], threat['risk_score'])
#                 threat_logs.append({
#                     'log': f"{threat['description']} (Risk: {threat['risk_score']}, Priority: {threat['priority_score']:.2f})",
#                     'response_plan': response_plan,
#                     'cba': cba_info if cba_info else {}
#                 })

#             return jsonify(threat_logs if threat_logs else [
#                 {
#                     "log": "No threat logs available",
#                     "response_plan": {
#                         "threat_type": "Other",
#                         "description": "No response plan available",
#                         "priority": "Low",
#                         "mitigation_strategies": [],
#                         "response_steps": []
#                     },
#                     "cba": {}
#                 }
#             ]), 200
#         except Exception as e:
#             logger.error(f"Failed to fetch threat logs: {str(e)}")
#             return jsonify([
#                 {
#                     "log": "Hardcoded Threat Log 1",
#                     "response_plan": {
#                         "threat_type": "Other",
#                         "description": "Hardcoded response plan",
#                         "priority": "Low",
#                         "mitigation_strategies": [],
#                         "response_steps": []
#                     },
#                     "cba": {}
#                 },
#                 {
#                     "log": "Hardcoded Threat Log 2",
#                     "response_plan": {
#                         "threat_type": "Other",
#                         "description": "Hardcoded response plan",
#                         "priority": "Low",
#                         "mitigation_strategies": [],
#                         "response_steps": []
#                     },
#                     "cba": {}
#                 }
#             ]), 200

# @app.route('/api/risk-scores', methods=['GET'])
# def get_risk_scores():
#     try:
#         osint_data = get_threat_data("localhost:5002")
#         threat_descriptions = [event["description"] for event in osint_data.get("events", [])]
#         risk_scores = analyze_risk(threat_descriptions)
#         return jsonify(risk_scores if risk_scores else [50, 75, 90]), 200
#     except Exception as e:
#         logger.error(f"Failed to fetch risk scores: {str(e)}")
#         return jsonify([50, 75, 90]), 200

# @app.route('/api/real-time-alerts', methods=['GET'])
# def get_real_time_alerts():
#     try:
#         alerts = AlertLog.query.filter(AlertLog.created_at >= datetime.now() - timedelta(hours=24)).all()
#         real_time_alerts = [
#             {
#                 'alert': f"{alert.threat} (Risk: {alert.risk_score}, Type: {alert.alert_type})",
#                 'response_plan': incident_responder.generate_response_plan({
#                     'description': alert.threat,
#                     'risk_score': alert.risk_score,
#                     'threat_type': 'Other'
#                 })
#             } for alert in alerts
#         ]
#         # Ensure response_plan has mitigation_strategies and response_steps as arrays
#         for alert in real_time_alerts:
#             if not isinstance(alert['response_plan'].get('mitigation_strategies'), list):
#                 logger.warning(f"mitigation_strategies is not a list for alert {alert['alert']}: {alert['response_plan'].get('mitigation_strategies')}")
#                 alert['response_plan']['mitigation_strategies'] = []
#             if not isinstance(alert['response_plan'].get('response_steps'), list):
#                 logger.warning(f"response_steps is not a list for alert {alert['alert']}: {alert['response_plan'].get('response_steps')}")
#                 alert['response_plan']['response_steps'] = []
#         return jsonify(real_time_alerts if real_time_alerts else [
#             {
#                 "alert": "No real-time alerts available",
#                 "response_plan": {
#                     "threat_type": "Other",
#                     "description": "No response plan available",
#                     "priority": "Low",
#                     "mitigation_strategies": [],
#                     "response_steps": []
#                 }
#             }
#         ]), 200
#     except Exception as e:
#         logger.error(f"Failed to fetch real-time alerts: {str(e)}")
#         return jsonify([
#             {
#                 "alert": "Hardcoded Alert 1",
#                 "response_plan": {
#                     "threat_type": "Other",
#                     "description": "Hardcoded response plan",
#                     "priority": "Low",
#                     "mitigation_strategies": [],
#                     "response_steps": []
#                 }
#             },
#             {
#                 "alert": "Hardcoded Alert 2",
#                 "response_plan": {
#                     "threat_type": "Other",
#                     "description": "Hardcoded response plan",
#                     "priority": "Low",
#                     "mitigation_strategies": [],
#                     "response_steps": []
#                 }
#             }
#         ]), 200

# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=5002)
#     logger.info("Application is running on port 5002")


# # src/api/app.py (at the top)
# import importlib
# import api.spiderfoot
# importlib.reload(api.spiderfoot)

# # src/api/app.py
# from flask import Flask, jsonify, request
# import logging
# from api.logger import logger
# from flask_sqlalchemy import SQLAlchemy
# from flask_migrate import Migrate
# from flask_cors import CORS
# from werkzeug.security import generate_password_hash, check_password_hash
# from api.models import db, User, TvaMapping, ThreatData, AlertLog
# from api.fetch_osint import fetch_osint_data
# from api.spiderfoot import fetch_spiderfoot_data
# from src.api.risk_analysis import analyze_risk
# from src.api.risk_prioritization import RiskPrioritizer
# from src.api.incident_response import IncidentResponder
# from api.alerts import send_alert_if_high_risk
# from api.cba_analysis import suggest_mitigation
# from api.api_optimizer import get_threat_data
# from datetime import datetime, timedelta
# from time import time
# import threading
# from api.models import db, Asset

# logging.basicConfig(level=logging.INFO)
# app = Flask(__name__)

# # Enable CORS for frontend
# CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://shopsmart:123456789@localhost:5432/shopsmart'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# db.init_app(app)
# migrate = Migrate(app, db)

# risk_prioritizer = RiskPrioritizer()
# incident_responder = IncidentResponder()
# lock = threading.Lock()

# with app.app_context():
#     db.create_all()

# @app.route('/api/register', methods=['POST'])
# def register():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')
#     if not username or not password:
#         return jsonify({"error": "Username and password are required"}), 400
#     if User.query.filter_by(username=username).first():
#         return jsonify({"error": "Username already exists"}), 400
#     hashed_password = generate_password_hash(password)
#     new_user = User(username=username, password_hash=hashed_password)
#     try:
#         db.session.add(new_user)
#         db.session.commit()
#         return jsonify({"message": "User registered successfully"}), 201
#     except Exception as e:
#         db.session.rollback()
#         logger.error(f"Failed to register user: {str(e)}")
#         return jsonify({"error": str(e)}), 400

# @app.route('/api/login', methods=['POST'])
# def login():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')
#     if not username or not password:
#         return jsonify({"error": "Username and password are required"}), 400
#     user = User.query.filter_by(username=username).first()
#     if user and check_password_hash(user.password_hash, password):
#         return jsonify({"message": "Login successful", "user_id": user.id, "username": user.username}), 200
#     else:
#         return jsonify({"error": "Invalid username or password"}), 401

# @app.route('/api/user/<int:user_id>', methods=['GET'])
# def get_user_details(user_id):
#     user = User.query.get(user_id)
#     if user:
#         return jsonify({"id": user.id, "username": user.username}), 200
#     else:
#         return jsonify({"error": "User not found"}), 404

# @app.route('/api/assets', methods=['GET'])
# def get_assets():
#     try:
#         assets = Asset.query.all()
#         assets_list = [
#             {
#                 "id": asset.id,
#                 "name": asset.name,
#                 "type": asset.type,
#                 "identifier": asset.identifier
#             }
#             for asset in assets
#         ]
#         logger.info(f"Fetched {len(assets_list)} assets")
#         return jsonify(assets_list), 200
#     except Exception as e:
#         logger.error(f"Failed to fetch assets: {str(e)}")
#         return jsonify({"error": str(e)}), 500

# @app.route('/api/spiderfoot/threat-logs', methods=['GET'])
# def get_threat_logs():
#     with lock:
#         try:
#             start_time = time()
#             query = request.args.get('query', 'localhost:5002')
#             osint_data = get_threat_data(query)
#             logger.info(f"get_threat_data for query '{query}' took {time() - start_time:.2f} seconds")
#             if not isinstance(osint_data, dict) or 'events' not in osint_data:
#                 logger.error(f"Invalid OSINT data structure: {osint_data}")
#                 raise ValueError("Invalid OSINT data structure received")
#             events = osint_data.get('events', [])
#             if not events:
#                 logger.warning("No events returned from SpiderFoot")
#                 events = [
#                     {
#                         "description": f"SpiderFoot failed for query '{query}'",
#                         "threat_type": "Error",
#                         "risk_score": 75
#                     }
#                 ]
#             threat_descriptions = [event.get("description", "Unknown") for event in events]
#             risk_scores = analyze_risk(threat_descriptions)
#             tva_mappings = [
#                 {'threat_name': tva.threat_name, 'likelihood': tva.likelihood, 'impact': tva.impact}
#                 for tva in TvaMapping.query.all()
#             ]
#             processed_threats = set()
#             threats_with_metadata = []
#             for event, risk_score in zip(events, risk_scores):
#                 desc = event.get('description', 'Unknown')
#                 if desc in processed_threats:
#                     continue
#                 processed_threats.add(desc)
#                 threat_entry = ThreatData.query.filter_by(description=desc).order_by(ThreatData.created_at.desc()).first()
#                 if not threat_entry:
#                     threat_entry = ThreatData(
#                         description=desc,
#                         threat_type=event.get('threat_type', 'Other'),
#                         risk_score=risk_score,
#                         created_at=datetime.utcnow()
#                     )
#                     db.session.add(threat_entry)
#                     created_at = datetime.utcnow()
#                     logger.info(f"Inserted new threat into threat_data: {desc}")
#                 else:
#                     created_at = threat_entry.created_at
#                 threats_with_metadata.append({
#                     'description': desc,
#                     'threat_type': event.get('threat_type', 'Other'),
#                     'risk_score': risk_score,
#                     'created_at': created_at
#                 })

#             prioritized_threats = risk_prioritizer.prioritize_threats(threats_with_metadata, tva_mappings)
#             threat_logs = []
#             for threat in prioritized_threats[:10]:
#                 send_alert_if_high_risk(threat['description'], threat['risk_score'], threat['threat_type'])
#                 response_plan = incident_responder.generate_response_plan(threat)
#                 cba_info = suggest_mitigation(threat['description'], threat['risk_score'])
#                 threat_logs.append({
#                     'log': f"{threat['description']} (Risk: {threat['risk_score']}, Priority: {threat['priority_score']:.2f})",
#                     'response_plan': response_plan,
#                     'cba': cba_info
#                 })
#             db.session.commit()  # Ensure alerts from send_alert_if_high_risk are committed
#             return jsonify(threat_logs), 200
#         except Exception as e:
#             logger.error(f"Failed to fetch threat logs: {str(e)}")
#             db.session.rollback()  # Rollback on error to avoid partial commits
#             return jsonify([{"log": f"Error: {str(e)}", "response_plan": {}}]), 500

# def get_threat_data(query, modules="sfp_spider,sfp_http"):
#     try:
#         spiderfoot_data = fetch_spiderfoot_data(query, modules=modules)
#         return spiderfoot_data
#     except Exception as e:
#         logger.error(f"Error in get_threat_data: {str(e)}")
#         return {
#             "events": [
#                 {
#                     "description": f"SpiderFoot failed for query '{query}'",
#                     "threat_type": "Error",
#                     "risk_score": 75
#                 }
#             ]
#         }

# @app.route('/api/risk-scores', methods=['GET'])
# def get_risk_scores():
#     try:
#         osint_data = get_threat_data("localhost:5002")
#         threat_descriptions = [event.get("description", "Unknown") for event in osint_data.get("events", [])]
#         risk_scores = analyze_risk(threat_descriptions)
#         return jsonify(risk_scores if risk_scores else [50, 75, 90])
#     except Exception as e:
#         logger.error(f"Failed to fetch risk scores: {str(e)}")
#         return jsonify([50, 75, 90]), 200

# @app.route('/api/real-time-alerts', methods=['GET'])
# def get_real_time_alerts():
#     try:
#         asset_name = request.args.get('query', '')
#         asset = Asset.query.filter_by(name=asset_name).first()
#         query = asset.identifier if asset and asset.identifier else asset_name
#         alerts = ThreatData.query.order_by(ThreatData.created_at.desc()).limit(10).all()
#         filtered_alerts = [
#             alert for alert in alerts
#             if query.lower() in alert.description.lower()
#         ]
#         alerts_list = [
#             {
#                 "alert": f"{alert.description} (Risk: {alert.risk_score}, Type: High Risk)",
#                 "response_plan": incident_responder.generate_response_plan({
#                     "description": alert.description,
#                     "risk_score": alert.risk_score,
#                     "threat_type": alert.threat_type
#                 })
#             }
#             for alert in filtered_alerts
#         ]
#         logger.info(f"Fetched {len(alerts_list)} real-time alerts for query '{query}'")
#         return jsonify(alerts_list), 200
#     except Exception as e:
#         logger.error(f"Failed to fetch real-time alerts: {str(e)}")
#         return jsonify([]), 200
    
# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=5002)
#     logger.info("Application is running on port 5002")


# # src/api/app.py (at the top)
# import importlib
# import api.spiderfoot
# importlib.reload(api.spiderfoot)

# # Add Hugging Face imports
# from transformers import pipeline

# # src/api/app.py
# from flask import Flask, jsonify, request
# import logging
# from api.logger import logger
# from flask_sqlalchemy import SQLAlchemy
# from flask_migrate import Migrate
# from flask_cors import CORS
# from werkzeug.security import generate_password_hash, check_password_hash
# from api.models import db, User, TvaMapping, ThreatData, AlertLog
# from api.fetch_osint import fetch_osint_data
# from api.spiderfoot import fetch_spiderfoot_data
# from src.api.risk_analysis import analyze_risk
# from src.api.risk_prioritization import RiskPrioritizer
# from src.api.incident_response import IncidentResponder
# from api.alerts import send_alert_if_high_risk
# from api.cba_analysis import suggest_mitigation
# from api.api_optimizer import get_threat_data
# from datetime import datetime, timedelta
# from time import time
# import threading
# from api.models import db, Asset

# logging.basicConfig(level=logging.INFO)
# app = Flask(__name__)

# # Enable CORS for frontend
# CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://shopsmart:123456789@localhost:5432/shopsmart'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# db.init_app(app)
# migrate = Migrate(app, db)

# risk_prioritizer = RiskPrioritizer()
# incident_responder = IncidentResponder()
# lock = threading.Lock()

# # Initialize the Hugging Face text generation pipeline
# generator = pipeline('text-generation', model='distilgpt2')

# with app.app_context():
#     db.create_all()

# @app.route('/api/register', methods=['POST'])
# def register():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')
#     if not username or not password:
#         return jsonify({"error": "Username and password are required"}), 400
#     if User.query.filter_by(username=username).first():
#         return jsonify({"error": "Username already exists"}), 400
#     hashed_password = generate_password_hash(password)
#     new_user = User(username=username, password_hash=hashed_password)
#     try:
#         db.session.add(new_user)
#         db.session.commit()
#         return jsonify({"message": "User registered successfully"}), 201
#     except Exception as e:
#         db.session.rollback()
#         logger.error(f"Failed to register user: {str(e)}")
#         return jsonify({"error": str(e)}), 400

# @app.route('/api/login', methods=['POST'])
# def login():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')
#     if not username or not password:
#         return jsonify({"error": "Username and password are required"}), 400
#     user = User.query.filter_by(username=username).first()
#     if user and check_password_hash(user.password_hash, password):
#         return jsonify({"message": "Login successful", "user_id": user.id, "username": user.username}), 200
#     else:
#         return jsonify({"error": "Invalid username or password"}), 401

# @app.route('/api/user/<int:user_id>', methods=['GET'])
# def get_user_details(user_id):
#     user = User.query.get(user_id)
#     if user:
#         return jsonify({"id": user.id, "username": user.username}), 200
#     else:
#         return jsonify({"error": "User not found"}), 404

# @app.route('/api/assets', methods=['GET'])
# def get_assets():
#     try:
#         assets = Asset.query.all()
#         assets_list = [
#             {
#                 "id": asset.id,
#                 "name": asset.name,
#                 "type": asset.type,
#                 "identifier": asset.identifier
#             }
#             for asset in assets
#         ]
#         logger.info(f"Fetched {len(assets_list)} assets")
#         return jsonify(assets_list), 200
#     except Exception as e:
#         logger.error(f"Failed to fetch assets: {str(e)}")
#         return jsonify({"error": str(e)}), 500

# @app.route('/api/spiderfoot/threat-logs', methods=['GET'])
# def get_threat_logs():
#     with lock:
#         try:
#             start_time = time()
#             query = request.args.get('query', 'localhost:5002')
#             osint_data = get_threat_data(query)
#             logger.info(f"get_threat_data for query '{query}' took {time() - start_time:.2f} seconds")
#             if not isinstance(osint_data, dict) or 'events' not in osint_data:
#                 logger.error(f"Invalid OSINT data structure: {osint_data}")
#                 raise ValueError("Invalid OSINT data structure received")
#             events = osint_data.get('events', [])
#             if not events:
#                 logger.warning("No events returned from SpiderFoot")
#                 events = [
#                     {
#                         "description": f"SpiderFoot failed for query '{query}'",
#                         "threat_type": "Error",
#                         "risk_score": 75
#                     }
#                 ]
#             threat_descriptions = [event.get("description", "Unknown") for event in events]
#             risk_scores = analyze_risk(threat_descriptions)
#             tva_mappings = [
#                 {'threat_name': tva.threat_name, 'likelihood': tva.likelihood, 'impact': tva.impact}
#                 for tva in TvaMapping.query.all()
#             ]
#             processed_threats = set()
#             threats_with_metadata = []
#             for event, risk_score in zip(events, risk_scores):
#                 desc = event.get('description', 'Unknown')
#                 if desc in processed_threats:
#                     continue
#                 processed_threats.add(desc)
#                 threat_entry = ThreatData.query.filter_by(description=desc).order_by(ThreatData.created_at.desc()).first()
#                 if not threat_entry:
#                     threat_entry = ThreatData(
#                         description=desc,
#                         threat_type=event.get('threat_type', 'Other'),
#                         risk_score=risk_score,
#                         created_at=datetime.utcnow()
#                     )
#                     db.session.add(threat_entry)
#                     created_at = datetime.utcnow()
#                     logger.info(f"Inserted new threat into threat_data: {desc}")
#                 else:
#                     created_at = threat_entry.created_at
#                 threats_with_metadata.append({
#                     'description': desc,
#                     'threat_type': event.get('threat_type', 'Other'),
#                     'risk_score': risk_score,
#                     'created_at': created_at
#                 })

#             prioritized_threats = risk_prioritizer.prioritize_threats(threats_with_metadata, tva_mappings)
#             threat_logs = []
#             for threat in prioritized_threats[:10]:
#                 try:
#                     send_alert_if_high_risk(threat['description'], threat['risk_score'], threat['threat_type'])
#                     logger.info(f"Sent alert for threat: {threat['description']} (Risk: {threat['risk_score']})")
#                 except Exception as e:
#                     logger.error(f"Failed to send alert for threat {threat['description']}: {str(e)}")
#                 response_plan = incident_responder.generate_response_plan(threat)
#                 cba_info = suggest_mitigation(threat['description'], threat['risk_score'])
#                 threat_logs.append({
#                     'log': f"{threat['description']} (Risk: {threat['risk_score']}, Priority: {threat['priority_score']:.2f})",
#                     'response_plan': response_plan,
#                     'cba': cba_info
#                 })
#             db.session.commit()
#             return jsonify(threat_logs), 200
#         except Exception as e:
#             logger.error(f"Failed to fetch threat logs: {str(e)}")
#             db.session.rollback()
#             return jsonify([{"log": f"Error: {str(e)}", "response_plan": {}}]), 500

# def get_threat_data(query, modules="sfp_spider,sfp_http"):
#     try:
#         spiderfoot_data = fetch_spiderfoot_data(query, modules=modules)
#         return spiderfoot_data
#     except Exception as e:
#         logger.error(f"Error in get_threat_data: {str(e)}")
#         return {
#             "events": [
#                 {
#                     "description": f"SpiderFoot failed for query '{query}'",
#                     "threat_type": "Error",
#                     "risk_score": 75
#                 }
#             ]
#         }

# @app.route('/api/risk-scores', methods=['GET'])
# def get_risk_scores():
#     try:
#         osint_data = get_threat_data("localhost:5002")
#         threat_descriptions = [event.get("description", "Unknown") for event in osint_data.get("events", [])]
#         risk_scores = analyze_risk(threat_descriptions)
#         return jsonify(risk_scores if risk_scores else [50, 75, 90])
#     except Exception as e:
#         logger.error(f"Failed to fetch risk scores: {str(e)}")
#         return jsonify([50, 75, 90]), 200

# @app.route('/api/real-time-alerts', methods=['GET'])
# def get_real_time_alerts():
#     try:
#         asset_name = request.args.get('query', '')
#         asset = Asset.query.filter_by(name=asset_name).first()
#         query = asset.identifier if asset and asset.identifier else asset_name
#         alerts = ThreatData.query.order_by(ThreatData.created_at.desc()).limit(10).all()
#         filtered_alerts = [
#             alert for alert in alerts
#             if query.lower() in alert.description.lower()
#         ]
#         alerts_list = []
#         for alert in filtered_alerts:
#             try:
#                 # Prepare prompt for mitigation strategies
#                 mitigation_prompt = (
#                     f"Generate mitigation strategies for a cybersecurity threat: "
#                     f"Description: {alert.description}, Threat Type: {alert.threat_type}, Risk Score: {alert.risk_score}. "
#                     f"Provide a list of strategies."
#                 )
#                 mitigation_response = generator(mitigation_prompt, max_length=50, num_return_sequences=1)[0]['generated_text']
#                 mitigation_strategies = mitigation_response.split('\n')[:3]  # Take first 3 lines as strategies

#                 # Prepare prompt for response steps
#                 response_prompt = (
#                     f"Generate response steps for a cybersecurity threat: "
#                     f"Description: {alert.description}, Threat Type: {alert.threat_type}, Risk Score: {alert.risk_score}. "
#                     f"Provide a list of steps."
#                 )
#                 response_response = generator(response_prompt, max_length=50, num_return_sequences=1)[0]['generated_text']
#                 response_steps = response_response.split('\n')[:3]  # Take first 3 lines as steps

#                 # Construct response plan using existing structure
#                 response_plan = {
#                     "threat_type": alert.threat_type,
#                     "description": alert.description,
#                     "mitigation_strategies": mitigation_strategies,
#                     "response_steps": response_steps
#                 }
#             except Exception as e:
#                 logger.error(f"Failed to generate response plan for alert {alert.description}: {str(e)}")
#                 response_plan = {
#                     "threat_type": alert.threat_type,
#                     "description": alert.description,
#                     "mitigation_strategies": ["Unable to generate strategies due to error"],
#                     "response_steps": ["Unable to generate steps due to error"]
#                 }
#             alerts_list.append({
#                 "alert": f"{alert.description} (Risk: {alert.risk_score}, Type: High Risk)",
#                 "response_plan": response_plan
#             })
#         logger.info(f"Fetched {len(alerts_list)} real-time alerts for query '{query}'")
#         return jsonify(alerts_list), 200
#     except Exception as e:
#         logger.error(f"Failed to fetch real-time alerts: {str(e)}")
#         db.session.rollback()  # Ensure session is cleaned up on error
#         return jsonify([]), 200


# # src/api/app.py (at the top)
# import importlib
# import api.spiderfoot
# importlib.reload(api.spiderfoot)

# # Add Hugging Face imports
# from transformers import pipeline

# # src/api/app.py
# from flask import Flask, jsonify, request
# import logging
# from api.logger import logger
# from flask_sqlalchemy import SQLAlchemy
# from flask_migrate import Migrate
# from flask_cors import CORS
# from werkzeug.security import generate_password_hash, check_password_hash
# from api.models import db, User, TvaMapping, ThreatData, AlertLog
# from api.fetch_osint import fetch_osint_data
# from api.spiderfoot import fetch_spiderfoot_data
# from src.api.risk_analysis import analyze_risk
# from src.api.risk_prioritization import RiskPrioritizer
# from src.api.incident_response import IncidentResponder
# from api.alerts import send_alert_if_high_risk
# from api.cba_analysis import suggest_mitigation
# from api.api_optimizer import get_threat_data
# from datetime import datetime, timedelta
# from time import time
# import threading
# from api.models import db, Asset

# logging.basicConfig(level=logging.INFO)
# app = Flask(__name__)

# # Enable CORS for frontend
# CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://shopsmart:123456789@localhost:5432/shopsmart'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# db.init_app(app)
# migrate = Migrate(app, db)

# risk_prioritizer = RiskPrioritizer()
# incident_responder = IncidentResponder()
# lock = threading.Lock()

# # Initialize the Hugging Face text generation pipeline
# generator = pipeline('text-generation', model='distilgpt2')

# with app.app_context():
#     db.create_all()

# @app.route('/api/register', methods=['POST'])
# def register():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')
#     if not username or not password:
#         return jsonify({"error": "Username and password are required"}), 400
#     if User.query.filter_by(username=username).first():
#         return jsonify({"error": "Username already exists"}), 400
#     hashed_password = generate_password_hash(password)
#     new_user = User(username=username, password_hash=hashed_password)
#     try:
#         db.session.add(new_user)
#         db.session.commit()
#         return jsonify({"message": "User registered successfully"}), 201
#     except Exception as e:
#         db.session.rollback()
#         logger.error(f"Failed to register user: {str(e)}")
#         return jsonify({"error": str(e)}), 400

# @app.route('/api/login', methods=['POST'])
# def login():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')
#     if not username or not password:
#         return jsonify({"error": "Username and password are required"}), 400
#     user = User.query.filter_by(username=username).first()
#     if user and check_password_hash(user.password_hash, password):
#         return jsonify({"message": "Login successful", "user_id": user.id, "username": user.username}), 200
#     else:
#         return jsonify({"error": "Invalid username or password"}), 401

# @app.route('/api/user/<int:user_id>', methods=['GET'])
# def get_user_details(user_id):
#     user = User.query.get(user_id)
#     if user:
#         return jsonify({"id": user.id, "username": user.username}), 200
#     else:
#         return jsonify({"error": "User not found"}), 404

# @app.route('/api/assets', methods=['GET'])
# def get_assets():
#     try:
#         assets = Asset.query.all()
#         assets_list = [
#             {
#                 "id": asset.id,
#                 "name": asset.name,
#                 "type": asset.type,
#                 "identifier": asset.identifier
#             }
#             for asset in assets
#         ]
#         logger.info(f"Fetched {len(assets_list)} assets")
#         return jsonify(assets_list), 200
#     except Exception as e:
#         logger.error(f"Failed to fetch assets: {str(e)}")
#         return jsonify({"error": str(e)}), 500

# @app.route('/api/spiderfoot/threat-logs', methods=['GET'])
# def get_threat_logs():
#     with lock:
#         try:
#             logger.info("Starting SpiderFoot threat logs fetch")
#             start_time = time()
#             query = request.args.get('query', 'localhost:5002')
#             osint_data = get_threat_data(query)
#             logger.info(f"get_threat_data for query '{query}' took {time() - start_time:.2f} seconds")
#             if not isinstance(osint_data, dict) or 'events' not in osint_data:
#                 logger.error(f"Invalid OSINT data structure: {osint_data}")
#                 raise ValueError("Invalid OSINT data structure received")
#             events = osint_data.get('events', [])
#             if not events:
#                 logger.warning("No events returned from SpiderFoot")
#                 events = [
#                     {
#                         "description": f"SpiderFoot failed for query '{query}'",
#                         "threat_type": "Error",
#                         "risk_score": 75
#                     }
#                 ]
#             threat_descriptions = [event.get("description", "Unknown") for event in events]
#             risk_scores = analyze_risk(threat_descriptions)
#             tva_mappings = [
#                 {'threat_name': tva.threat_name, 'likelihood': tva.likelihood, 'impact': tva.impact}
#                 for tva in TvaMapping.query.all()
#             ]
#             processed_threats = set()
#             threats_with_metadata = []
#             for event, risk_score in zip(events, risk_scores):
#                 desc = event.get('description', 'Unknown')
#                 if desc in processed_threats:
#                     continue
#                 processed_threats.add(desc)
#                 threat_entry = ThreatData.query.filter_by(description=desc).order_by(ThreatData.created_at.desc()).first()
#                 if not threat_entry:
#                     threat_entry = ThreatData(
#                         description=desc,
#                         threat_type=event.get('threat_type', 'Other'),
#                         risk_score=risk_score,
#                         created_at=datetime.utcnow()
#                     )
#                     db.session.add(threat_entry)
#                     created_at = datetime.utcnow()
#                     logger.info(f"Inserted new threat into threat_data: {desc}")
#                 else:
#                     created_at = threat_entry.created_at
#                 threats_with_metadata.append({
#                     'description': desc,
#                     'threat_type': event.get('threat_type', 'Other'),
#                     'risk_score': risk_score,
#                     'created_at': created_at
#                 })

#             prioritized_threats = risk_prioritizer.prioritize_threats(threats_with_metadata, tva_mappings)
#             threat_logs = []
#             for threat in prioritized_threats[:10]:
#                 try:
#                     send_alert_if_high_risk(threat['description'], threat['risk_score'], threat['threat_type'])
#                     logger.info(f"Sent alert for threat: {threat['description']} (Risk: {threat['risk_score']})")
#                 except Exception as e:
#                     logger.error(f"Failed to send alert for threat {threat['description']}: {str(e)}")
#                 response_plan = incident_responder.generate_response_plan(threat)
#                 cba_info = suggest_mitigation(threat['description'], threat['risk_score'])
#                 threat_logs.append({
#                     'log': f"{threat['description']} (Risk: {threat['risk_score']}, Priority: {threat['priority_score']:.2f})",
#                     'response_plan': response_plan,
#                     'cba': cba_info
#                 })
#             db.session.commit()
#             logger.info(f"Committed {len(prioritized_threats)} threats to threat_data")
#             logger.info("Completed SpiderFoot threat logs fetch")
#             return jsonify(threat_logs), 200
#         except Exception as e:
#             logger.error(f"Failed to fetch threat logs: {str(e)}")
#             db.session.rollback()
#             return jsonify([{"log": f"Error: {str(e)}", "response_plan": {}}]), 500

# def get_threat_data(query, modules="sfp_spider,sfp_http"):
#     try:
#         spiderfoot_data = fetch_spiderfoot_data(query, modules=modules)
#         return spiderfoot_data
#     except Exception as e:
#         logger.error(f"Error in get_threat_data: {str(e)}")
#         return {
#             "events": [
#                 {
#                     "description": f"SpiderFoot failed for query '{query}'",
#                     "threat_type": "Error",
#                     "risk_score": 75
#                 }
#             ]
#         }

# @app.route('/api/risk-scores', methods=['GET'])
# def get_risk_scores():
#     try:
#         osint_data = get_threat_data("localhost:5002")
#         threat_descriptions = [event.get("description", "Unknown") for event in osint_data.get("events", [])]
#         risk_scores = analyze_risk(threat_descriptions)
#         return jsonify(risk_scores if risk_scores else [50, 75, 90])
#     except Exception as e:
#         logger.error(f"Failed to fetch risk scores: {str(e)}")
#         return jsonify([50, 75, 90]), 200

# @app.route('/api/real-time-alerts', methods=['GET'])
# def get_real_time_alerts():
#     try:
#         logger.info("Starting real-time alerts fetch")
#         asset_name = request.args.get('query', '')
#         asset = Asset.query.filter_by(name=asset_name).first()
#         query = asset.identifier if asset and asset.identifier else asset_name
#         logger.info(f"Fetching real-time alerts for query: '{query}'")
#         alerts = ThreatData.query.order_by(ThreatData.created_at.desc()).limit(10).all()
#         logger.info(f"Fetched {len(alerts)} alerts from threat_data table")

#         # Relaxed filtering: If query doesn't match, return all alerts
#         filtered_alerts = [
#             alert for alert in alerts
#             if query.lower() in alert.description.lower()
#         ]
#         if not filtered_alerts:
#             logger.warning(f"No alerts matched query '{query}', returning all alerts")
#             filtered_alerts = alerts

#         logger.info(f"Filtered {len(filtered_alerts)} alerts after applying query filter")

#         alerts_list = []
#         for alert in filtered_alerts:
#             try:
#                 # Prepare prompt for mitigation strategies
#                 mitigation_prompt = (
#                     f"Generate mitigation strategies for a cybersecurity threat: "
#                     f"Description: {alert.description}, Threat Type: {alert.threat_type}, Risk Score: {alert.risk_score}. "
#                     f"Provide a list of strategies."
#                 )
#                 mitigation_response = generator(mitigation_prompt, max_length=50, num_return_sequences=1)[0]['generated_text']
#                 mitigation_strategies = mitigation_response.split('\n')[:3]  # Take first 3 lines as strategies

#                 # Prepare prompt for response steps
#                 response_prompt = (
#                     f"Generate response steps for a cybersecurity threat: "
#                     f"Description: {alert.description}, Threat Type: {alert.threat_type}, Risk Score: {alert.risk_score}. "
#                     f"Provide a list of steps."
#                 )
#                 response_response = generator(response_prompt, max_length=50, num_return_sequences=1)[0]['generated_text']
#                 response_steps = response_response.split('\n')[:3]  # Take first 3 lines as steps

#                 # Construct response plan using existing structure
#                 response_plan = {
#                     "threat_type": alert.threat_type,
#                     "description": alert.description,
#                     "mitigation_strategies": mitigation_strategies,
#                     "response_steps": response_steps
#                 }
#             except Exception as e:
#                 logger.error(f"Failed to generate response plan for alert {alert.description}: {str(e)}")
#                 response_plan = {
#                     "threat_type": alert.threat_type,
#                     "description": alert.description,
#                     "mitigation_strategies": ["Unable to generate strategies due to error"],
#                     "response_steps": ["Unable to generate steps due to error"]
#                 }
#             alerts_list.append({
#                 "alert": f"{alert.description} (Risk: {alert.risk_score}, Type: High Risk)",
#                 "response_plan": response_plan
#             })
#         logger.info(f"Returning {len(alerts_list)} real-time alerts for query '{query}'")
#         return jsonify(alerts_list), 200
#     except Exception as e:
#         logger.error(f"Failed to fetch real-time alerts: {str(e)}")
#         db.session.rollback()
#         return jsonify([]), 200


# # src/api/app.py (at the top)
# import importlib
# import api.spiderfoot
# importlib.reload(api.spiderfoot)

# # Add Hugging Face imports
# from transformers import pipeline

# # src/api/app.py
# from flask import Flask, jsonify, request
# import logging
# from api.logger import logger
# from flask_sqlalchemy import SQLAlchemy
# from flask_migrate import Migrate
# from flask_cors import CORS
# from werkzeug.security import generate_password_hash, check_password_hash
# from api.models import db, User, TvaMapping, ThreatData, AlertLog
# from api.fetch_osint import fetch_osint_data
# from api.spiderfoot import fetch_spiderfoot_data
# from src.api.risk_analysis import analyze_risk
# from src.api.risk_prioritization import RiskPrioritizer
# from src.api.incident_response import IncidentResponder
# from api.alerts import send_alert_if_high_risk
# from api.cba_analysis import suggest_mitigation
# from api.api_optimizer import get_threat_data
# from datetime import datetime, timedelta
# from time import time
# import threading
# from api.models import db, Asset
# import random  # For fallback variability

# logging.basicConfig(level=logging.INFO)
# app = Flask(__name__)

# # Enable CORS for frontend
# CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://shopsmart:123456789@localhost:5432/shopsmart'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# db.init_app(app)
# migrate = Migrate(app, db)

# risk_prioritizer = RiskPrioritizer()
# incident_responder = IncidentResponder()
# lock = threading.Lock()

# # Initialize the Hugging Face text generation pipeline
# generator = pipeline('text-generation', model='distilgpt2')

# with app.app_context():
#     db.create_all()

# @app.route('/api/register', methods=['POST'])
# def register():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')
#     if not username or not password:
#         return jsonify({"error": "Username and password are required"}), 400
#     if User.query.filter_by(username=username).first():
#         return jsonify({"error": "Username already exists"}), 400
#     hashed_password = generate_password_hash(password)
#     new_user = User(username=username, password_hash=hashed_password)
#     try:
#         db.session.add(new_user)
#         db.session.commit()
#         return jsonify({"message": "User registered successfully"}), 201
#     except Exception as e:
#         db.session.rollback()
#         logger.error(f"Failed to register user: {str(e)}")
#         return jsonify({"error": str(e)}), 400

# @app.route('/api/login', methods=['POST'])
# def login():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')
#     if not username or not password:
#         return jsonify({"error": "Username and password are required"}), 400
#     user = User.query.filter_by(username=username).first()
#     if user and check_password_hash(user.password_hash, password):
#         return jsonify({"message": "Login successful", "user_id": user.id, "username": user.username}), 200
#     else:
#         return jsonify({"error": "Invalid username or password"}), 401

# @app.route('/api/user/<int:user_id>', methods=['GET'])
# def get_user_details(user_id):
#     user = User.query.get(user_id)
#     if user:
#         return jsonify({"id": user.id, "username": user.username}), 200
#     else:
#         return jsonify({"error": "User not found"}), 404

# @app.route('/api/assets', methods=['GET'])
# def get_assets():
#     try:
#         assets = Asset.query.all()
#         assets_list = [
#             {
#                 "id": asset.id,
#                 "name": asset.name,
#                 "type": asset.type,
#                 "identifier": asset.identifier
#             }
#             for asset in assets
#         ]
#         logger.info(f"Fetched {len(assets_list)} assets")
#         return jsonify(assets_list), 200
#     except Exception as e:
#         logger.error(f"Failed to fetch assets: {str(e)}")
#         return jsonify({"error": str(e)}), 500

# @app.route('/api/spiderfoot/threat-logs', methods=['GET'])
# def get_threat_logs():
#     with lock:
#         try:
#             logger.info("Starting SpiderFoot threat logs fetch")
#             start_time = time()
#             query = request.args.get('query', 'localhost:5002')
#             osint_data = get_threat_data(query)
#             logger.info(f"get_threat_data for query '{query}' took {time() - start_time:.2f} seconds")
#             if not isinstance(osint_data, dict) or 'events' not in osint_data:
#                 logger.error(f"Invalid OSINT data structure: {osint_data}")
#                 raise ValueError("Invalid OSINT data structure received")
#             events = osint_data.get('events', [])
#             if not events:
#                 logger.warning("No events returned from SpiderFoot")
#                 events = [
#                     {
#                         "description": f"SpiderFoot failed for query '{query}'",
#                         "threat_type": "Error",
#                         "risk_score": 75
#                     }
#                 ]

#             # Use the risk_score from events if available, otherwise calculate with analyze_risk
#             threats_with_metadata = []
#             processed_threats = set()
#             for event in events:
#                 desc = event.get('description', 'Unknown')
#                 if desc in processed_threats:
#                     continue
#                 processed_threats.add(desc)

#                 risk_score = event.get('risk_score')
#                 if risk_score is None:
#                     threat_descriptions = [desc]
#                     risk_scores = analyze_risk(threat_descriptions)
#                     risk_score = risk_scores[0] if risk_scores else 50
#                     logger.info(f"Calculated risk score for '{desc}': {risk_score}")
#                 else:
#                     logger.info(f"Using pre-assigned risk score for '{desc}': {risk_score}")

#                 threat_entry = ThreatData.query.filter_by(description=desc).order_by(ThreatData.created_at.desc()).first()
#                 if not threat_entry:
#                     threat_entry = ThreatData(
#                         description=desc,
#                         threat_type=event.get('threat_type', 'Other'),
#                         risk_score=risk_score,
#                         created_at=datetime.utcnow()
#                     )
#                     db.session.add(threat_entry)
#                     created_at = datetime.utcnow()
#                     logger.info(f"Inserted new threat into threat_data: {desc} with risk_score: {risk_score}")
#                 else:
#                     created_at = threat_entry.created_at

#                 threats_with_metadata.append({
#                     'description': desc,
#                     'threat_type': event.get('threat_type', 'Other'),
#                     'risk_score': risk_score,
#                     'created_at': created_at
#                 })

#             tva_mappings = [
#                 {'threat_name': tva.threat_name, 'likelihood': tva.likelihood, 'impact': tva.impact}
#                 for tva in TvaMapping.query.all()
#             ]

#             prioritized_threats = risk_prioritizer.prioritize_threats(threats_with_metadata, tva_mappings)
#             threat_logs = []
#             for threat in prioritized_threats[:10]:
#                 try:
#                     send_alert_if_high_risk(threat['description'], threat['risk_score'], threat['threat_type'])
#                     logger.info(f"Sent alert for threat: {threat['description']} (Risk: {threat['risk_score']})")
#                 except Exception as e:
#                     logger.error(f"Failed to send alert for threat {threat['description']}: {str(e)}")
#                 response_plan = incident_responder.generate_response_plan(threat)
#                 cba_info = suggest_mitigation(threat['description'], threat['risk_score'])
#                 threat_logs.append({
#                     'log': f"{threat['description']} (Risk: {threat['risk_score']}, Priority: {threat['priority_score']:.2f})",
#                     'response_plan': response_plan,
#                     'cba': cba_info
#                 })
#             db.session.commit()
#             logger.info(f"Committed {len(prioritized_threats)} threats to threat_data")
#             logger.info("Completed SpiderFoot threat logs fetch")
#             return jsonify(threat_logs), 200
#         except Exception as e:
#             logger.error(f"Failed to fetch threat logs: {str(e)}")
#             db.session.rollback()
#             return jsonify([{"log": f"Error: {str(e)}", "response_plan": {}}]), 500

# def get_threat_data(query, modules="sfp_spider,sfp_http"):
#     try:
#         spiderfoot_data = fetch_spiderfoot_data(query, modules=modules)
#         return spiderfoot_data
#     except Exception as e:
#         logger.error(f"Error in get_threat_data: {str(e)}")
#         base_risk_score = 75
#         query_hash = sum(ord(c) for c in query) % 20
#         varied_risk_score = min(max(base_risk_score + query_hash - 10, 50), 90)
#         logger.info(f"Generated varied risk score for query '{query}': {varied_risk_score}")
#         return {
#             "events": [
#                 {
#                     "description": f"SpiderFoot failed for query '{query}'",
#                     "threat_type": "Error",
#                     "risk_score": varied_risk_score
#                 }
#             ]
#         }

# @app.route('/api/risk-scores', methods=['GET'])
# def get_risk_scores():
#     try:
#         query = request.args.get('query')
#         if not query:
#             logger.warning("No query parameter provided in /api/risk-scores request. Using fallback with variability.")
#             # Fallback: Generate a pseudo-query based on a random asset or default
#             assets = Asset.query.all()
#             if assets:
#                 query = random.choice([asset.name for asset in assets])
#                 logger.info(f"Selected random asset for query: '{query}'")
#             else:
#                 query = f"fallback-asset-{random.randint(1, 100)}"
#                 logger.info(f"No assets found, using generated query: '{query}'")

#         logger.info(f"Fetching risk scores for query: '{query}'")

#         # Fetch risk scores from threat_data table
#         threats = ThreatData.query.filter(ThreatData.description.ilike(f"%{query}%")).order_by(ThreatData.created_at.desc()).limit(10).all()
#         if threats:
#             risk_scores = [threat.risk_score for threat in threats]
#             logger.info(f"Fetched {len(risk_scores)} risk scores from threat_data for query '{query}': {risk_scores}")
#         else:
#             logger.info(f"No threats found in threat_data for query '{query}', falling back to get_threat_data")
#             osint_data = get_threat_data(query)
#             threat_descriptions = [event.get("description", "Unknown") for event in osint_data.get("events", [])]
#             risk_scores = [event.get("risk_score", 50) for event in osint_data.get("events", [])]
#             logger.info(f"Fetched {len(risk_scores)} risk scores from get_threat_data for query '{query}': {risk_scores}")

#         # Introduce additional variability based on query
#         query_hash = sum(ord(c) for c in query) % 10
#         risk_scores = [min(max(score + (query_hash - 5), 0), 100) for score in risk_scores]
#         logger.info(f"Adjusted risk scores with query-based variability for '{query}': {risk_scores}")

#         # Ensure at least 3 data points for graph visibility
#         if len(risk_scores) < 3:
#             logger.info(f"Padding risk scores from {len(risk_scores)} to 3 for graph display")
#             risk_scores.extend([50] * (3 - len(risk_scores)))

#         logger.info(f"Returning risk scores: {risk_scores}")
#         return jsonify(risk_scores)
#     except Exception as e:
#         logger.error(f"Failed to fetch risk scores: {str(e)}")
#         return jsonify([50, 75, 90]), 200

# @app.route('/api/real-time-alerts', methods=['GET'])
# def get_real_time_alerts():
#     try:
#         logger.info("Starting real-time alerts fetch")
#         asset_name = request.args.get('query', '')
#         asset = Asset.query.filter_by(name=asset_name).first()
#         query = asset.identifier if asset and asset.identifier else asset_name
#         logger.info(f"Fetching real-time alerts for query: '{query}'")
#         alerts = ThreatData.query.order_by(ThreatData.created_at.desc()).limit(10).all()
#         logger.info(f"Fetched {len(alerts)} alerts from threat_data table")

#         # Relaxed filtering: If query doesn't match, return all alerts
#         filtered_alerts = [
#             alert for alert in alerts
#             if query.lower() in alert.description.lower()
#         ]
#         if not filtered_alerts:
#             logger.warning(f"No alerts matched query '{query}', returning all alerts")
#             filtered_alerts = alerts

#         logger.info(f"Filtered {len(filtered_alerts)} alerts after applying query filter")

#         alerts_list = []
#         for alert in filtered_alerts:
#             try:
#                 mitigation_prompt = (
#                     f"Generate mitigation strategies for a cybersecurity threat: "
#                     f"Description: {alert.description}, Threat Type: {alert.threat_type}, Risk Score: {alert.risk_score}. "
#                     f"Provide a list of strategies."
#                 )
#                 mitigation_response = generator(mitigation_prompt, max_length=50, num_return_sequences=1)[0]['generated_text']
#                 mitigation_strategies = mitigation_response.split('\n')[:3]

#                 response_prompt = (
#                     f"Generate response steps for a cybersecurity threat: "
#                     f"Description: {alert.description}, Threat Type: {alert.threat_type}, Risk Score: {alert.risk_score}. "
#                     f"Provide a list of steps."
#                 )
#                 response_response = generator(response_prompt, max_length=50, num_return_sequences=1)[0]['generated_text']
#                 response_steps = response_response.split('\n')[:3]

#                 response_plan = {
#                     "threat_type": alert.threat_type,
#                     "description": alert.description,
#                     "mitigation_strategies": mitigation_strategies,
#                     "response_steps": response_steps
#                 }
#             except Exception as e:
#                 logger.error(f"Failed to generate response plan for alert {alert.description}: {str(e)}")
#                 response_plan = {
#                     "threat_type": alert.threat_type,
#                     "description": alert.description,
#                     "mitigation_strategies": ["Unable to generate strategies due to error"],
#                     "response_steps": ["Unable to generate steps due to error"]
#                 }
#             alerts_list.append({
#                 "alert": f"{alert.description} (Risk: {alert.risk_score}, Type: High Risk)",
#                 "response_plan": response_plan
#             })
#         logger.info(f"Returning {len(alerts_list)} real-time alerts for query '{query}'")
#         return jsonify(alerts_list), 200
#     except Exception as e:
#         logger.error(f"Failed to fetch real-time alerts: {str(e)}")
#         db.session.rollback()
#         return jsonify([]), 200
    
# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=5002)
#     logger.info("Application is running on port 5002")


# src/api/app.py
import importlib
import api.spiderfoot  # From api/ directory
importlib.reload(api.spiderfoot)

import os
import subprocess
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from api.models import db, User, TvaMapping, ThreatData, AlertLog  # From api/ directory
from api.fetch_osint import fetch_osint_data
from api.spiderfoot import fetch_spiderfoot_data
from src.api.risk_analysis import analyze_risk  # From src/api/
from src.api.risk_scoring import RiskScorer  # From src/api/
from src.api.risk_prioritization import RiskPrioritizer  # From src/api/
from src.api.incident_response import IncidentResponder  # From src/api/
from api.alerts import send_alert_if_high_risk  # From api/
from api.cba_analysis import suggest_mitigation  # From api/
from api.api_optimizer import get_threat_data  # From api/
from src.api.risk_generator import ThreatReportGenerator  # From src/api/
from datetime import datetime, timedelta
from time import time
import threading
from api.models import db, Asset
from transformers import pipeline
from src.api.custom_logging import setup_logger  # From src/api/, corrected import

app = Flask(__name__)

# Enable CORS for frontend
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://shopsmart:123456789@localhost:5432/shopsmart'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
migrate = Migrate(app, db)

# Setup logging with rotation
logger = setup_logger('app')

# Initialize LLM for zero-shot classification
try:
    llm_classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
    logger.info("Successfully initialized Hugging Face LLM for real-time alert analysis")
except Exception as e:
    logger.error(f"Failed to initialize LLM classifier: {str(e)}")
    llm_classifier = None

# Initialize text generation model
try:
    generator = pipeline("text-generation", model="gpt2")
    logger.info("Successfully initialized Hugging Face text generation model (gpt2)")
except Exception as e:
    logger.error(f"Failed to initialize text generation model: {str(e)}")
    generator = None

# Initialize risk scoring and other components
risk_scorer = RiskScorer()
risk_prioritizer = RiskPrioritizer()
incident_responder = IncidentResponder()
lock = threading.Lock()

# def backup_database():
#     backup_path = f"backups/shopsmart_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.sql"
#     os.makedirs('backups', exist_ok=True)
#     pg_dump_path = "/opt/homebrew/Cellar/postgresql@15/15.3/bin/pg_dump" if os.path.exists("/opt/homebrew/Cellar/postgresql@15/15.3/bin/pg_dump") else "pg_dump"
#     subprocess.run([pg_dump_path, "-U", "shopsmart", "shopsmart", "-f", backup_path], check=True)
#     logger.info(f"Database backed up to {backup_path}")

def generate_periodic_reports():
    logger.info("Starting periodic report generation thread")
    report_generator = ThreatReportGenerator()
    while True:
        try:
            logger.debug("Beginning report generation cycle")
            with app.app_context():  # Ensure Flask app context for database access
                # backup_database()
                report_path = report_generator.generate_pdf()
                logger.info(f"Periodic report generated: {report_path}")
        except Exception as e:
            logger.error(f"Periodic report generation failed: {str(e)}", exc_info=True)
        logger.debug("Sleeping for 1 hour")
        time.sleep(3600)  # 1 hour; use 60 for testing (1 minute)

# Start periodic reporting
logger.info("Launching report generation thread")
threading.Thread(target=generate_periodic_reports, daemon=True).start()

with app.app_context():
    db.create_all()

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 400
    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password_hash=hashed_password)
    try:
        db.session.add(new_user)
        db.session.commit()
        logger.info(f"User registered: {username}")
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to register user: {str(e)}")
        return jsonify({"error": str(e)}), 400

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        logger.info(f"User logged in: {username}")
        return jsonify({"message": "Login successful", "user_id": user.id, "username": user.username}), 200
    else:
        logger.warning(f"Failed login attempt for {username}")
        return jsonify({"error": "Invalid username or password"}), 401

@app.route('/api/user/<int:user_id>', methods=['GET'])
def get_user_details(user_id):
    user = User.query.get(user_id)
    if user:
        return jsonify({"id": user.id, "username": user.username}), 200
    else:
        logger.warning(f"User not found: {user_id}")
        return jsonify({"error": "User not found"}), 404

@app.route('/api/assets', methods=['GET'])
def get_assets():
    try:
        assets = Asset.query.all()
        assets_list = [
            {
                "id": asset.id,
                "name": asset.name,
                "type": asset.type,
                "identifier": asset.identifier
            }
            for asset in assets
        ]
        logger.info(f"Fetched {len(assets_list)} assets")
        return jsonify(assets_list), 200
    except Exception as e:
        logger.error(f"Failed to fetch assets: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/spiderfoot/threat-logs', methods=['GET'])
def get_threat_logs():
    with lock:
        try:
            start_time = time()
            query = request.args.get('query', 'localhost:5002')
            osint_data = get_threat_data(query)
            logger.info(f"get_threat_data for query '{query}' took {time() - start_time:.2f} seconds")
            if not isinstance(osint_data, dict) or 'events' not in osint_data:
                logger.error(f"Invalid OSINT data structure: {osint_data}")
                raise ValueError("Invalid OSINT data structure received")
            events = osint_data.get('events', [])
            if not events:
                logger.warning("No events returned from SpiderFoot")
                events = [
                    {
                        "description": f"SpiderFoot failed for query '{query}'",
                        "threat_type": "Error",
                        "risk_score": 75
                    }
                ]
            tva_mappings = [
                {'threat_name': tva.threat_name, 'likelihood': tva.likelihood, 'impact': tva.impact}
                for tva in TvaMapping.query.all()
            ]
            threats_for_scoring = [
                {
                    "description": event.get("description", "Unknown"),
                    "likelihood": next((tva["likelihood"] for tva in tva_mappings if tva["threat_name"] == event.get("threat_type", "Other")), 3),
                    "impact": next((tva["impact"] for tva in tva_mappings if tva["threat_name"] == event.get("threat_type", "Other")), 3),
                    "created_at": datetime.utcnow()
                }
                for event in events
            ]
            risk_scores = risk_scorer.analyze_risk(threats_for_scoring)
            processed_threats = set()
            threats_with_metadata = []
            for event, risk_score in zip(events, risk_scores):
                desc = event.get('description', 'Unknown')
                if desc in processed_threats:
                    continue
                processed_threats.add(desc)
                threat_entry = ThreatData.query.filter_by(description=desc).order_by(ThreatData.created_at.desc()).first()
                if not threat_entry:
                    threat_entry = ThreatData(
                        description=desc,
                        threat_type=event.get('threat_type', 'Other'),
                        risk_score=risk_score,
                        created_at=datetime.utcnow()
                    )
                    db.session.add(threat_entry)
                    created_at = datetime.utcnow()
                    logger.info(f"Inserted new threat into threat_data: {desc}")
                else:
                    created_at = threat_entry.created_at
                threats_with_metadata.append({
                    'description': desc,
                    'threat_type': event.get('threat_type', 'Other'),
                    'risk_score': risk_score,
                    'created_at': created_at
                })

            prioritized_threats = risk_prioritizer.prioritize_threats(threats_with_metadata, tva_mappings)
            threat_logs = []
            for threat in prioritized_threats[:10]:
                send_alert_if_high_risk(threat['description'], threat['risk_score'], threat['threat_type'])
                response_plan = incident_responder.generate_response_plan(threat)
                cba_info = suggest_mitigation(threat['description'], threat['risk_score'])
                threat_logs.append({
                    'log': f"{threat['description']} (Risk: {threat['risk_score']}, Priority: {threat['priority_score']:.2f})",
                    'response_plan': response_plan,
                    'cba': cba_info
                })
            db.session.commit()
            logger.info(f"Returning {len(threat_logs)} threat logs for query '{query}'")
            return jsonify(threat_logs), 200
        except Exception as e:
            logger.error(f"Failed to fetch threat logs: {str(e)}")
            db.session.rollback()
            return jsonify([{"log": f"Error: {str(e)}", "response_plan": {}}]), 500

def get_threat_data(query, modules="sfp_spider,sfp_http"):
    try:
        spiderfoot_data = fetch_spiderfoot_data(query, modules=modules)
        return spiderfoot_data
    except Exception as e:
        logger.error(f"Error in get_threat_data: {str(e)}")
        return {
            "events": [
                {
                    "description": f"SpiderFoot failed for query '{query}'",
                    "threat_type": "Error",
                    "risk_score": 75
                }
            ]
        }

@app.route('/api/risk-scores', methods=['GET'])
def get_risk_scores():
    try:
        query = request.args.get('query', 'localhost:5002')
        osint_data = get_threat_data(query)
        threats_for_scoring = [
            {
                "description": event.get("description", "Unknown"),
                "likelihood": 3,  # Default if no TVA mapping
                "impact": 3,
                "created_at": datetime.utcnow()
            }
            for event in osint_data.get("events", [])
        ]
        risk_scores = risk_scorer.analyze_risk(threats_for_scoring)
        logger.info(f"Risk scores for query '{query}': {risk_scores}")
        return jsonify(risk_scores), 200
    except Exception as e:
        logger.error(f"Failed to fetch risk scores: {str(e)}")
        return jsonify([50, 75, 90]), 200

@app.route('/api/real-time-alerts', methods=['GET'])
def get_real_time_alerts():
    try:
        logger.info("Starting real-time alerts fetch")
        asset_name = request.args.get('query', '')
        asset = Asset.query.filter_by(name=asset_name).first()
        query = asset.identifier if asset and asset.identifier else asset_name
        logger.info(f"Fetching real-time alerts for query: '{query}'")
        alerts = ThreatData.query.order_by(ThreatData.created_at.desc()).limit(10).all()
        logger.info(f"Fetched {len(alerts)} alerts from threat_data table")

        filtered_alerts = [
            alert for alert in alerts
            if query.lower() in alert.description.lower()
        ] if query else alerts
        if not filtered_alerts:
            logger.warning(f"No alerts matched query '{query}', returning all alerts")
            filtered_alerts = alerts

        alerts_list = []
        for alert in filtered_alerts:
            try:
                threat_info = {
                    "description": alert.description,
                    "risk_score": alert.risk_score,
                    "threat_type": alert.threat_type
                }
                base_response_plan = incident_responder.generate_response_plan(threat_info)

                mitigation_strategies = base_response_plan["mitigation_strategies"]
                response_steps = base_response_plan["response_steps"]
                if generator:
                    mitigation_prompt = (
                        f"Generate mitigation strategies for: {alert.description}, Type: {alert.threat_type}, Risk: {alert.risk_score}."
                    )
                    mitigation_response = generator(mitigation_prompt, max_length=100, num_return_sequences=1)[0]['generated_text']
                    mitigation_strategies = [s.strip() for s in mitigation_response.split('\n') if s.strip()][:3]

                    response_prompt = (
                        f"Generate response steps for: {alert.description}, Type: {alert.threat_type}, Risk: {alert.risk_score}."
                    )
                    response_response = generator(response_prompt, max_length=100, num_return_sequences=1)[0]['generated_text']
                    response_steps = [s.strip() for s in response_response.split('\n') if s.strip()][:3]

                llm_insights = {}
                if llm_classifier:
                    labels = ["Low Severity", "Medium Severity", "High Severity"]
                    result = llm_classifier(
                        alert.description,
                        candidate_labels=labels,
                        hypothesis_template="This alert indicates a {} threat."
                    )
                    llm_insights = {
                        "severity": result["labels"][0],
                        "confidence": round(result["scores"][0], 2),
                        "suggested_action": suggest_action(result["labels"][0])
                    }
                else:
                    llm_insights = {"severity": "Unknown", "confidence": 0, "suggested_action": "Manual review required"}

                response_plan = {
                    "threat_type": alert.threat_type,
                    "description": alert.description,
                    "priority": base_response_plan["priority"],
                    "mitigation_strategies": mitigation_strategies,
                    "response_steps": response_steps
                }

                alerts_list.append({
                    "alert": f"{alert.description} (Risk: {alert.risk_score}, Type: High Risk)",
                    "response_plan": response_plan,
                    "llm_insights": llm_insights
                })
            except Exception as e:
                logger.error(f"Failed to process alert {alert.description}: {str(e)}")
                response_plan = {
                    "threat_type": alert.threat_type,
                    "description": alert.description,
                    "priority": "Medium",
                    "mitigation_strategies": ["Unable to generate strategies due to error"],
                    "response_steps": ["Unable to generate steps due to error"]
                }
                alerts_list.append({
                    "alert": f"{alert.description} (Risk: {alert.risk_score}, Type: High Risk)",
                    "response_plan": response_plan,
                    "llm_insights": {"severity": "Unknown", "confidence": 0, "suggested_action": "Manual review required"}
                })
        logger.info(f"Returning {len(alerts_list)} real-time alerts for query '{query}'")
        return jsonify(alerts_list), 200
    except Exception as e:
        logger.error(f"Failed to fetch real-time alerts: {str(e)}")
        db.session.rollback()
        return jsonify([]), 200

# @app.route('/api/generate-report', methods=['GET'])
# def generate_report():
#     generator = ThreatReportGenerator()
#     format = request.args.get('format', 'pdf')
#     try:
#         if format == 'pdf':
#             path = generator.generate_pdf()
#         elif format == 'csv':
#             path = generator.generate_csv()
#         else:
#             return jsonify({"error": "Invalid format"}), 400
#         logger.info(f"Report generated successfully: {path}")
#         return jsonify({"message": "Report generated", "path": path}), 200
#     except Exception as e:
#         logger.error(f"Failed to generate report: {str(e)}")
#         return jsonify({"error": str(e)}), 500
@app.route('/api/generate-report', methods=['GET'])
def generate_report():
    # backup_database()
    generator = ThreatReportGenerator()
    format = request.args.get('format', 'pdf')
    try:
        if format == 'pdf':
            path = generator.generate_pdf()
        elif format == 'csv':
            path = generator.generate_csv()
        else:
            return jsonify({"error": "Invalid format"}), 400
        logger.info(f"Manual report generated: {path}")
        return jsonify({"message": "Report generated", "path": path}), 200
    except Exception as e:
        logger.error(f"Failed to generate report: {str(e)}")
        return jsonify({"error": str(e)}), 500

def suggest_action(severity):
    actions = {
        "Low Severity": "Monitor the situation and log for future reference.",
        "Medium Severity": "Investigate the alert and apply basic mitigation steps.",
        "High Severity": "Escalate immediately and initiate full incident response."
    }
    return actions.get(severity, "Manual review required")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5002)
    logger.info("Application is running on port 5002")