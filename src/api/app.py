# # src/api/app.py
# from flask import Flask, jsonify, request
# from flask_sqlalchemy import SQLAlchemy
# from api.virustotal import fetch_virustotal_data
# from api.hibp import check_email_breach
# from api.abuseipdb import check_ip_abuse

# app = Flask(__name__)

# # Configure the database connection
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://shopsmart:123456789@localhost:5432/shopsmart'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# db = SQLAlchemy(app)

# @app.route('/api/osint/virustotal', methods=['GET'])
# def get_virustotal_data():
#     url = request.args.get('url')
#     api_key = request.args.get('14f931f13f341ec0f9a2089984b43523a98dfa79689b8117e7449196afbdec9f')  # Pass your API key as a query parameter
#     if not url or not api_key:
#         return jsonify({"error": "URL and API key are required"}), 400
#     result = fetch_virustotal_data(api_key, url)
#     return jsonify(result)

# @app.route('/api/osint/hibp', methods=['GET'])
# def get_hibp_data():
#     email = request.args.get('email')
#     if not email:
#         return jsonify({"error": "Email is required"}), 400
#     breaches = check_email_breach(email)
#     return jsonify(breaches)

# @app.route('/api/osint/abuseipdb', methods=['GET'])
# def get_abuseipdb_data():
#     ip_address = request.args.get('ip_address')
#     api_key = request.args.get('c4e131e49721c5dd6cdb5e0660aaf2e972fae788f172b67b6122fa91f959d7223adc8d1251ed1e7d')  # Pass your API key as a query parameter
#     if not ip_address or not api_key:
#         return jsonify({"error": "IP address and API key are required"}), 400
#     result = check_ip_abuse(api_key, ip_address)
#     return jsonify(result)

# # New API endpoints for the dashboard
# @app.route('/api/threat-logs', methods=['GET'])
# def get_threat_logs():
#     # Replace with actual logic to fetch threat logs from your database or API
#     threat_logs = [
#         "Threat detected from IP 192.0.2.1",
#         "Malware found in file example.exe",
#         "Phishing attempt reported on example.com"
#     ]
#     return jsonify(threat_logs)

# @app.route('/api/risk-scores', methods=['GET'])
# def get_risk_scores():
#     # Replace with actual logic to fetch risk scores
#     risk_scores = [75, 85, 90]  # Example risk scores
#     return jsonify(risk_scores)

# @app.route('/api/real-time-alerts', methods=['GET'])
# def get_real_time_alerts():
#     # Replace with actual logic to fetch real-time alerts
#     real_time_alerts = [
#         "Alert: Suspicious login attempt detected.",
#         "Alert: New malware signature detected.",
#         "Alert: Unusual outbound traffic detected."
#     ]
#     return jsonify(real_time_alerts)

# @app.route('/api/osint', methods=['GET'])
# def osint_data():
#     return jsonify({"message": "OSINT data endpoint"})

# if __name__ == '__main__':
#     app.run(debug=True)



# # src/api/app.py
# from flask import Flask, jsonify, request
# from flask_sqlalchemy import SQLAlchemy
# from flask_cors import CORS  # Import Flask-CORS
# from api.virustotal import fetch_virustotal_data
# from api.hibp import check_email_breach
# from api.abuseipdb import check_ip_abuse

# app = Flask(__name__)
# CORS(app)  # Enable CORS for all routes

# # Configure the database connection
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://shopsmart:123456789@localhost:5432/shopsmart'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# db = SQLAlchemy(app)

# @app.route('/api/osint/virustotal', methods=['GET'])
# def get_virustotal_data():
#     url = request.args.get('url')
#     api_key = request.args.get('4f931f13f341ec0f9a2089984b43523a98dfa79689b8117e7449196afbdec9f')  # Pass your API key as a query parameter
#     if not url or not api_key:
#         return jsonify({"error": "URL and API key are required"}), 400
#     result = fetch_virustotal_data(api_key, url)
#     return jsonify(result)

# @app.route('/api/osint/hibp', methods=['GET'])
# def get_hibp_data():
#     email = request.args.get('email')
#     if not email:
#         return jsonify({"error": "Email is required"}), 400
#     breaches = check_email_breach(email)
#     return jsonify(breaches)

# @app.route('/api/osint/abuseipdb', methods=['GET'])
# def get_abuseipdb_data():
#     ip_address = request.args.get('ip_address')
#     api_key = request.args.get('c4e131e49721c5dd6cdb5e0660aaf2e972fae788f172b67b6122fa91f959d7223adc8d1251ed1e7d')  # Pass your API key as a query parameter
#     if not ip_address or not api_key:
#         return jsonify({"error": "IP address and API key are required"}), 400
#     result = check_ip_abuse(api_key, ip_address)
#     return jsonify(result)

# # New API endpoints for the dashboard
# @app.route('/api/threat-logs', methods=['GET'])
# def get_threat_logs():
#     threat_logs = [
#         "Threat detected from IP 192.0.2.1",
#         "Malware found in file example.exe",
#         "Phishing attempt reported on example.com"
#     ]
#     return jsonify(threat_logs)

# @app.route('/api/risk-scores', methods=['GET'])
# def get_risk_scores():
#     risk_scores = [75, 85, 90]  # Example risk scores
#     return jsonify(risk_scores)

# @app.route('/api/real-time-alerts', methods=['GET'])
# def get_real_time_alerts():
#     real_time_alerts = [
#         "Alert: Suspicious login attempt detected.",
#         "Alert: New malware signature detected.",
#         "Alert: Unusual outbound traffic detected."
#     ]
#     return jsonify(real_time_alerts)

# @app.route('/api/osint', methods=['GET'])
# def osint_data():
#     return jsonify({"message": "OSINT data endpoint"})

# if __name__ == '__main__':
#     app.run(debug=True)



# from flask import Flask, jsonify, request
# from flask_sqlalchemy import SQLAlchemy
# from flask_cors import CORS
# import datetime
# import random

# # Import your API functions
# from api.virustotal import fetch_virustotal_data
# from api.hibp import check_email_breach
# from api.abuseipdb import check_ip_abuse

# app = Flask(__name__)

# # Configure CORS properly
# CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

# # Configure the database connection
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://shopsmart:123456789@localhost:5432/shopsmart'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# db = SQLAlchemy(app)

# @app.route('/api/virustotal', methods=['GET'])
# def get_virustotal_data():
#     url = request.args.get('url')
#     # Fix the API key handling
#     api_key = request.headers.get('API-Key', '4f931f13f341ec0f9a2089984b43523a98dfa79689b8117e7449196afbdec9f')
    
#     if not url:
#         return jsonify({"error": "URL is required"}), 400
    
#     result = fetch_virustotal_data(api_key, url)
#     return jsonify(result)

# @app.route('/api/hibp', methods=['GET'])
# def get_hibp_data():
#     email = request.args.get('email')
#     if not email:
#         return jsonify({"error": "Email is required"}), 400
    
#     breaches = check_email_breach(email)
#     return jsonify(breaches)

# @app.route('/api/abuseipdb', methods=['GET'])
# def get_abuseipdb_data():
#     ip_address = request.args.get('ip_address')
#     # Fix the API key handling
#     api_key = request.headers.get('API-Key', 'c4e131e49721c5dd6cdb5e0660aaf2e972fae788f172b67b6122fa91f959d7223adc8d1251ed1e7d')
    
#     if not ip_address:
#         return jsonify({"error": "IP address is required"}), 400
    
#     result = check_ip_abuse(api_key, ip_address)
#     return jsonify(result)

# # Enhanced Dashboard API endpoints with more structured data
# @app.route('/api/threat-logs', methods=['GET'])
# def get_threat_logs():
#     # More detailed threat logs
#     threat_logs = [
#         "Malware found in file example.exe from host 192.168.1.45",
#         "Phishing attempt reported on example.com targeting financial credentials",
#         "Suspicious IP 203.0.113.42 attempted multiple login failures",
#         "Malware signature detected in network traffic from 198.51.100.23",
#         "Phishing email detected with subject 'Urgent: Update your account'",
#         "IP 192.0.2.18 flagged for scanning activity"
#     ]
#     return jsonify(threat_logs)

# @app.route('/api/risk-scores', methods=['GET'])
# def get_risk_scores():
#     # More varied risk scores
#     risk_scores = [92, 65, 78, 85, 45, 88]
#     return jsonify(risk_scores)

# @app.route('/api/real-time-alerts', methods=['GET'])
# def get_real_time_alerts():
#     # More descriptive alerts
#     real_time_alerts = [
#         "Alert: Suspicious login attempt detected from unusual location.",
#         "Alert: New malware signature detected in outbound network traffic.",
#         "Alert: Unusual outbound traffic detected to known malicious IP.",
#         "Alert: Multiple failed authentication attempts for admin account.",
#         "Alert: Suspicious file download detected on marketing workstation."
#     ]
#     return jsonify(real_time_alerts)

# @app.route('/api/osint', methods=['GET'])
# def osint_data():
#     return jsonify({"message": "OSINT data endpoint"})

# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=5001)





# src/api/app.py
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from api.models import db, User  # Import the User model
import datetime
import random

# # Import your API functions
from api.virustotal import fetch_virustotal_data
from api.hibp import check_email_breach
from api.abuseipdb import check_ip_abuse
from api.shodan import search_shodan  # Import the Shodan search function

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})
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
        return jsonify({"message": "User  registered successfully"}), 201
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
        return jsonify({"error": "User  not found"}), 404

# Other existing routes...
@app.route('/api/virustotal', methods=['GET'])
def get_virustotal_data():
    url = request.args.get('url')
    # Fix the API key handling
    api_key = request.headers.get('API-Key', '4f931f13f341ec0f9a2089984b43523a98dfa79689b8117e7449196afbdec9f')
    #api_key = config.get('VIRUSTOTAL_API_KEY')
    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    result = fetch_virustotal_data(api_key, url)
    return jsonify(result)

@app.route('/api/hibp', methods=['GET'])
def get_hibp_data():
    email = request.args.get('email')
    if not email:
        return jsonify({"error": "Email is required"}), 400
    
    breaches = check_email_breach(email)
    return jsonify(breaches)

@app.route('/api/abuseipdb', methods=['GET'])
def get_abuseipdb_data():
    ip_address = request.args.get('ip_address')
    # Fix the API key handling
    api_key = request.headers.get('API-Key', 'c4e131e49721c5dd6cdb5e0660aaf2e972fae788f172b67b6122fa91f959d7223adc8d1251ed1e7d')
    #api_key = config.get('ABUSEIPDB_API_KEY')

    if not ip_address:
        return jsonify({"error": "IP address is required"}), 400
    
    result = check_ip_abuse(api_key, ip_address)
    return jsonify(result)

# Shodan Search Endpoint
@app.route('/api/shodan', methods=['GET'])
def get_shodan_data():
    query = request.args.get('query')
    api_key = request.headers.get('API-Key')  # Ensure you pass your Shodan API key in the headers
    #api_key = config.get('SHODAN_API_KEY')

    if not query:
        return jsonify({"error": "Query is required"}), 400

    if not api_key:
        return jsonify({"error": "API key is required"}), 400

    result = search_shodan(api_key, query)
    return jsonify(result)

# Enhanced Dashboard API endpoints with more structured data
@app.route('/api/threat-logs', methods=['GET'])
def get_threat_logs():
    # More detailed threat logs
    threat_logs = [
        "Malware found in file example.exe from host 192.168.1.45",
        "Phishing attempt reported on example.com targeting financial credentials",
        "Suspicious IP 203.0.113.42 attempted multiple login failures",
        "Malware signature detected in network traffic from 198.51.100.23",
        "Phishing email detected with subject 'Urgent: Update your account'",
        "IP 192.0.2.18 flagged for scanning activity"
    ]
    return jsonify(threat_logs)

@app.route('/api/risk-scores', methods=['GET'])
def get_risk_scores():
    # More varied risk scores
    risk_scores = [92, 65, 78, 85, 45, 88]
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
    with app.app_context():
        db.create_all()  # Create tables
    app.run(debug=True, host='0.0.0.0', port=5001)
