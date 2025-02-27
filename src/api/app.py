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



from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS  # Import Flask-CORS
from api.virustotal import fetch_virustotal_data
from api.hibp import check_email_breach
from api.abuseipdb import check_ip_abuse

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # Enable CORS for all routes

# Configure the database connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://shopsmart:123456789@localhost:5432/shopsmart'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

@app.route('/api/osint/virustotal', methods=['GET'])
def get_virustotal_data():
    url = request.args.get('url')
    api_key = request.headers.get('X-Api-Key')  # API key should be sent in headers
    if not url or not api_key:
        return jsonify({"error": "URL and API key are required"}), 400
    result = fetch_virustotal_data(api_key, url)
    return jsonify(result)

@app.route('/api/osint/hibp', methods=['GET'])
def get_hibp_data():
    email = request.args.get('email')
    if not email:
        return jsonify({"error": "Email is required"}), 400
    breaches = check_email_breach(email)
    return jsonify(breaches)

@app.route('/api/osint/abuseipdb', methods=['GET'])
def get_abuseipdb_data():
    ip_address = request.args.get('ip_address')
    api_key = request.headers.get('X-Api-Key')  # API key should be sent in headers
    if not ip_address or not api_key:
        return jsonify({"error": "IP address and API key are required"}), 400
    result = check_ip_abuse(api_key, ip_address)
    return jsonify(result)

# New API endpoints for the dashboard
@app.route('/api/threat-logs', methods=['GET'])
def get_threat_logs():
    threat_logs = [
        "Threat detected from IP 192.0.2.1",
        "Malware found in file example.exe",
        "Phishing attempt reported on example.com"
    ]
    return jsonify(threat_logs)

@app.route('/api/risk-scores', methods=['GET'])
def get_risk_scores():
    risk_scores = [75, 85, 90]  # Example risk scores
    return jsonify(risk_scores)

@app.route('/api/real-time-alerts', methods=['GET'])
def get_real_time_alerts():
    real_time_alerts = [
        "Alert: Suspicious login attempt detected.",
        "Alert: New malware signature detected.",
        "Alert: Unusual outbound traffic detected."
    ]
    return jsonify(real_time_alerts)

@app.route('/api/osint', methods=['GET'])
def osint_data():
    return jsonify({"message": "OSINT data endpoint"})

if __name__ == '__main__':
    app.run(debug=True)
