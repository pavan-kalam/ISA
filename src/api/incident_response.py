# src/api/incident_response.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from api.models import db, IncidentLog
from custom_logging import setup_logger
logger = setup_logger('incident_response')
from datetime import datetime
import logging
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger('incident_response')

DATABASE_URL = 'postgresql://shopsmart:123456789@localhost:5432/shopsmart'

def get_db_session():
    try:
        engine = create_engine(DATABASE_URL)
        Session = sessionmaker(bind=engine)
        return Session()
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return None

class IncidentResponder:
    def __init__(self):
        self.response_plans = {
            "SQL Injection": {
                "Preparation": "Ensure IDS/IPS rules detect SQL injection attempts.",
                "Detection and Analysis": "Analyze logs for SQL injection patterns.",
                "Containment": "Block the attacking IP.",
                "Eradication": "Patch the vulnerability in the application.",
                "Recovery": "Restore affected systems from backups.",
                "Post-Incident": "Conduct forensic analysis and update security policies."
            },
            "Phishing": {
                "Preparation": "Train users on phishing awareness.",
                "Detection and Analysis": "Identify phishing emails via filters.",
                "Containment": "Notify affected users.",
                "Eradication": "Change compromised credentials.",
                "Recovery": "Update phishing filters.",
                "Post-Incident": "Review incident for training improvements."
            },
            "DDoS Attack": {
                "Preparation": "Set up DDoS mitigation services.",
                "Detection and Analysis": "Monitor traffic for anomalies.",
                "Containment": "Activate DDoS mitigation.",
                "Eradication": "Enable rate limiting.",
                "Recovery": "Monitor ongoing traffic.",
                "Post-Incident": "Analyze attack source and improve defenses."
            },
            "Default threat": {
                "Preparation": "Prepare generic security measures.",
                "Detection and Analysis": "Analyze threat data.",
                "Containment": "Contain the threat.",
                "Eradication": "Remove the threat.",
                "Recovery": "Recover systems.",
                "Post-Incident": "Review and improve processes."
            }
        }

    def generate_response_plan(self, threat_info):
        threat_desc = threat_info.get('description', 'Unknown Threat').strip().lower()
        plan = self.response_plans.get(threat_desc.title(), None)
        if not plan:
            if "sql" in threat_desc or "injection" in threat_desc:
                plan = self.response_plans["SQL Injection"]
            elif "phish" in threat_desc:
                plan = self.response_plans["Phishing"]
            elif "ddos" in threat_desc or "denial" in threat_desc:
                plan = self.response_plans["DDoS Attack"]
            else:
                plan = self.response_plans["Default threat"]

        response_plan = {
            "threat_type": threat_info.get('threat_type', 'Other'),
            "description": threat_desc,
            "priority": "High" if threat_info.get('risk_score', 0) > 20 else "Medium",
            "mitigation_strategies": list(plan.values()),
            "response_steps": [f"{phase}: {action}" for phase, action in plan.items()]
        }
        self.log_incident(threat_info, response_plan)
        return response_plan

    def log_incident(self, threat_info, response_plan):
        session = get_db_session()
        if not session:
            return
        try:
            incident_log = IncidentLog(
                threat_type=threat_info.get('threat_type', 'Other'),
                description=threat_info.get('description', 'Unknown Threat'),
                response_plan=str(response_plan),
                risk_score=threat_info.get('risk_score', 0)
            )
            session.add(incident_log)
            session.commit()
            logger.info(f"Logged incident: {threat_info['description']}")
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to log incident: {e}")
        finally:
            session.close()

if __name__ == "__main__":
    responder = IncidentResponder()
    threat = {"description": "SQL Injection attempt detected", "risk_score": 25, "threat_type": "Injection"}
    response = responder.generate_response_plan(threat)
    print(f"Incident Response Plan: {response}")