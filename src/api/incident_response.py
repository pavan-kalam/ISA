# src/api/incident_response.py
import logging
from src.api.mitigation_recommendations import MitigationRecommender

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('incident_response')

class IncidentResponder:
    def __init__(self):
        self.mitigation_recommender = MitigationRecommender()
        # Define incident response playbooks for each threat type
        self.playbooks = {
            'Phishing': {
                'steps': [
                    "Identify and isolate affected users.",
                    "Reset credentials for compromised accounts.",
                    "Analyze phishing email for IOCs (e.g., URLs, attachments).",
                    "Report the incident to the security team and update threat intelligence."
                ],
                'priority': "High"
            },
            'Malware': {
                'steps': [
                    "Isolate the infected system from the network.",
                    "Collect forensic evidence (e.g., memory dumps, logs).",
                    "Eradicate the malware using antivirus tools.",
                    "Restore the system from a clean backup."
                ],
                'priority': "Critical"
            },
            'IP': {
                'steps': [
                    "Block the IP address at the firewall and monitor for further activity.",
                    "Trace the IP to identify the source (e.g., geolocation, WHOIS).",
                    "Review logs for other systems accessed by the IP.",
                    "Update security policies to prevent future access."
                ],
                'priority': "Medium"
            },
            'Other': {
                'steps': [
                    "Escalate the incident to the security team for investigation.",
                    "Collect and preserve evidence for forensic analysis.",
                    "Monitor systems for additional suspicious activity.",
                    "Document the incident and lessons learned."
                ],
                'priority': "Medium"
            }
        }

    def generate_response_plan(self, threat):
        """
        Generate an incident response plan for a threat.
        Args:
            threat (dict): Threat data with 'threat_type', 'description', 'priority_score'
        Returns:
            dict: Response plan with mitigation strategies and playbook steps
        """
        try:
            threat_type = threat.get('threat_type', 'Other')
            priority_score = threat.get('priority_score', 50)

            # Get mitigation recommendations
            mitigations = self.mitigation_recommender.get_recommendations(threat_type)

            # Get playbook for the threat type
            playbook = self.playbooks.get(threat_type, self.playbooks['Other'])

            # Adjust priority based on priority score
            if priority_score > 80:
                playbook['priority'] = "Critical"
            elif priority_score > 50:
                playbook['priority'] = "High"

            response_plan = {
                'threat_type': threat_type,
                'description': threat.get('description', 'No description available'),
                'priority': playbook['priority'],
                'mitigation_strategies': mitigations,
                'response_steps': playbook['steps']
            }

            logger.info(f"Generated response plan for {threat_type}: {response_plan}")
            return response_plan
        except Exception as e:
            logger.error(f"Error generating response plan: {str(e)}")
            return {
                'threat_type': 'Unknown',
                'description': 'Error generating response plan',
                'priority': 'Medium',
                'mitigation_strategies': ["Investigate the issue and consult a security expert."],
                'response_steps': ["Escalate to the security team."]
            }