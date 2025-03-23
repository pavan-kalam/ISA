# src/api/mitigation_recommendations.py
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('mitigation_recommendations')

class MitigationRecommender:
    def __init__(self):
        # Define mitigation strategies for each threat type
        self.mitigation_strategies = {
            'Phishing': [
                "Implement email filtering to block phishing attempts.",
                "Conduct user awareness training on recognizing phishing emails.",
                "Enable multi-factor authentication (MFA) for all accounts.",
                "Monitor and block suspicious domains in DNS traffic."
            ],
            'Malware': [
                "Deploy endpoint detection and response (EDR) solutions.",
                "Update and patch all systems to prevent exploitation.",
                "Isolate affected systems to prevent malware spread.",
                "Run antivirus scans and remove detected malware."
            ],
            'IP': [
                "Block the suspicious IP address at the firewall.",
                "Investigate the source of the IP for potential attribution.",
                "Enable intrusion detection systems (IDS) to monitor traffic.",
                "Review access logs for unauthorized access attempts."
            ],
            'Other': [
                "Conduct a thorough investigation to identify the threat.",
                "Review system logs for unusual activity.",
                "Implement network segmentation to limit exposure.",
                "Engage a security team for further analysis."
            ]
        }

    def get_recommendations(self, threat_type):
        """
        Get mitigation recommendations for a given threat type.
        Args:
            threat_type (str): Type of the threat (e.g., 'Phishing', 'Malware')
        Returns:
            list: List of mitigation strategies
        """
        try:
            recommendations = self.mitigation_strategies.get(threat_type, self.mitigation_strategies['Other'])
            logger.info(f"Generated recommendations for {threat_type}: {recommendations}")
            return recommendations
        except Exception as e:
            logger.error(f"Error generating recommendations: {str(e)}")
            return ["Investigate the threat further and consult a security expert."]