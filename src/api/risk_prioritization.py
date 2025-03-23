# src/api/risk_prioritization.py
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('risk_prioritization')

class RiskPrioritizer:
    def __init__(self, weights=None):
        # Default weights for the scoring model
        self.weights = weights or {
            'risk_score': 0.4,  # 40% weight
            'likelihood': 0.3,  # 30% weight
            'impact': 0.2,      # 20% weight
            'recency': 0.1      # 10% weight (how recent the threat is)
        }

    def calculate_priority_score(self, threat, tva_mapping=None, current_time=None):
        """
        Calculate a priority score for a threat.
        Args:
            threat (dict): Threat data with 'risk_score', 'threat_type', 'created_at'
            tva_mapping (dict): TVA mapping with 'likelihood', 'impact' for the threat type
            current_time (datetime): Current time for recency calculation
        Returns:
            float: Priority score (0-100)
        """
        try:
            # Extract risk score (0-100)
            risk_score = threat.get('risk_score', 50)

            # Get likelihood and impact from tva_mapping (1-5 scale)
            threat_type = threat.get('threat_type', 'Other')
            likelihood = tva_mapping.get('likelihood', 3) if tva_mapping else 3
            impact = tva_mapping.get('impact', 3) if tva_mapping else 3

            # Normalize likelihood and impact to 0-100 scale
            likelihood_normalized = (likelihood / 5) * 100
            impact_normalized = (impact / 5) * 100

            # Calculate recency score (0-100)
            created_at = threat.get('created_at')
            current_time = current_time or datetime.now()
            if created_at:
                time_diff_hours = (current_time - created_at).total_seconds() / 3600
                # Recency score: 100 if within 1 hour, decreases to 0 over 24 hours
                recency_score = max(0, 100 - (time_diff_hours / 24) * 100)
            else:
                recency_score = 50  # Default if no timestamp

            # Calculate weighted priority score
            priority_score = (
                self.weights['risk_score'] * risk_score +
                self.weights['likelihood'] * likelihood_normalized +
                self.weights['impact'] * impact_normalized +
                self.weights['recency'] * recency_score
            )

            # Ensure score is between 0 and 100
            priority_score = min(max(priority_score, 0), 100)
            logger.info(f"Calculated priority score for {threat_type}: {priority_score:.2f}")
            return priority_score

        except Exception as e:
            logger.error(f"Error calculating priority score: {str(e)}")
            return 50  # Default score on error

    def prioritize_threats(self, threats, tva_mappings, current_time=None):
        """
        Prioritize a list of threats.
        Args:
            threats (list): List of threat dictionaries
            tva_mappings (list): List of TVA mappings with 'threat_name', 'likelihood', 'impact'
            current_time (datetime): Current time for recency calculation
        Returns:
            list: Sorted list of threats with priority scores
        """
        # Create a lookup dictionary for tva_mappings
        tva_lookup = {mapping['threat_name']: mapping for mapping in tva_mappings}

        # Calculate priority score for each threat
        prioritized_threats = []
        for threat in threats:
            threat_type = threat.get('threat_type', 'Other')
            tva_mapping = tva_lookup.get(threat_type)
            priority_score = self.calculate_priority_score(threat, tva_mapping, current_time)
            threat['priority_score'] = priority_score
            prioritized_threats.append(threat)

        # Sort threats by priority score (descending)
        prioritized_threats.sort(key=lambda x: x['priority_score'], reverse=True)
        return prioritized_threats