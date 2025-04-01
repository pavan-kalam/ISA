# risk_scoring.py
import logging
from datetime import datetime
import numpy as np
from transformers import pipeline
# Replace: from logging import setup_logger
from custom_logging import setup_logger
logger = setup_logger('risk_scoring')

try:
    classifier = pipeline("sentiment-analysis", model="distilbert-base-uncased-finetuned-sst-2-english")
    logger.info("Initialized sentiment analysis classifier")
except Exception as e:
    logger.error(f"Failed to initialize classifier: {str(e)}")
    classifier = None

class RiskScorer:
    def __init__(self):
        self.history = []

    def calculate_decay_factor(self, created_at, current_time=None):
        current_time = current_time or datetime.utcnow()
        time_diff_hours = (current_time - created_at).total_seconds() / 3600
        decay_factor = np.exp(-time_diff_hours / 24)  # Decay halves every 24 hours
        logger.debug(f"Decay factor for {created_at}: {decay_factor}")
        return max(0.1, decay_factor)

    def calculate_risk_score(self, description, likelihood=3, impact=3, created_at=None):
        if not classifier:
            logger.warning("Classifier unavailable, using default score")
            return 50
        
        created_at = created_at or datetime.utcnow()
        try:
            result = classifier(description)[0]
            sentiment_score = result['score'] if result['label'] == "NEGATIVE" else 1 - result['score']
            base_score = sentiment_score * 100
            likelihood_normalized = (likelihood / 5) * 100
            impact_normalized = (impact / 5) * 100
            combined_score = (base_score * 0.4 + likelihood_normalized * 0.3 + impact_normalized * 0.3)
            decay_factor = self.calculate_decay_factor(created_at)
            final_score = combined_score * decay_factor
            logger.info(f"Risk score for '{description}': {final_score:.2f}")
            return min(max(int(final_score), 0), 100)
        except Exception as e:
            logger.error(f"Error calculating risk score for '{description}': {str(e)}")
            return 50

    def analyze_risk(self, threats):
        if not threats:
            logger.warning("No threats provided, returning default scores")
            return [50, 75, 90]
        
        risk_scores = []
        for threat in threats:
            desc = threat.get("description", "Unknown")
            likelihood = threat.get("likelihood", 3)
            impact = threat.get("impact", 3)
            created_at = threat.get("created_at", datetime.utcnow())
            score = self.calculate_risk_score(desc, likelihood, impact, created_at)
            risk_scores.append(score)
            self.history.append({"description": desc, "risk_score": score, "created_at": created_at})
        
        self.history = self.history[-100:]  # Limit history
        return risk_scores if len(risk_scores) >= 3 else risk_scores + [50] * (3 - len(risk_scores))

# Integration with app.py
if __name__ == "__main__":
    scorer = RiskScorer()
    test_threats = [
        {"description": "Malicious IP detected", "likelihood": 4, "impact": 4, "created_at": datetime.utcnow()},
        {"description": "Phishing attempt", "likelihood": 3, "impact": 3, "created_at": datetime.utcnow()}
    ]
    scores = scorer.analyze_risk(test_threats)
    print(f"Risk Scores: {scores}")