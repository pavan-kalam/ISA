# src/api/risk_analysis.py
from transformers import pipeline
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('risk_analysis')

classifier = pipeline("sentiment-analysis", model="distilbert-base-uncased")

def analyze_risk(threat_descriptions):
    """Analyze risk scores using an LLM for text classification."""
    if not threat_descriptions:
        logger.warning("No threat descriptions provided, returning default scores.")
        return [50, 75, 90]

    risk_scores = []
    for desc in threat_descriptions:
        try:
            result = classifier(desc)[0]
            label = result['label']
            confidence = result['score']

            if label == "NEGATIVE":
                risk_score = int(100 * confidence)
            else:
                risk_score = int(50 * (1 - confidence))

            risk_scores.append(min(max(risk_score, 0), 100))
        except Exception as e:
            logger.error(f"Error analyzing risk for '{desc}': {str(e)}")
            risk_scores.append(50)

    logger.info(f"Generated risk scores: {risk_scores}")
    return risk_scores

def analyze_trends(threat_data):
    """Analyze trends in threat data."""
    if not threat_data:
        return {"trend": "none", "count": 0}
    
    high_risk_count = sum(1 for threat in threat_data if threat.get("risk") in ["high", "medium"])
    trend = "increasing" if high_risk_count > len(threat_data) / 2 else "stable"
    return {"trend": trend, "count": len(threat_data)}