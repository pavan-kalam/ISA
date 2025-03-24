# src/api/risk_analysis.py
from transformers import pipeline
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('risk_analysis')

# Initialize the Hugging Face LLM for sentiment analysis
classifier = pipeline("sentiment-analysis", model="distilbert-base-uncased-finetuned-sst-2-english")

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

            # Map sentiment to risk score: NEGATIVE -> high risk, POSITIVE -> low risk
            if label == "NEGATIVE":
                risk_score = int(100 * confidence)  # High confidence in NEGATIVE -> higher risk
            else:
                risk_score = int(50 * (1 - confidence))  # High confidence in POSITIVE -> lower risk

            risk_scores.append(min(max(risk_score, 0), 100))
        except Exception as e:
            logger.error(f"Error analyzing risk for '{desc}': {str(e)}")
            risk_scores.append(50)  # Default score on error

    # Adjust risk scores based on trends
    trends = analyze_trends([{"description": desc, "risk_score": score} for desc, score in zip(threat_descriptions, risk_scores)])
    if trends.get("trend") == "increasing":
        # Increase risk scores by 10% if trend is increasing
        risk_scores = [min(int(score * 1.1), 100) for score in risk_scores]
        logger.info("Adjusted risk scores upward due to increasing threat trend.")

    logger.info(f"Generated risk scores: {risk_scores}")
    return risk_scores

def analyze_trends(threat_data):
    """Analyze trends in threat data to determine if risk is increasing."""
    if not threat_data:
        return {"trend": "none", "count": 0}
    
    high_risk_count = sum(1 for threat in threat_data if threat.get("risk_score", 0) > 80)
    trend = "increasing" if high_risk_count > len(threat_data) / 2 else "stable"
    return {"trend": trend, "count": len(threat_data)}