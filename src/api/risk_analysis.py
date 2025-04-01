# src/api/risk_analysis.py
from transformers import pipeline
import logging
from custom_logging import setup_logger
logger = setup_logger('risk_analysis')
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#     handlers=[
#         logging.FileHandler('risk_analysis.log'),
#         logging.StreamHandler()
#     ]
# )
# logger = logging.getLogger('risk_analysis')

# Initialize the Hugging Face LLM for sentiment analysis
try:
    classifier = pipeline("sentiment-analysis", model="distilbert-base-uncased-finetuned-sst-2-english")
    logger.info("Successfully initialized Hugging Face sentiment analysis classifier")
except Exception as e:
    logger.error(f"Failed to initialize sentiment analysis classifier: {str(e)}")
    classifier = None

def analyze_risk(threat_descriptions):
    """
    Analyze risk scores using an LLM for text classification.

    Args:
        threat_descriptions (list): A list of threat description strings.

    Returns:
        list: A list of risk scores (integers between 0 and 100).
    """
    if not threat_descriptions:
        logger.warning("No threat descriptions provided, returning default scores.")
        return [50, 75, 90]

    if not classifier:
        logger.error("Sentiment analysis classifier not initialized, returning default scores")
        return [50] * len(threat_descriptions)

    risk_scores = []
    for desc in threat_descriptions:
        try:
            result = classifier(desc)[0]
            label = result['label']
            confidence = result['score']
            logger.info(f"Sentiment analysis for '{desc}': {label}, confidence: {confidence:.3f}")

            # Map sentiment to risk score
            if label == "NEGATIVE":
                risk_score = int(100 * confidence)  # High confidence in NEGATIVE -> higher risk
            else:
                risk_score = int(50 * (1 - confidence))  # High confidence in POSITIVE -> lower risk

            risk_scores.append(min(max(risk_score, 0), 100))
        except Exception as e:
            logger.error(f"Error analyzing risk for '{desc}': {str(e)}")
            risk_scores.append(50)  # Default score on error

    # Ensure at least 3 data points for graph visibility
    if len(risk_scores) < 3:
        logger.info(f"Padding risk scores from {len(risk_scores)} to 3 for graph display")
        risk_scores.extend([50] * (3 - len(risk_scores)))

    # Adjust risk scores based on trends
    trends = analyze_trends([{"description": desc, "risk_score": score} for desc, score in zip(threat_descriptions, risk_scores)])
    if trends.get("trend") == "increasing":
        risk_scores = [min(int(score * 1.1), 100) for score in risk_scores]
        logger.info(f"Adjusted risk scores upward due to increasing threat trend. Final scores: {risk_scores}")
    else:
        logger.info(f"No adjustment needed, trend is {trends.get('trend')}. Final scores: {risk_scores}")

    return risk_scores

def analyze_trends(threat_data):
    """
    Analyze trends in threat data to determine if risk is increasing.

    Args:
        threat_data (list): A list of dictionaries with 'description' and 'risk_score'.

    Returns:
        dict: A dictionary with 'trend' ('increasing' or 'stable') and 'count'.
    """
    if not threat_data:
        return {"trend": "none", "count": 0}
    
    high_risk_count = sum(1 for threat in threat_data if threat.get("risk_score", 0) > 80)
    trend = "increasing" if high_risk_count > len(threat_data) / 2 else "stable"
    logger.info(f"Trend analysis: {high_risk_count} high-risk items out of {len(threat_data)}, trend: {trend}")
    return {"trend": trend, "count": len(threat_data)}

if __name__ == "__main__":
    test_descs = ["Error fetching SpiderFoot data", "Malicious IP detected"]
    scores = analyze_risk(test_descs)
    print(f"Risk Scores: {scores}")