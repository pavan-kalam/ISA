# # src/api/risk_analysis.py

# def calculate_risk(likelihood, impact):
#     """Calculate risk score based on likelihood and impact."""
#     return likelihood * impact

# def gpt_simulation(threat_description, risk_score):
#     """Simulate GPT-based risk scoring logic."""
#     # Placeholder logic for GPT-based refinement
#     # In a real implementation, you would call the GPT API here
#     return risk_score  # Return the original score for now

# def analyze_risk(threats):
#     """Analyze risks based on threat data."""
#     risk_scores = []
    
#     for threat in threats:
#         # Assign default likelihood and impact based on threat description
#         likelihood = 1  # Default value
#         impact = 1  # Default value
        
#         # Example logic to assign likelihood and impact based on threat description
#         if "SQL Injection" in threat:
#             likelihood = 4
#             impact = 5
#         elif "Phishing" in threat:
#             likelihood = 5
#             impact = 3
        
#         # Calculate risk score
#         risk_score = calculate_risk(likelihood, impact)
        
#         risk_scores.append({
#             "threat": threat,
#             "risk_score": risk_score
#         })

    
#     return risk_scores


# src/api/risk_analysis.py
from transformers import pipeline
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('risk_analysis.log'),
        logging.StreamHandler()
    ]
)
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
        logger.info("Adjusted risk scores upward due to increasing threat trend.")

    logger.info(f"Generated risk scores: {risk_scores}")
    return risk_scores

def analyze_trends(threat_data):
    """Analyze trends in threat data to determine if risk is increasing."""
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