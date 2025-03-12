from transformers import pipeline

# Initialize the sentiment analysis model once
sentiment_analyzer = pipeline("sentiment-analysis")

def analyze_risk(data):
    """Analyze risk based on sentiment analysis of input data."""
    
    if not data or not isinstance(data, str):
        return []  # Return an empty list for invalid input
    
    # Analyze sentiment
    results = sentiment_analyzer([data])  # Ensure input is a list
    
    # Convert sentiment results to risk scores
    risk_scores = []
    for result in results:
        score = result['score']  # Confidence score
        if result['label'] == 'POSITIVE':
            risk_scores.append(1 - score)  # Lower risk with higher confidence
        elif result['label'] == 'NEGATIVE':
            risk_scores.append(score)  # Higher risk with higher confidence
        else:
            risk_scores.append(0.5)  # Neutral risk
    
    return risk_scores
