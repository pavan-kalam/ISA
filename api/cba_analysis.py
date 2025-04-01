# api/cba_analysis.py
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('cba_analysis')

def calculate_cba(ale_prior, ale_post, acs):
    try:
        if any(x < 0 for x in [ale_prior, ale_post, acs]):
            raise ValueError("Values must be non-negative")
        cba = ale_prior - ale_post - acs
        logger.info(f"CBA calculated: ALE_prior={ale_prior}, ALE_post={ale_post}, ACS={acs}, Result={cba}")
        return cba
    except Exception as e:
        logger.error(f"CBA calculation error: {e}")
        return None

def suggest_mitigation(threat, risk_score):
    mitigations = {
        "SQL Injection": {"ale_prior": 50000, "ale_post": 10000, "acs": 15000},
        "Phishing": {"ale_prior": 30000, "ale_post": 5000, "acs": 10000},
        "DDoS Attack": {"ale_prior": 100000, "ale_post": 20000, "acs": 30000}
    }
    data = mitigations.get(threat, {"ale_prior": 10000, "ale_post": 2000, "acs": 5000})
    cba = calculate_cba(data["ale_prior"], data["ale_post"], data["acs"])
    return {
        "threat": threat,
        "risk_score": risk_score,
        "cba": cba,
        "ale_prior": data["ale_prior"],
        "ale_post": data["ale_post"],
        "acs": data["acs"]
    }

if __name__ == "__main__":
    result = suggest_mitigation("SQL Injection", 25)
    print(f"CBA Result: {result}")