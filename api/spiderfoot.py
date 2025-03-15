import requests

def fetch_spiderfoot_data(api_key, query):
    """Fetch data from the Spiderfoot API or return hardcoded data if the API key is not configured."""
    if not api_key:
        return [
            {"description": "Hardcoded threat description 1", "risk": "low"},
            {"description": "Hardcoded threat description 2", "risk": "medium"},
            {"description": "Hardcoded threat description 3", "risk": "high"},
        ]
    
    url = f"https://api.spiderfoot.net/v1/query?api_key={api_key}&query={query}"
    response = requests.get(url)
    
    if response.status_code != 200:
        return {"error": f"Failed to fetch data: {response.status_code}"}
    
    return response.json()
