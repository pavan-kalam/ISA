# api/spiderfoot.py
import requests

def fetch_spiderfoot_data(api_key, query):
    """Fetch data from the local Spiderfoot instance."""
    if not api_key:
        return [
            {"description": "Hardcoded threat description 1", "risk": "low"},
            {"description": "Hardcoded threat description 2", "risk": "medium"},
            {"description": "Hardcoded threat description 3", "risk": "high"},
        ]
    
    url = f"http://localhost:5001/sf/api?key={api_key}&query={query}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        if 'error' in data:
            return {"error": f"Spiderfoot error: {data['error']}"}
        return data.get('events', [])
    except requests.RequestException as e:
        return {"error": f"Failed to fetch data from Spiderfoot: {str(e)}"}