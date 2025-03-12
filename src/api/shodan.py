# api/shodan.py
import requests

def search_zoomeye(api_key, query):
    url = f"https://api.zoomeye.org/host/search?query={query}"
    headers = {
        'Authorization': f'Bearer {api_key}'
    }
    try:
        response = requests.get(url, headers=headers)
        return response.json() if response.status_code == 200 else {"error": "Failed to fetch data"}
    except Exception as e:
        return {"error": str(e)}
