# api/virustotal.py
import requests

def fetch_urlscan_data(api_key, url):
    headers = {
        'Authorization': f'Bearer {api_key}'
    }
    response = requests.get(f'https://urlscan.io/api/v1/scan/', headers=headers, json={"url": url})
    return response.json()
