# api/virustotal.py
import requests

def fetch_virustotal_data(api_key, url):
    headers = {
        'x-apikey': api_key
    }
    response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url}', headers=headers)
    return response.json()