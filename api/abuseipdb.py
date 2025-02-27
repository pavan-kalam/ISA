# api/abuseipdb.py
import requests

def check_ip_abuse(api_key, ip_address):
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }
    response = requests.get(f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}', headers=headers)
    return response.json()