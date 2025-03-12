# api/hibp.py
import requests

def check_email_breach_intelx(email, api_key):
    url = f'https://free.intelx.io/api/v1/breach?email={email}'
    headers = {
        'Authorization': f'Bearer {api_key}'
    }
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else None
