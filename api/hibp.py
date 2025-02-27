# api/hibp.py
import requests

def check_email_breach(email):
    url = f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}'
    headers = {
        'User -Agent': 'YourAppName'
    }
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else None