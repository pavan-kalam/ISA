import os
import logging
import requests

logger = logging.getLogger(__name__)

def fetch_osint_data():
    """Fetch OSINT data from Spiderfoot or use hardcoded data if API key is not available."""
    api_key = os.getenv('SPIDERFOOT_API_KEY')

    if api_key:
        # Use the Spiderfoot API to fetch data
        url = "http://127.0.0.1:5001/api/v1/"  # Replace with actual endpoint
        headers = {"API-Key": api_key}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"Failed to fetch data from Spiderfoot: {response.status_code} - {response.text}")
            return {"events": []}  # Return empty events on failure
    else:
        # Use hardcoded default data for testing
        logger.warning("No API key provided, using hardcoded default data.")
        return {
            "events": [
                {"description": "Test event 1", "risk": "low"},
                {"description": "Test event 2", "risk": "medium"},
                {"description": "Test event 3", "risk": "high"},
            ]
        }
