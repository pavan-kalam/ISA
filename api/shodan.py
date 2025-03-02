# api/shodan.py
import shodan

# Initialize the Shodan API
def get_shodan_api(api_key):
    return shodan.Shodan(api_key)

def search_shodan(api_key, query):
    api = get_shodan_api(api_key)
    try:
        results = api.search(query)
        return results
    except shodan.APIError as e:
        return {"error": str(e)}