# api/api_optimizer.py
import redis
import json
from api.fetch_osint import fetch_osint_data
from dotenv import load_dotenv
import os
from datetime import datetime

# Load environment variables from .env file
load_dotenv()

# Redis configuration
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))

# Configure logging
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#     handlers=[
#         logging.FileHandler('api_optimizer.log'),
#         logging.StreamHandler()
#     ]
# )
# logger = logging.getLogger('api_optimizer')
from custom_logging import setup_logger
logger = setup_logger('api_optimizer')

# Initialize Redis cache
cache = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)

def serialize_datetime(obj):
    """Serialize datetime objects for JSON."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

def get_threat_data(query):
    """
    Fetch threat data for the given query, with caching.
    
    Args:
        query (str): The target to scan (e.g., "localhost:5002").
    
    Returns:
        dict: Threat data from SpiderFoot.
    """
    cache_key = f"threat:{query}"
    try:
        cached_data = cache.get(cache_key)
        if cached_data:
            logger.info(f"Cache hit for query: {query}")
            return json.loads(cached_data)
    except Exception as e:
        logger.error(f"Cache retrieval error: {e}")

    # Fetch fresh data if not in cache
    data = fetch_osint_data(query)
    try:
        cache.setex(cache_key, 3600, json.dumps(data, default=serialize_datetime))
        logger.info(f"Cache set for query: {query}")
    except Exception as e:
        logger.error(f"Cache set error: {e}")
    return data

if __name__ == "__main__":
    # Test the function standalone
    result = get_threat_data("localhost:5002")
    print(f"Threat Data: {result}")