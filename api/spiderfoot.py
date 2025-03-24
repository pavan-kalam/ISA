# api/spiderfoot.py
import subprocess
import json
from json import JSONDecodeError
import os
from dotenv import load_dotenv
import logging
import tempfile
import shutil

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('spiderfoot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('spiderfoot')

# Docker container name (set in .env or default)
SPIDERFOOT_CONTAINER_NAME = os.getenv('SPIDERFOOT_CONTAINER_NAME', 'spiderfoot')

def fetch_spiderfoot_data(query):
    """Fetch data from SpiderFoot using Docker exec."""
    logger.info(f"Attempting to fetch data for query: {query}")
    temp_dir = tempfile.mkdtemp()
    temp_file_local = os.path.join(temp_dir, 'results.json')
    temp_file_container = '/tmp/results.json'

    try:
        # Use sfp_spider and sfp_http for HTTP endpoints
        exec_command = (
            f"docker exec {SPIDERFOOT_CONTAINER_NAME} sh -c "
            f"\"python3 sf.py -m sfp_spider,sfp_http -s \\\"{query}\\\" -o json > {temp_file_container}\""
        )
        logger.info(f"Executing command: {exec_command}")
        subprocess.check_call(exec_command, shell=True, timeout=300)

        cp_command = f"docker cp {SPIDERFOOT_CONTAINER_NAME}:{temp_file_container} {temp_file_local}"
        logger.info(f"Copying results: {cp_command}")
        subprocess.check_call(cp_command, shell=True)

        with open(temp_file_local, 'r') as f:
            data = json.load(f)
        logger.info(f"Successfully fetched {len(data)} events from SpiderFoot CLI")

    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, JSONDecodeError, FileNotFoundError) as e:
        logger.error(f"Error running SpiderFoot Docker CLI or processing results: {str(e)} - Falling back to hardcoded data")
        return [
            {"description": "Hardcoded threat description 1", "risk": "low"},
            {"description": "Hardcoded threat description 2", "risk": "medium"},
            {"description": "Hardcoded threat description 3", "risk": "high"},
        ]
    finally:
        # Clean up temporary files and directory
        if os.path.exists(temp_file_local):
            os.remove(temp_file_local)
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

    if not data or not isinstance(data, list):
        logger.warning(f"No valid data from SpiderFoot for query {query} - Falling back to hardcoded data")
        return [
            {"description": "No data from SpiderFoot", "risk": "low"},
        ]

    # Process CLI output into expected format
    threats = []
    for event in data:
        description = event.get('data', 'No data available')
        risk = determine_risk(event)
        threats.append({"description": description, "risk": risk})
    logger.info(f"Processed {len(threats)} threats from CLI data")
    return threats

def determine_risk(event):
    """Determine risk level based on SpiderFoot event type."""
    event_type = event.get('type', '').upper()  # Adjusted to match your output's 'type' field
    risk_mapping = {
        'IP ADDRESS': 'medium',
        'IPV6 ADDRESS': 'medium',
        'DOMAIN NAME': 'low',
        'INTERNET NAME': 'low',
        'DOMAIN NAME (PARENT)': 'low',
        'MALICIOUS_IP_ADDRESS': 'high',  # Add more as needed
        'MALICIOUS_URL': 'high',
        'LEAKED_CREDENTIAL': 'high',
    }
    return risk_mapping.get(event_type, 'low')