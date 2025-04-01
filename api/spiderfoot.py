# api/spiderfoot.py
import subprocess
import json
from json import JSONDecodeError
import os
import re
from dotenv import load_dotenv
import logging
import tempfile
import shutil

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('spiderfoot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('spiderfoot')

SPIDERFOOT_CONTAINER_NAME = os.getenv('SPIDERFOOT_CONTAINER_NAME', 'spiderfoot')

def fetch_spiderfoot_data(query, modules="sfp_spider,sfp_http"):
    logger.info(f"Fetching SpiderFoot data for query: {query}")
    temp_dir = tempfile.mkdtemp()
    temp_file_local = os.path.join(temp_dir, 'results.json')
    temp_file_container = '/tmp/results.json'
    try:
        exec_command = (
            f"docker exec {SPIDERFOOT_CONTAINER_NAME} sh -c "
            f"\"python3 sf.py -m {modules} -s \\\"{query}\\\" -o json > {temp_file_container}\""
        )
        logger.info(f"Executing SpiderFoot command: {exec_command}")
        subprocess.check_call(exec_command, shell=True, timeout=300)
        cp_command = f"docker cp {SPIDERFOOT_CONTAINER_NAME}:{temp_file_container} {temp_file_local}"
        logger.info(f"Copying results: {cp_command}")
        subprocess.check_call(cp_command, shell=True)
        
        # Read and log the raw content
        with open(temp_file_local, 'r', encoding='utf-8', errors='replace') as f:
            raw_data = f.read()
        logger.debug(f"Raw SpiderFoot output: {raw_data}")

        # Sanitize the output: Remove control characters
        sanitized_data = re.sub(r'[\x00-\x1F\x7F]', '', raw_data)
        logger.debug(f"Sanitized SpiderFoot output: {sanitized_data}")

        # Parse the sanitized data as JSON
        data = json.loads(sanitized_data)
        logger.info(f"Successfully fetched {len(data)} events from SpiderFoot CLI")
        if not data or not isinstance(data, list):
            logger.warning(f"Invalid or empty data from SpiderFoot: {data}")
            return {"events": []}
        threats = [
            {
                "description": event.get('data', 'No data available'),
                "threat_type": event.get('type', 'Other'),
                "risk": determine_risk(event)
            }
            for event in data
        ]
        return {"events": threats}
    except subprocess.CalledProcessError as e:
        error_output = e.output.decode('utf-8') if e.output else "No output available"
        logger.error(f"SpiderFoot command failed with exit status {e.returncode}: {error_output}")
        return {
            "events": [
                {"description": f"SpiderFoot execution failed for query '{query}': {error_output}", "threat_type": "Error", "risk": "low"}
            ]
        }
    except (subprocess.TimeoutExpired, JSONDecodeError, FileNotFoundError) as e:
        logger.error(f"Error processing SpiderFoot results for query '{query}': {str(e)}")
        return {
            "events": [
                {"description": f"Error fetching SpiderFoot data for query '{query}': {str(e)}", "threat_type": "Error", "risk": "low"}
            ]
        }
    finally:
        if os.path.exists(temp_file_local):
            os.remove(temp_file_local)
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

def determine_risk(event):
    event_type = event.get('type', '').upper()
    risk_mapping = {
        'IP ADDRESS': 'medium',
        'IPV6 ADDRESS': 'medium',
        'DOMAIN NAME': 'low',
        'INTERNET NAME': 'low',
        'DOMAIN NAME (PARENT)': 'low',
        'MALICIOUS_IP_ADDRESS': 'high',
        'MALICIOUS_URL': 'high',
        'LEAKED_CREDENTIAL': 'high',
        'USERNAME': 'medium',
    }
    return risk_mapping.get(event_type, 'low')

if __name__ == "__main__":
    result = fetch_spiderfoot_data("localhost:5002")
    print(json.dumps(result, indent=2))