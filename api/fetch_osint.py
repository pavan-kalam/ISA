#!/usr/bin/env python3
# api/fetch_osint.py

import os
import logging
import time
from datetime import datetime
import requests
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError

# Import Spiderfoot API module
from .spiderfoot import fetch_spiderfoot_data  # New import for Spiderfoot

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('osint_fetcher.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('osint_fetcher')

# Database configuration
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://shopsmart:123456789@localhost:5432/shopsmart')

# API Keys
SPIDERFOOT_API_KEY = os.getenv('SPIDERFOOT_API_KEY')  # New Spiderfoot API key

# Fetch interval in seconds (default: 1 hour)
FETCH_INTERVAL = int(os.getenv('FETCH_INTERVAL', 3600))

def get_db_session():
    """Create and return a database session"""
    try:
        engine = create_engine(DATABASE_URL)
        Session = sessionmaker(bind=engine)
        return Session()
    except Exception as e:
        logger.error(f"Database connection error: {str(e)}")
        return None

def fetch_spiderfoot_intelligence(query):
    """Fetch threat intelligence from Spiderfoot"""
    if not SPIDERFOOT_API_KEY:
        logger.error("Spiderfoot API key not configured")
        return [{"description": "Default threat description from Spiderfoot", "risk": "low"}]
    
    try:
        data = fetch_spiderfoot_data(SPIDERFOOT_API_KEY, query)
        if 'error' in data:
            logger.error(f"Error from Spiderfoot: {data['error']}")
            return [{"description": "Default threat description from Spiderfoot", "risk": "low"}]
        return data
    except Exception as e:
        logger.error(f"Error fetching Spiderfoot data: {str(e)}")
        return [{"description": "Default threat description from Spiderfoot", "risk": "high"}]



def process_threat_data(data, source):
    """Process the threat data based on the source."""
    processed_data = []
    for item in data:
        if isinstance(item, dict):  # Ensure item is a dictionary
            if source == 'zoomeye':
                processed_data.append({
                    "description": item.get("description", "No description available"),
                    "risk": item.get("risk", "unknown")
                })
            elif source == 'abuseipdb':
                processed_data.append({
                    "description": item.get("data", {}).get("abuseConfidenceScore", "No score available"),
                    "risk": "high" if item.get("data", {}).get("abuseConfidenceScore", 0) > 50 else "low"
                })
        else:
            logger.warning(f"Expected a dictionary but got a {type(item).__name__}: {item}")
        # Add more processing logic for other sources as needed
    return processed_data

def fetch_osint_data():
    """Fetch OSINT data from multiple sources and return a unified structure."""    
    logger.info("Starting OSINT data fetch...")
    all_threats = []
    
    # Example queries for Spiderfoot
    spiderfoot_queries = [
        'org:"ShopSmart Solutions"',
        'port:27017 mongodb',
        'port:3306 mysql',
        'http.title:"admin" login'
    ]
    
    for query in spiderfoot_queries:
        spiderfoot_data = fetch_spiderfoot_intelligence(query)
        if spiderfoot_data:
            threats = process_threat_data(spiderfoot_data, 'spiderfoot')
            all_threats.extend(threats)
            logger.info(f"Processed threats from Spiderfoot")
        else:
            logger.warning("No data received from Spiderfoot, using default data.")
            all_threats.append({"description": "Default threat description from Spiderfoot", "risk": "high"})



    # Remove the default data section as it's no longer relevant

    return {"events": all_threats}

def main():
    """Main entry point with scheduler setup"""
    logger.info("Starting OSINT Threat Intelligence Fetcher")
    
    # Test database connection
    session = get_db_session()
    if not session:
        logger.error("Failed to establish database connection. Exiting.")
        return
    session.close()
    
    # Create a scheduler
    scheduler = BackgroundScheduler()
    
    # Schedule the job to run at the specified interval
    scheduler.add_job(
        fetch_osint_data,
        'interval',
        seconds=FETCH_INTERVAL,
        next_run_time=datetime.now()  # Run immediately on start
    )
    
    try:
        scheduler.start()
        # Keep the script running
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
        logger.info("Shutting down OSINT Threat Intelligence Fetcher")

if __name__ == '__main__':
    main()
