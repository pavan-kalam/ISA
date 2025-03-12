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

# Import our API modules
from .hibp import check_email_breach_intelx
from .shodan import search_zoomeye
from .virustotal import fetch_urlscan_data
from .abuseipdb import check_ip_abuse  # Import the abuseipdb function

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
ZOOMEYE_API_KEY = os.getenv('ZOOMEYE_API_KEY')
INTELX_API_KEY = os.getenv('INTELX_API_KEY')
URLSCAN_API_KEY = os.getenv('URLSCAN_API_KEY')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')  # Add the AbuseIPDB API key

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

def fetch_zoomeye_intelligence(query):
    """Fetch threat intelligence from ZoomEye"""
    if not ZOOMEYE_API_KEY:
        logger.error("ZoomEye API key not configured")
        return [{"description": "Default threat description from ZoomEye", "risk": "low"}]
    
    try:
        data = search_zoomeye(ZOOMEYE_API_KEY, query)
        if 'error' in data:
            logger.error(f"Error from ZoomEye: {data['error']}")
            return [{"description": "Default threat description from ZoomEye", "risk": "low"}]
        return data
    except Exception as e:
        logger.error(f"Error fetching ZoomEye data: {str(e)}")
        return [{"description": "Default threat description from ZoomEye", "risk": "high"}]

def fetch_urlscan_intelligence(url):
    """Fetch data from URLScan"""
    if not URLSCAN_API_KEY:
        logger.error("URLScan API key not configured")
        return [{"description": "Default threat description from URLScan", "risk": "low"}]
    
    try:
        urlscan_data = fetch_urlscan_data(URLSCAN_API_KEY, url)
        if 'error' in urlscan_data or urlscan_data.get('status') == 404:
            logger.error(f"Error from URLScan: {urlscan_data.get('message', 'Unknown error')}")
            return [{"description": "Default threat description from URLScan", "risk": "high"}]
        return urlscan_data
    except Exception as e:
        logger.error(f"Error fetching URLScan data: {str(e)}")
        return [{"description": "Default threat description from URLScan", "risk": "high"}]

def fetch_intelx_intelligence(email):
    """Fetch breach data from IntelX"""
    if not INTELX_API_KEY:
        logger.error("IntelX API key not configured")
        return None
    
    try:
        breach_data = check_email_breach_intelx(email, INTELX_API_KEY)
        return breach_data
    except Exception as e:
        logger.error(f"Error fetching IntelX data: {str(e)}")
        return None

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
    
    # Example queries for ZoomEye
    zoomeye_queries = [
        'org:"ShopSmart Solutions"',
        'port:27017 mongodb',
        'port:3306 mysql',
        'http.title:"admin" login'
    ]
    
    for query in zoomeye_queries:
        zoomeye_data = fetch_zoomeye_intelligence(query)
        if zoomeye_data:
            threats = process_threat_data(zoomeye_data, 'zoomeye')
            all_threats.extend(threats)
            logger.info(f"Processed threats from ZoomEye")
        else:
            logger.warning("No data received from ZoomEye, using default data.")
            all_threats.append({"description": "Default threat description from ZoomEye", "risk": "high"})

    # Example IP addresses for AbuseIPDB
    ip_addresses = [
        '192.0.2.1',
        '203.0.113.5'
    ]

    for ip in ip_addresses:
        abuse_data = check_ip_abuse(ABUSEIPDB_API_KEY, ip)
        if abuse_data:
            threats = process_threat_data(abuse_data, 'abuseipdb')
            all_threats.extend(threats)
            logger.info(f"Processed threats from AbuseIPDB")
        else:
            logger.warning("No data received from AbuseIPDB, using default data.")
            all_threats.append({"description": "Default threat description from AbuseIPDB", "risk": "high"})

    # Example email patterns for IntelX
    email_patterns = [
        'admin@shopsmartsolutions.com',
        'support@shopsmartsolutions.com',
        'info@shopsmartsolutions.com'
    ]

    for email in email_patterns:
        intelx_data = fetch_intelx_intelligence(email)
        if intelx_data:
            threats = process_threat_data(intelx_data, 'intelx')
            all_threats.extend(threats)
            logger.info(f"Processed threats from IntelX")
        else:
            logger.warning("No data received from IntelX, using default data.")
            all_threats.append({"description": "Default threat description from IntelX", "risk": "high"})

    # Example URLs for URLScan
    url_patterns = [
        'http://example.com',
        'http://test.com'
    ]

    for url in url_patterns:
        urlscan_data = fetch_urlscan_intelligence(url)
        if urlscan_data:
            threats = process_threat_data(urlscan_data, 'urlscan')
            all_threats.extend(threats)
            logger.info(f"Processed threats from URLScan")
        else:
            logger.warning("No data received from URLScan, using default data.")
            all_threats.append({"description": "Default threat description from URLScan", "risk": "low"})

    if not all_threats:
        logger.warning("No threats found from any sources. Using default data for risk analysis.")
        # Provide default data for risk analysis
        default_data = [
            {"description": "Default threat description 1", "risk": "low"},
            {"description": "Default threat description 2", "risk": "medium"},
        ]
        return {"events": default_data}

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
