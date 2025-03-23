#!/usr/bin/env python3
# api/fetch_osint.py

import os
import logging
import time
from datetime import datetime
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError
from api.spiderfoot import fetch_spiderfoot_data
from src.api.risk_analysis import analyze_trends, analyze_risk
from api.models import db, ThreatData, TvaMapping

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
SPIDERFOOT_API_KEY = os.getenv('SPIDERFOOT_API_KEY')

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
        if isinstance(data, dict) and 'error' in data:
            logger.error(f"Error from Spiderfoot: {data['error']}")
            return [{"description": "Default threat description from Spiderfoot", "risk": "low"}]
        return data
    except Exception as e:
        logger.error(f"Error fetching Spiderfoot data: {str(e)}")
        return [{"description": "Default threat description from Spiderfoot", "risk": "high"}]

def process_threat_data(data, source):
    """Process the threat data and determine threat type."""
    processed_data = []
    for item in data:
        if isinstance(item, dict):
            if source == 'spiderfoot':
                description = item.get("description", "No description available")
                threat_type = "Other"
                if "malware" in description.lower():
                    threat_type = "Malware"
                elif "phishing" in description.lower():
                    threat_type = "Phishing"
                elif "ip" in description.lower():
                    threat_type = "IP"
                processed_data.append({
                    "description": description,
                    "risk": item.get("risk", "unknown"),
                    "threat_type": threat_type
                })
        else:
            logger.warning(f"Expected a dictionary but got a {type(item).__name__}: {item}")
    return processed_data

def save_threat_data(threats):
    """Save processed threat data to the database and update tva_mapping."""
    session = get_db_session()
    if not session:
        logger.error("Failed to save threat data: No database session.")
        return

    try:
        descriptions = [threat["description"] for threat in threats]
        risk_scores = analyze_risk(descriptions)

        for threat, risk_score in zip(threats, risk_scores):
            # Save to threat_data
            threat_entry = ThreatData(
                threat_type=threat["threat_type"],
                description=threat["description"],
                risk_score=risk_score
            )
            session.add(threat_entry)

            # Check if this threat type exists in tva_mapping; if not, add it
            existing_mapping = session.query(TvaMapping).filter_by(threat_name=threat["threat_type"]).first()
            if not existing_mapping:
                new_mapping = TvaMapping(
                    asset_id=0,
                    description=f"Threat: {threat['description']}",
                    threat_name=threat["threat_type"],
                    likelihood=1,
                    impact=1
                )
                session.add(new_mapping)

        session.commit()
        logger.info(f"Saved {len(threats)} threats to the database.")
    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Failed to save threat data: {str(e)}")
    finally:
        session.close()

def update_tva_mapping():
    """Execute the TVA update SQL script."""
    engine = create_engine(DATABASE_URL)
    try:
        with engine.connect() as connection:
            with open('db/tva_update.sql', 'r') as file:
                sql_script = file.read()
            connection.exec_driver_sql(sql_script)
            connection.commit()
            logger.info("Successfully updated TVA mapping.")
    except Exception as e:
        logger.error(f"Failed to update TVA mapping: {str(e)}")

def fetch_osint_data():
    """Fetch OSINT data from multiple sources and return a unified structure."""
    logger.info("Starting OSINT data fetch...")
    all_threats = []
    
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
            # Fetch created_at for each threat
            for threat in threats:
                threat_entry = ThreatData.query.filter_by(description=threat['description']).order_by(ThreatData.created_at.desc()).first()
                threat['created_at'] = threat_entry.created_at if threat_entry else datetime.now()
            all_threats.extend(threats)
            logger.info(f"Processed threats from Spiderfoot for query: {query}")
        else:
            logger.warning(f"No data received from Spiderfoot for query: {query}")
            all_threats.append({
                "description": "Default threat description from Spiderfoot",
                "risk": "high",
                "threat_type": "Other",
                "created_at": datetime.now()
            })

    # Save threats to the database and update tva_mapping
    save_threat_data(all_threats)

    # Update TVA mapping
    update_tva_mapping()

    # Analyze trends
    trends = analyze_trends(all_threats)
    logger.info(f"Threat trends: {trends}")

    return {"events": all_threats, "trends": trends}

def main():
    """Main entry point with scheduler setup"""
    logger.info("Starting OSINT Threat Intelligence Fetcher")
    
    session = get_db_session()
    if not session:
        logger.error("Failed to establish database connection. Exiting.")
        return
    session.close()
    
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        fetch_osint_data,
        'interval',
        seconds=FETCH_INTERVAL,
        next_run_time=datetime.now()
    )
    
    try:
        scheduler.start()
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
        logger.info("Shutting down OSINT Threat Intelligence Fetcher")

if __name__ == '__main__':
    main()