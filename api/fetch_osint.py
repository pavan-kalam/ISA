#!/usr/bin/env python3
# api/fetch_osint.py

import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError
from api.spiderfoot import fetch_spiderfoot_data
from api.models import db, ThreatData, TvaMapping
from custom_logging import setup_logger
logger = setup_logger('fetch_osint')
# Load environment variables from .env file
load_dotenv()

# Configure logging
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#     handlers=[
#         logging.FileHandler('osint_fetcher.log'),
#         logging.StreamHandler()
#     ]
# )
# logger = logging.getLogger('osint_fetcher')

# Database configuration
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://shopsmart:123456789@localhost:5432/shopsmart')

def get_db_session():
    """Create and return a database session."""
    try:
        engine = create_engine(DATABASE_URL)
        Session = sessionmaker(bind=engine)
        return Session()
    except Exception as e:
        logger.error(f"Database connection error: {str(e)}")
        return None

def fetch_spiderfoot_intelligence(query):
    """Fetch threat intelligence from SpiderFoot CLI."""
    try:
        data = fetch_spiderfoot_data(query)
        if not data or 'events' not in data or len(data['events']) == 0:
            logger.warning(f"No data returned for query: {query}")
            logger.info(f"Returning default threat for query: {query}")
            return [{"description": f"Default threat for {query}", "threat_type": "Other", "risk": "high"}]
        return data['events']
    except Exception as e:
        logger.error(f"Error fetching SpiderFoot data for query '{query}': {str(e)}")
        logger.info(f"Returning default threat for query: {query}")
        return [{"description": f"Default threat for {query}", "threat_type": "Other", "risk": "high"}]

def process_threat_data(data):
    """Process the threat data and determine threat type."""
    processed_data = []
    for item in data:
        if isinstance(item, dict):
            description = item.get("description", "No description available")
            threat_type = item.get("threat_type", "Other")
            if not threat_type or threat_type == "Other":
                if "malware" in description.lower():
                    threat_type = "Malware"
                elif "phishing" in description.lower():
                    threat_type = "Phishing"
                elif "ip" in description.lower():
                    threat_type = "IP"
            processed_data.append({
                "description": description,
                "threat_type": threat_type,
                "risk": item.get("risk", "unknown")
            })
        else:
            logger.warning(f"Expected a dictionary but got a {type(item).__name__}: {item}")
    return processed_data

def save_threat_data(threats):
    """Save processed threat data to the database."""
    session = get_db_session()
    if not session:
        logger.error("Failed to save threat data: No database session.")
        return

    try:
        new_threats = 0
        for threat in threats:
            # Check for existing threat to avoid duplicates
            existing_threat = session.query(ThreatData).filter_by(description=threat["description"]).first()
            if not existing_threat:
                threat_entry = ThreatData(
                    threat_type=threat["threat_type"],
                    description=threat["description"],
                    risk_score=0  # Risk score will be updated later via analyze_risk in app.py
                )
                session.add(threat_entry)
                new_threats += 1
        session.commit()
        logger.info(f"Saved {new_threats} new threats to the database (out of {len(threats)} processed).")
    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Failed to save threat data: {str(e)}")
    finally:
        session.close()

def update_tva_mapping(threats):
    """Update TVA mapping based on processed threats."""
    session = get_db_session()
    if not session:
        logger.error("Failed to update TVA mapping: No database session.")
        return

    try:
        new_mappings = 0
        for threat in threats:
            existing_mapping = session.query(TvaMapping).filter_by(threat_name=threat["threat_type"]).first()
            if not existing_mapping:
                new_mapping = TvaMapping(
                    asset_id=0,  # Default asset_id (should be updated based on actual asset in a production system)
                    description=f"Threat type: {threat['threat_type']}",
                    threat_name=threat["threat_type"],
                    likelihood=1,  # Default likelihood (integer)
                    impact=1      # Default impact (integer)
                )
                session.add(new_mapping)
                new_mappings += 1
        session.commit()
        logger.info(f"Updated TVA mapping with {new_mappings} new entries (out of {len(threats)} threats).")
    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Failed to update TVA mapping: {str(e)}")
    finally:
        session.close()

def fetch_osint_data(query="localhost:5002"):
    """
    Fetch OSINT data for the given query and process it.
    
    Args:
        query (str): The target to scan (default: "localhost:5002").
    
    Returns:
        dict: A dictionary containing processed SpiderFoot events.
    """
    # Validate query
    if not query or not isinstance(query, str) or query.strip() == "":
        logger.error("Invalid or empty query provided, using default query 'localhost:5002'")
        query = "localhost:5002"
    
    logger.info(f"Starting OSINT data fetch for query: {query}")
    
    # Fetch SpiderFoot data
    spiderfoot_data = fetch_spiderfoot_intelligence(query)
    if not spiderfoot_data:
        logger.warning(f"No data received from SpiderFoot for query: {query}")
        return {"events": []}

    # Process the data
    processed_threats = process_threat_data(spiderfoot_data)
    logger.info(f"Processed {len(processed_threats)} threats from SpiderFoot for query: {query}")

    # Save to database
    save_threat_data(processed_threats)
    update_tva_mapping(processed_threats)

    # Prepare response for app.py
    events = [
        {
            "description": threat["description"],
            "threat_type": threat["threat_type"]
        }
        for threat in processed_threats
    ]

    return {"events": events}

if __name__ == "__main__":
    # Test the function standalone
    result = fetch_osint_data("localhost:5002")
    print(f"OSINT Data: {result}")