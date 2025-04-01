# api/logger.py
import logging
import os
from dotenv import load_dotenv

load_dotenv()

# Configure the log file path from environment variable, default to 'app.log'
LOG_FILE_PATH = os.getenv('LOG_FILE_PATH', 'app.log')

# Configure the logger for the application
logger = logging.getLogger('app')
logger.setLevel(logging.INFO)

# File handler
file_handler = logging.FileHandler(LOG_FILE_PATH)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(console_handler)