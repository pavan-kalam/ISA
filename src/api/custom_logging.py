# # custom_logging.py
# import os
# import logging
# from logging.handlers import RotatingFileHandler
# from dotenv import load_dotenv

# load_dotenv()

# LOG_FILE_PATH = os.getenv('LOG_FILE_PATH', 'app.log')
# MAX_BYTES = 10 * 1024 * 1024  # 10 MB
# BACKUP_COUNT = 5

# def setup_logger(name, level=logging.INFO):
#     logger = logging.getLogger(name)
#     logger.setLevel(level)
    
#     if not logger.handlers:
#         file_handler = RotatingFileHandler(
#             LOG_FILE_PATH,
#             maxBytes=MAX_BYTES,
#             backupCount=BACKUP_COUNT
#         )
#         file_handler.setFormatter(
#             logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#         )
#         logger.addHandler(file_handler)
        
#         console_handler = logging.StreamHandler()
#         console_handler.setFormatter(
#             logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#         )
#         logger.addHandler(console_handler)
    
#     return logger

# if __name__ == "__main__":
#     logger = setup_logger('test')
#     logger.info("Logging system initialized")


# src/api/custom_logging.py
import os
import logging
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv

load_dotenv()

MAX_BYTES = 10 * 1024 * 1024  # 10 MB
BACKUP_COUNT = 5

def setup_logger(name, level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    if not logger.handlers:  # Only add handlers if none exist
        # Default to 'logs/<name>.log' if no LOG_FILE_PATH in .env
        default_log_path = os.path.join('logs', f"{name}.log")
        log_file_path = os.getenv('LOG_FILE_PATH', default_log_path)
        
        # Ensure the directory exists
        log_dir = os.path.dirname(log_file_path)
        if log_dir:  # Only create if there’s a directory component
            os.makedirs(log_dir, exist_ok=True)
        
        file_handler = RotatingFileHandler(
            log_file_path,
            maxBytes=MAX_BYTES,
            backupCount=BACKUP_COUNT
        )
        file_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        logger.addHandler(file_handler)
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        logger.addHandler(console_handler)
    
    return logger

if __name__ == "__main__":
    logger = setup_logger('test')
    logger.info("Logging system initialized")