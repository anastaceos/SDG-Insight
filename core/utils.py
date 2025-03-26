import logging # Import the logging module for logging

# Configure logging to write both INFO and ERROR messages to the same file
def setup_logging():
    logging.basicConfig(
        filename='error.log',  # Log file name
        level=logging.INFO,  # Log all messages of level INFO and above
        format='%(asctime)s - %(levelname)s - %(message)s',  # Log format
        datefmt='%Y-%m-%d %H:%M:%S'  # Date format
    )
