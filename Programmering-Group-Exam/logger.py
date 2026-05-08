import logging

# Configure logging system
logging.basicConfig(
    filename="threat.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# Create logger object
threat_logger = logging.getLogger("threat_intelligence")