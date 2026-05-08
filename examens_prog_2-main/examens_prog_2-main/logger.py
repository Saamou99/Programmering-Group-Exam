import logging 

logging.basicConfig(filename="threat.log", level = logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")

threat_logger = logging.getLogger("threat_intel")

