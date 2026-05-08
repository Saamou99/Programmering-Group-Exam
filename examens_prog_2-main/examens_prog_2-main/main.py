import requests 
import datetime
import json
from api import get_token, fetch_incidents
from database import create_tables, insert_alerts, insert_incident, insert_IOCs
from config import DB_FILE
from logger import threat_logger



def main():
    threat_logger.info("Setting up database...")
    create_tables()
    
    threat_logger.info("Requesting token...")
    token = get_token()
    
    if token is None:
        threat_logger.warning("Could not retrieve token. Exiting")
        return

    threat_logger.info("Fetching incidents")
    incidents = fetch_incidents(token)
    threat_logger.info(f"Fetched {len(incidents)} incidents")
    
    with open ("incidents.json", "w") as f:
        json.dump(incidents, f, indent=4)
    threat_logger.info("Incidents saved to incidents.json")
    
    threat_logger.info("Sorting alerts in database...")
    
    for incident in incidents:
        insert_incident(incident)    
        
        for alert in incident.get("alerts", []):
            insert_alerts(alert)
            
            entities = alert.get("entities", {})
            for ioc_type, values in entities.items():
                for value in values:
                    insert_IOCs(incident.get("incidentId"), ioc_type, value)
            
if __name__ == "__main__":
    main()