import json

from api import get_token, fetch_incidents
from database import (
    create_tables,
    insert_incident,
    insert_alert,
    insert_ioc
)
from logger import threat_logger


def main():
    """
    Main program function.

    Flow:
    1. Create database tables
    2. Retrieve API token
    3. Fetch incidents from API
    4. Save incidents to JSON file
    5. Insert incidents, alerts, and IOCs into database
    """

    # -----------------------------------
    # CREATE DATABASE TABLES
    # -----------------------------------
    threat_logger.info("Creating database tables...")
    create_tables()

    # -----------------------------------
    # GET AUTHENTICATION TOKEN
    # -----------------------------------
    print("Getting token...")
    threat_logger.info("Requesting authentication token")

    token = get_token()

    # Stop program if token retrieval failed
    if token is None:
        print("Failed to retrieve token")
        threat_logger.warning("Program stopped because token retrieval failed")
        return

    print("Token retrieved successfully")

    # -----------------------------------
    # FETCH INCIDENTS FROM API
    # -----------------------------------
    print("Fetching incidents...")
    threat_logger.info("Fetching incidents from API")

    incidents = fetch_incidents(token)

    # Validate API response
    if not isinstance(incidents, list):
        print("Invalid API response")
        threat_logger.error("API response was not a list")
        return

    print(f"Retrieved {len(incidents)} incidents")
    threat_logger.info(f"Retrieved {len(incidents)} incidents")

    # -----------------------------------
    # SAVE RAW JSON DATA
    # -----------------------------------
    try:
        with open("incidents.json", "w", encoding="utf-8") as file:
            json.dump(incidents, file, indent=4)

        threat_logger.info("Incidents saved to incidents.json")

    except Exception as e:
        threat_logger.exception(f"Failed to save incidents.json: {e}")

    # -----------------------------------
    # DATABASE INSERTION
    # -----------------------------------
    print("Saving data to database...")
    threat_logger.info("Starting database insertion")

    incident_count = 0
    alert_count = 0
    ioc_count = 0

    # Loop through all incidents
    for incident in incidents:

        # -----------------------------
        # INSERT INCIDENT
        # -----------------------------
        inserted_incident = insert_incident(incident)

        if inserted_incident:
            incident_count += 1

        # -----------------------------
        # LOOP THROUGH ALERTS
        # -----------------------------
        for alert in incident.get("alerts", []):

            # Add incidentId to alert object
            # because alert itself does not contain it
            alert["incidentId"] = incident.get("incidentId")

            inserted_alert = insert_alert(alert)

            if inserted_alert:
                alert_count += 1

            # -------------------------
            # IOC EXTRACTION
            # -------------------------
            entities = alert.get("entities", {})

            # Loop through IOC categories
            for ioc_type, values in entities.items():

                # Ensure values is a list
                if not isinstance(values, list):
                    continue

                # Insert each IOC value
                for value in values:

                    inserted_ioc = insert_ioc(
                        incident.get("incidentId"),
                        ioc_type,
                        value
                    )

                    if inserted_ioc:
                        ioc_count += 1

    # -----------------------------------
    # FINAL OUTPUT
    # -----------------------------------
    print("\nDatabase insertion completed")
    print(f"Inserted incidents: {incident_count}")
    print(f"Inserted alerts: {alert_count}")
    print(f"Inserted IOCs: {ioc_count}")

    threat_logger.info(
        f"Database insertion completed | "
        f"Incidents: {incident_count} | "
        f"Alerts: {alert_count} | "
        f"IOCs: {ioc_count}"
    )


# ---------------------------------------
# START PROGRAM
# ---------------------------------------
if __name__ == "__main__":
    main()