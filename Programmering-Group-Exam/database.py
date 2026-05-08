import sqlite3
from logger import threat_logger
from config import DB_FILE

def create_tables():
    """
    Creates all database tables.

    Tables:
    - incidents
    - alerts
    - iocs

    IF NOT EXISTS prevents duplicate table creation.
    UNIQUE constraints prevent duplicate data.
    """

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Enable foreign key support
    cursor.execute("PRAGMA foreign_keys = ON")

    try:

        # INCIDENTS TABLE
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            incident_name TEXT,
            severity TEXT,
            status TEXT,
            classification TEXT,
            determination TEXT,
            created_time TEXT,
            last_update_time TEXT,
            assigned_to TEXT,
            threat_family TEXT,
            summary TEXT,
            users INTEGER,
            machines INTEGER,
            mailboxes INTEGER
        )
        """)

        # ALERTS TABLE
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            incident_id TEXT,
            title TEXT,
            category TEXT,
            severity TEXT,
            detection_source TEXT,
            machine_id TEXT,
            computer_dns_name TEXT,
            first_activity TEXT,
            last_seen TEXT,

            FOREIGN KEY (incident_id)
            REFERENCES incidents(incident_id)
        )
        """)

        # IOC TABLE
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT,
            type TEXT,
            value TEXT,

            UNIQUE(incident_id, type, value),

            FOREIGN KEY (incident_id)
            REFERENCES incidents(incident_id)
        )
        """)

        conn.commit()

        threat_logger.info("Database tables created successfully")

    except sqlite3.Error as error:
        threat_logger.exception(f"Database creation error: {error}")

    finally:
        conn.close()

def insert_incident(incident):
    """
    Inserts incident data into incidents table.

    INSERT OR IGNORE prevents duplicate incidents.
    """

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    try:

        cursor.execute("""
        INSERT OR IGNORE INTO incidents (
            incident_id,
            incident_name,
            severity,
            status,
            classification,
            determination,
            created_time,
            last_update_time,
            assigned_to,
            threat_family,
            summary,
            users,
            machines,
            mailboxes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            incident.get("incidentId"),
            incident.get("incidentName"),
            incident.get("severity"),
            incident.get("status"),
            incident.get("classification"),
            incident.get("determination"),
            incident.get("createdTime"),
            incident.get("lastUpdateTime"),
            incident.get("assignedTo"),
            incident.get("threatFamily"),
            incident.get("summary"),
            incident.get("impactedEntities", {}).get("users"),
            incident.get("impactedEntities", {}).get("machines"),
            incident.get("impactedEntities", {}).get("mailboxes")
        ))

        conn.commit()

    except sqlite3.Error as error:
        threat_logger.exception(f"Incident insert error: {error}")
        conn.rollback()

    finally:
        conn.close()



def insert_alert(alert, incident_id):
    """
    Inserts alert data into alerts table.

    Missing fields are handled gracefully using .get().
    """

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    try:

        cursor.execute("""
        INSERT OR IGNORE INTO alerts (
            alert_id,
            incident_id,
            title,
            category,
            severity,
            detection_source,
            machine_id,
            computer_dns_name,
            first_activity,
            last_seen
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.get("alertId"),
            incident_id,
            alert.get("title"),
            alert.get("category"),
            alert.get("severity"),
            alert.get("detectionSource"),
            alert.get("machineId"),
            alert.get("computerDnsName"),
            alert.get("firstActivity") or alert.get("firstSeen"),
            alert.get("lastSeen")
        ))

        conn.commit()

    except sqlite3.Error as error:
        threat_logger.exception(f"Alert insert error: {error}")
        conn.rollback()

    finally:
        conn.close()



def insert_ioc(incident_id, ioc_type, value):
    """
    Inserts IOC data into IOC table.

    IOC = Indicator of Compromise.

    Examples:
    - IP addresses
    - Domains
    - File hashes
    - Emails
    - Processes
    """

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    try:

        cursor.execute("""
        INSERT OR IGNORE INTO iocs (
            incident_id,
            type,
            value
        )
        VALUES (?, ?, ?)
        """, (
            incident_id,
            ioc_type,
            value
        ))

        conn.commit()

    except sqlite3.Error as error:
        threat_logger.exception(f"IOC insert error: {error}")
        conn.rollback()

    finally:
        conn.close()