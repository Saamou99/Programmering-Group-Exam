import sqlite3
from logger import threat_logger
from config import DB_FILE

def create_tables():
    """
    Skaber de 3 tables som er incidents, alerts og IOCs med de relevante 
    kolonner til efterspurgt data. Denne function fejlhåndteres med en try except og 
    hvis der findes fejl bliver den logget i vores threat.log fil.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incidentId      TEXT,
                    incidentName    TEXT,
                    severity        TEXT,
                    status          TEXT,
                    createdTime     TEXT,
                    UNIQUE(incidentId)
                )
            """),
        cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alertId         TEXT,
                    incidentId      TEXT,
                    machineId       TEXT,
                    detectionSource TEXT,
                    firstActivity   TEXT,
                    UNIQUE(alertId)
                )
            """),
        cursor.execute("""
                CREATE TABLE IF NOT EXISTS IOCs(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incidentId      TEXT,
                    type            TEXT,
                    value           TEXT,
                    UNIQUE(incidentId, type, value)
                )
            """)
        conn.commit()
    except sqlite3.Error as e:
        threat_logger.exception(f"Exception occured: {e}")
    finally:
        conn.close()
     
   
def insert_incident(incidents):
    """
    I denne funktion indsætter vi de parametre som vi gerne vil have inde i vores
    database. (incidentId, incidentName, severity, status, createdTime).
    
    Vi benytter get til at hente dataen fra det data incidents.
    
    Denne funktion benytte sig også af en try except som logger fejl til threat.log.
    """
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT OR IGNORE INTO incidents (
                incidentID, incidentName, severity, status,
                createdTime
            ) VALUES (?, ?, ?, ?, ?)
        """,(
            incidents.get("incidentId"),
            incidents.get("incidentName"),
            incidents.get("severity"),
            incidents.get("status"),
            incidents.get("createdTime")
            
        ))
        conn.commit()
    except sqlite3.Error as e:
        threat_logger.exception(f"Exception occured: {e}")
    finally:
        conn.close()
        
def insert_alerts(alerts):
    """
    I denne funktion indsætter vi de parametre som vi gerne vil have inde i vores
    database. (alertId, incidentId, machineId, detectionSource, firstActivity).
    
    Vi benytter get til at hente dataen fra det data alerts.
    
    Denne funktion benytte sig også af en try except som logger fejl til threat.log.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT OR IGNORE INTO alerts (
                alertId, incidentId, machineId, detectionSource, firstActivity
            ) VALUES (?, ?, ?, ?, ?)
        """,(
            alerts.get("alertId"),
            alerts.get("incidentId"),
            alerts.get("machineId"),
            alerts.get("detectionSource"),
            alerts.get("firstActivity")
            
        ))
        conn.commit()
    except sqlite3.Error as e:
        threat_logger.exception(f"Exception occured: {e}")
    finally:
        conn.close()
        
def insert_IOCs(incidentId, ioc_type, value):
    """
    I denne funktion indsætter vi de parametre som vi gerne vil have inde i vores
    database. (incidentId, type, value).
    
    Vi benytter get til at hente dataen fra det data incidentId, ioc_type og value.
    
    Denne funktion benytte sig også af en try except som logger fejl til threat.log.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT OR IGNORE INTO IOCs (
                incidentId, type, value
            ) VALUES (?, ?, ?)
        """,(
            incidentId,
            value,
            ioc_type 
        ))
        conn.commit()
    except sqlite3.Error as e:
        threat_logger.exception(f"Exception occured: {e}")
    finally:
        conn.close()    
    