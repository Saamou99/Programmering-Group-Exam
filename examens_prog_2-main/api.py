import requests
import time 
import os 
from logger import threat_logger
from config import BASE_URL, EMAIL

def get_token():
    if os.path.exists("token.txt"):
        with open("token.txt", "r") as f:
            token = f.read()
            return token
    for attempt in range(3):
        try:
            url = f"{BASE_URL}/api/auth/token"
            response = requests.post(url, json={"email": EMAIL})
            response.raise_for_status()
            
            token = response.json()["token"]
            with open ("token.txt", "w") as f:
                f.write(token)
            return token
        except requests.exceptions.Timeout as e:
            threat_logger.exception(f"Exception has occured: {e}")
            time.sleep(5*(attempt + 1))
        except requests.exceptions.HTTPError as e:
            threat_logger.exception(f"Exception has occured: {e}")
        except requests.exceptions.RequestException as e:
            threat_logger.exception(f"Exception has occured: {e}")
            time.sleep(5*(attempt + 1))
    else:
        threat_logger.warning("Failed to get token after 3 attempts")
    return None

def fetch_incidents(token):
    headers = {"Authorization": f"Bearer {token}"}
    all_incidents = []
    skip = 0
    done = False
    while not done:
        for attempt in range(3):
            try:
                response = requests.get(f"{BASE_URL}/api/incidents", headers=headers, params={"$top": 100, "$skip": skip})
                response.raise_for_status()
                data = response.json()
                incidents = data["value"]
                all_incidents.extend(incidents)

                if "@odata.nextLink" not in data:
                    done = True 
                    break
                time.sleep(1.2)
                skip += 100
                break
            except requests.exceptions.Timeout as e:
                threat_logger.exception(f"Exception occurred: {e}")
                time.sleep(5*(attempt + 1))
            except requests.exceptions.HTTPError as e:
                threat_logger.exception(f"Exception occurred: {e}")
                break
            except requests.exceptions.RequestException as e:
                threat_logger.exception(f"Exception occurred: {e}")
                time.sleep(5*(attempt + 1))
                

    return all_incidents
