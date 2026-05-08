import os
import time
import requests
from logger import threat_logger
from config import BASE_URL, EMAIL, TOKEN_FILE

def get_token():
    """
    Retrieves API token.

    First checks if a local token file already exists.
    If not, requests a new token from the API.

    Retry logic is implemented to handle temporary network problems.
    """

    # Reuse existing token if file exists
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r") as file:
            token = file.read().strip()

            if token:
                threat_logger.info("Existing token loaded from token.txt")
                return token

    # Retry token request up to 3 times
    for attempt in range(3):

        try:
            url = f"{BASE_URL}/api/auth/token"

            response = requests.post(
                url,
                json={"email": EMAIL},
                timeout=5
            )

            response.raise_for_status()

            data = response.json()

            # Validate response
            if "token" not in data:
                threat_logger.error("Token missing from API response")
                return None

            token = data["token"]

            # Save token locally
            with open(TOKEN_FILE, "w") as file:
                file.write(token)

            threat_logger.info("Token retrieved successfully")
            return token

        except requests.exceptions.Timeout as error:
            threat_logger.exception(f"Timeout error: {error}")
            time.sleep(5 * (attempt + 1))

        except requests.exceptions.HTTPError as error:
            threat_logger.exception(f"HTTP error: {error}")
            break

        except requests.exceptions.RequestException as error:
            threat_logger.exception(f"Connection error: {error}")
            time.sleep(5 * (attempt + 1))

    threat_logger.warning("Failed to retrieve token after 3 attempts")
    return None


def fetch_incidents(token):
    """
    Fetches all incidents from the API using pagination.

    Uses:
    - Rate limiting protection
    - Retry logic
    - API response validation
    - Pagination for large datasets
    """

    headers = {
        "Authorization": f"Bearer {token}"
    }

    all_incidents = []
    skip = 0
    done = False

    while not done:

        for attempt in range(3):

            try:
                response = requests.get(
                    f"{BASE_URL}/api/incidents",
                    headers=headers,
                    params={"$top": 100, "$skip": skip},
                    timeout=5
                )

                response.raise_for_status()

                data = response.json()

                # Validate response structure
                if "value" not in data:
                    threat_logger.error("Missing 'value' field in API response")
                    return all_incidents

                incidents = data["value"]

                # Validate datatype
                if not isinstance(incidents, list):
                    threat_logger.error("Incidents data is not a list")
                    return all_incidents

                all_incidents.extend(incidents)

                threat_logger.info(
                    f"Fetched page with {len(incidents)} incidents"
                )

                # Check if more pages exist
                if "@odata.nextLink" not in data:
                    done = True
                    break

                # Pagination
                skip += 100

                # Rate limiting protection
                time.sleep(1.2)

                break

            except requests.exceptions.Timeout as error:
                threat_logger.exception(f"Timeout error: {error}")
                time.sleep(5 * (attempt + 1))

            except requests.exceptions.HTTPError as error:
                threat_logger.exception(f"HTTP error: {error}")
                break

            except requests.exceptions.RequestException as error:
                threat_logger.exception(f"Connection error: {error}")
                time.sleep(5 * (attempt + 1))

    threat_logger.info(f"Total incidents fetched: {len(all_incidents)}")

    return all_incidents