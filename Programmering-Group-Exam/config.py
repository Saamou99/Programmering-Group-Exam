import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

BASE_URL = os.getenv("BASE_URL")
EMAIL = os.getenv("EMAIL")
DB_FILE = os.getenv("DB_FILE")
TOKEN_FILE = os.getenv("TOKEN_FILE")