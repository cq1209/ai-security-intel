"""Application configuration loaded from environment variables."""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
CENSYS_API_ID = os.getenv("CENSYS_API_ID", "")
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET", "")
CENSYS_PAT = os.getenv("CENSYS_PAT", "")
HACKERONE_API_TOKEN = os.getenv("HACKERONE_API_TOKEN", "")

MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017")
MONGO_DB = os.getenv("MONGO_DB", "ai_security_intel")
