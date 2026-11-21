import os
from datetime import timedelta
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

class Config:
    # Flask Security
    SECRET_KEY = os.environ.get("SECRET_KEY", "cyber-soc-secret-key-super-secure-change-in-prod-2026")
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Database
    DATABASE_PATH = os.path.join(BASE_DIR, "database", "surface_monitoring.db")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", f"sqlite:///{DATABASE_PATH}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Cybersecurity Engine Settings
    NMAP_PATH = os.environ.get("NMAP_PATH", "nmap")
    NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
    NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    SCAN_DEFAULT_TIMEOUT = int(os.environ.get("SCAN_DEFAULT_TIMEOUT", 300))
    DEMO_LAB_SIMULATION = os.environ.get("DEMO_LAB_SIMULATION", "true").lower() in ("true", "1", "yes")

    # Storage paths
    REPORTS_DIR = os.path.join(BASE_DIR, "reports")
    STATIC_DIR = os.path.join(BASE_DIR, "static")
    
    # Audit & Monitoring
    AUDIT_LOG_ENABLED = True
    MAX_CONCURRENT_SCANS = 2
