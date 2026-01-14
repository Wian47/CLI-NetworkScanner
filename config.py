"""Configuration management for CLI Network Scanner."""

import os
from pathlib import Path


class Config:
    """Centralized configuration for NetworkScan Pro."""
    
    # Application info
    APP_NAME = "NetworkScan Pro"
    
    # Default paths
    DATA_DIR = Path("data")
    REPORTS_DIR = Path("reports")
    CACHE_DIR = Path.home() / ".cache" / "networkscan"
    
    # Database settings
    DB_FILE = DATA_DIR / "scan_history.db"
    
    # Network defaults
    DEFAULT_TIMEOUT = 2.0  # seconds
    DEFAULT_THREADS = 50
    DEFAULT_PING_COUNT = 4
    DEFAULT_MAX_HOPS = 30
    DEFAULT_PORT = 443
    
    # Common ports for quick scanning
    COMMON_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 8080, 8443]
    
    # API endpoints for IP geolocation
    GEOIP_APIS = [
        "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,district,zip,lat,lon,isp,org,as,asname,reverse,mobile,proxy,hosting,query",
        "https://ipinfo.io/{ip}/json"
    ]
    
    # Output settings
    JSON_INDENT = 2
    TABLE_WIDTH = 100
    
    @classmethod
    def ensure_dirs(cls):
        """Ensure all required directories exist."""
        cls.DATA_DIR.mkdir(exist_ok=True)
        cls.REPORTS_DIR.mkdir(exist_ok=True)
        cls.CACHE_DIR.mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def get_db_path(cls) -> Path:
        """Get the database file path, ensuring directory exists."""
        cls.DATA_DIR.mkdir(exist_ok=True)
        return cls.DB_FILE


# Environment variable overrides
if os.environ.get("NETSCAN_TIMEOUT"):
    try:
        Config.DEFAULT_TIMEOUT = float(os.environ["NETSCAN_TIMEOUT"])
    except ValueError:
        pass

if os.environ.get("NETSCAN_THREADS"):
    try:
        Config.DEFAULT_THREADS = int(os.environ["NETSCAN_THREADS"])
    except ValueError:
        pass
