"""Flask application configuration."""

import os
from pathlib import Path


class Config:
    """Base configuration class."""

    # Flask settings
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-key-change-in-production")

    # KDC paths - Multi-tenant mode
    # CAS_ROOT_DIR: Root directory containing all CAs organized as:
    #   CAs/<domain>/<ca-name>/STORE/{cacerts,certs,private,crls,p12}
    CAS_ROOT_DIR = Path(
        os.environ.get("CAS_ROOT_DIR", "/app/CAs")
    )

    # Legacy single-tenant mode (deprecated, use CAS_ROOT_DIR)
    STORE_DIR = Path(
        os.environ.get("STORE_DIR", "/app/central/scripts/STORE")
    )
    SCRIPTS_DIR = Path(
        os.environ.get("SCRIPTS_DIR", "/app/central/scripts")
    )

    # Multi-tenant mode flag
    MULTI_TENANT = os.environ.get("MULTI_TENANT", "true").lower() == "true"

    # Future authentication hook
    AUTH_ENABLED = os.environ.get("AUTH_ENABLED", "false").lower() == "true"

    # Default certificate settings
    DEFAULT_CA_KEY_LENGTH = int(os.environ.get("DEFAULT_CA_KEY_LENGTH", "4096"))
    DEFAULT_CA_LIFETIME = int(os.environ.get("DEFAULT_CA_LIFETIME", "3650"))
    DEFAULT_CERT_KEY_LENGTH = int(os.environ.get("DEFAULT_CERT_KEY_LENGTH", "3072"))
    DEFAULT_CERT_LIFETIME = int(os.environ.get("DEFAULT_CERT_LIFETIME", "181"))
    DEFAULT_COUNTRY = os.environ.get("DEFAULT_COUNTRY", "AT")


class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG = True
    # Use local paths for development
    CAS_ROOT_DIR = Path(
        os.environ.get(
            "CAS_ROOT_DIR",
            Path(__file__).resolve().parent.parent / "CAs"
        )
    )
    STORE_DIR = Path(
        os.environ.get(
            "STORE_DIR",
            Path(__file__).resolve().parent.parent / "central" / "scripts" / "STORE"
        )
    )
    SCRIPTS_DIR = Path(
        os.environ.get(
            "SCRIPTS_DIR",
            Path(__file__).resolve().parent.parent / "central" / "scripts"
        )
    )


class ProductionConfig(Config):
    """Production configuration."""

    DEBUG = False


class TestingConfig(Config):
    """Testing configuration."""

    TESTING = True
    STORE_DIR = Path("/tmp/kdc-test-store")
    SCRIPTS_DIR = Path("/tmp/kdc-test-scripts")
