"""CA service layer for the KDC web application."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from flask import current_app

# Add scripts directory to path for kdc import
_scripts_dir = Path(__file__).resolve().parent.parent.parent / "central" / "scripts"
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))

from kdc import CA, OperationResult


class CAService:
    """Service for managing Certificate Authorities."""

    @staticmethod
    def get_store_dir() -> Path:
        """Get the STORE directory from config or default."""
        try:
            return Path(current_app.config["STORE_DIR"])
        except RuntimeError:
            # Outside application context, use default
            return _scripts_dir / "STORE"

    @classmethod
    def list_cas(cls) -> list[dict[str, Any]]:
        """List all Certificate Authorities.

        Returns:
            List of dictionaries containing CA information.
        """
        store_dir = cls.get_store_dir()
        return CA.list_cas(store_dir)

    @classmethod
    def get_ca(cls, domain: str, name: str) -> dict[str, Any] | None:
        """Get a specific CA by domain and name.

        Args:
            domain: CA domain.
            name: CA name.

        Returns:
            Dictionary with CA information, or None if not found.
        """
        store_dir = cls.get_store_dir()
        ca = CA(name, domain, store_dir)

        if not ca.exists():
            return None

        result = ca.info()
        if result.success:
            return result.data
        return None

    @classmethod
    def create_ca(
        cls,
        name: str,
        domain: str,
        company: str,
        country: str | None = None,
        key_length: int | None = None,
        lifetime: int | None = None,
    ) -> OperationResult:
        """Create a new Certificate Authority.

        Args:
            name: CA name.
            domain: CA domain.
            company: Company name for the DN.
            country: Country code (defaults to config value).
            key_length: RSA key size in bits (defaults to config value).
            lifetime: CA validity in days (defaults to config value).

        Returns:
            OperationResult with success status and details.
        """
        store_dir = cls.get_store_dir()

        # Get defaults from config
        try:
            country = country or current_app.config["DEFAULT_COUNTRY"]
            key_length = key_length or current_app.config["DEFAULT_CA_KEY_LENGTH"]
            lifetime = lifetime or current_app.config["DEFAULT_CA_LIFETIME"]
        except RuntimeError:
            # Outside application context, use sensible defaults
            country = country or "AT"
            key_length = key_length or 4096
            lifetime = lifetime or 3650

        ca = CA(name, domain, store_dir)
        return ca.create(company, country, key_length, lifetime)

    @classmethod
    def get_ca_object(cls, name: str, domain: str) -> CA:
        """Get a CA object for use with certificate operations.

        Args:
            name: CA name.
            domain: CA domain.

        Returns:
            CA instance.
        """
        store_dir = cls.get_store_dir()
        return CA(name, domain, store_dir)
