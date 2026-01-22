"""CA service layer for the KDC web application.

Supports multi-tenant directory structure:
    CAs/<domain>/<ca-name>/STORE/{cacerts,certs,private,crls,p12}
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from flask import current_app

# Add scripts directory to path for kdc import
_scripts_dir = Path(__file__).resolve().parent.parent.parent / "central" / "scripts"
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))

from kdc import CA, OperationResult, parse_cert_info, run


class CAService:
    """Service for managing Certificate Authorities in multi-tenant mode."""

    @staticmethod
    def get_cas_root_dir() -> Path:
        """Get the CAs root directory from config."""
        try:
            return Path(current_app.config["CAS_ROOT_DIR"])
        except RuntimeError:
            return Path("/app/CAs")

    @staticmethod
    def is_multi_tenant() -> bool:
        """Check if multi-tenant mode is enabled."""
        try:
            return current_app.config.get("MULTI_TENANT", True)
        except RuntimeError:
            return True

    @staticmethod
    def get_store_dir() -> Path:
        """Get the legacy STORE directory (single-tenant mode)."""
        try:
            return Path(current_app.config["STORE_DIR"])
        except RuntimeError:
            return _scripts_dir / "STORE"

    @classmethod
    def get_ca_store_dir(cls, domain: str, ca_name: str) -> Path:
        """Get the STORE directory for a specific CA.

        Args:
            domain: Domain name (e.g., 'rothirsch.tech').
            ca_name: CA name (e.g., '4kMain').

        Returns:
            Path to the CA's STORE directory.
        """
        if cls.is_multi_tenant():
            return cls.get_cas_root_dir() / domain / ca_name / "STORE"
        else:
            return cls.get_store_dir()

    @classmethod
    def list_cas(cls) -> list[dict[str, Any]]:
        """List all Certificate Authorities.

        Scans the multi-tenant directory structure:
            CAs/<domain>/<ca-name>/STORE/cacerts/

        Returns:
            List of dictionaries containing CA information.
        """
        cas = []

        if cls.is_multi_tenant():
            cas_root = cls.get_cas_root_dir()
            if not cas_root.exists():
                return []

            # Scan CAs/<domain>/<ca-name>/STORE/cacerts/
            for domain_dir in cas_root.iterdir():
                if not domain_dir.is_dir():
                    continue
                domain = domain_dir.name

                for ca_dir in domain_dir.iterdir():
                    if not ca_dir.is_dir():
                        continue
                    ca_name = ca_dir.name

                    store_dir = ca_dir / "STORE"
                    cacerts_dir = store_dir / "cacerts"

                    if not cacerts_dir.exists():
                        continue

                    # Find CA certificates
                    for cert_file in cacerts_dir.glob("*.pem"):
                        ca_info = cls._parse_ca_cert(cert_file, domain, ca_name, store_dir)
                        if ca_info:
                            cas.append(ca_info)
        else:
            # Legacy single-tenant mode
            store_dir = cls.get_store_dir()
            return CA.list_cas(store_dir)

        return cas

    @classmethod
    def _parse_ca_cert(
        cls, cert_path: Path, domain: str, ca_name: str, store_dir: Path
    ) -> dict[str, Any] | None:
        """Parse a CA certificate file and extract information.

        Args:
            cert_path: Path to the CA certificate.
            domain: Domain name.
            ca_name: CA name.
            store_dir: Path to the STORE directory.

        Returns:
            Dictionary with CA information, or None on error.
        """
        try:
            result = run(
                ["ipsec", "pki", "--print", "--in", str(cert_path)],
                capture=True
            )
            info = parse_cert_info(result.stdout)
            info["name"] = ca_name
            info["domain"] = domain
            info["cert_path"] = str(cert_path)
            info["store_dir"] = str(store_dir)

            # Find corresponding private key
            key_name = cert_path.name
            key_path = store_dir / "private" / key_name
            info["key_path"] = str(key_path) if key_path.exists() else None

            return info
        except Exception as exc:
            return {
                "name": ca_name,
                "domain": domain,
                "cert_path": str(cert_path),
                "store_dir": str(store_dir),
                "error": str(exc),
            }

    @classmethod
    def get_ca(cls, domain: str, name: str) -> dict[str, Any] | None:
        """Get a specific CA by domain and name.

        Args:
            domain: CA domain.
            name: CA name.

        Returns:
            Dictionary with CA information, or None if not found.
        """
        if cls.is_multi_tenant():
            store_dir = cls.get_ca_store_dir(domain, name)
            cacerts_dir = store_dir / "cacerts"

            if not cacerts_dir.exists():
                return None

            # Find CA certificate (first .pem file in cacerts)
            for cert_file in cacerts_dir.glob("*.pem"):
                return cls._parse_ca_cert(cert_file, domain, name, store_dir)

            return None
        else:
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
        # Get defaults from config
        try:
            country = country or current_app.config["DEFAULT_COUNTRY"]
            key_length = key_length or current_app.config["DEFAULT_CA_KEY_LENGTH"]
            lifetime = lifetime or current_app.config["DEFAULT_CA_LIFETIME"]
        except RuntimeError:
            country = country or "AT"
            key_length = key_length or 4096
            lifetime = lifetime or 3650

        if cls.is_multi_tenant():
            store_dir = cls.get_ca_store_dir(domain, name)
            # Create directory structure
            store_dir.mkdir(parents=True, exist_ok=True)
            (store_dir / "cacerts").mkdir(exist_ok=True)
            (store_dir / "certs").mkdir(exist_ok=True)
            (store_dir / "private").mkdir(exist_ok=True)
            (store_dir / "crls").mkdir(exist_ok=True)
            (store_dir / "p12").mkdir(exist_ok=True)
        else:
            store_dir = cls.get_store_dir()

        ca = CA(name, domain, store_dir)
        return ca.create(company, country, key_length, lifetime)

    @classmethod
    def get_ca_object(cls, name: str, domain: str) -> CA:
        """Get a CA object for use with certificate operations.

        Args:
            name: CA name.
            domain: CA domain.

        Returns:
            CA instance configured with correct store directory.
        """
        if cls.is_multi_tenant():
            store_dir = cls.get_ca_store_dir(domain, name)
        else:
            store_dir = cls.get_store_dir()

        return CA(name, domain, store_dir)

    @classmethod
    def list_domains(cls) -> list[str]:
        """List all domains (customers).

        Returns:
            List of domain names.
        """
        if not cls.is_multi_tenant():
            return []

        cas_root = cls.get_cas_root_dir()
        if not cas_root.exists():
            return []

        return sorted([
            d.name for d in cas_root.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        ])

    @classmethod
    def list_cas_by_domain(cls, domain: str) -> list[dict[str, Any]]:
        """List all CAs for a specific domain.

        Args:
            domain: Domain name.

        Returns:
            List of CA information dictionaries.
        """
        all_cas = cls.list_cas()
        return [ca for ca in all_cas if ca.get("domain") == domain]
