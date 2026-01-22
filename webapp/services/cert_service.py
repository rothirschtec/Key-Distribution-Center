"""Certificate service layer for the KDC web application."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from flask import current_app

# Add scripts directory to path for kdc import
_scripts_dir = Path(__file__).resolve().parent.parent.parent / "central" / "scripts"
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))

from kdc import CA, CertificateManager, OperationResult


class CertificateService:
    """Service for managing certificates."""

    @staticmethod
    def get_store_dir() -> Path:
        """Get the STORE directory from config or default."""
        try:
            return Path(current_app.config["STORE_DIR"])
        except RuntimeError:
            # Outside application context, use default
            return _scripts_dir / "STORE"

    @classmethod
    def get_manager(cls) -> CertificateManager:
        """Get a CertificateManager instance.

        Returns:
            CertificateManager configured with the correct store directory.
        """
        store_dir = cls.get_store_dir()
        return CertificateManager(store_dir)

    @classmethod
    def list_certificates(cls) -> list[dict[str, Any]]:
        """List all certificates.

        Returns:
            List of dictionaries containing certificate information.
        """
        manager = cls.get_manager()
        return manager.list_certificates()

    @classmethod
    def get_certificate(cls, cn: str) -> dict[str, Any] | None:
        """Get a specific certificate by CN.

        Args:
            cn: Certificate Common Name (can be partial).

        Returns:
            Dictionary with certificate information, or None if not found.
        """
        manager = cls.get_manager()
        cert_dir = manager.cert_dir

        # Find matching certificate files
        matches = list(cert_dir.glob(f"*{cn}*.pem"))
        if not matches:
            return None

        # Return first match
        result = manager.info(matches[0])
        if result.success:
            return result.data
        return None

    @classmethod
    def create_certificate(
        cls,
        cn: str,
        ca_name: str,
        ca_domain: str,
        company: str,
        country: str | None = None,
        key_length: int | None = None,
        lifetime: int | None = None,
        cert_type: str = "user",
    ) -> OperationResult:
        """Create a new certificate.

        Args:
            cn: Common Name for the certificate.
            ca_name: Name of the signing CA.
            ca_domain: Domain of the signing CA.
            company: Company name for the DN.
            country: Country code (defaults to config value).
            key_length: RSA key size in bits (defaults to config value).
            lifetime: Certificate validity in days (defaults to config value).
            cert_type: Type of certificate: "user", "vpn", or "host".

        Returns:
            OperationResult with success status and details.
        """
        store_dir = cls.get_store_dir()

        # Get defaults from config
        try:
            country = country or current_app.config["DEFAULT_COUNTRY"]
            key_length = key_length or current_app.config["DEFAULT_CERT_KEY_LENGTH"]
            lifetime = lifetime or current_app.config["DEFAULT_CERT_LIFETIME"]
        except RuntimeError:
            # Outside application context, use sensible defaults
            country = country or "AT"
            key_length = key_length or 3072
            lifetime = lifetime or 181

        ca = CA(ca_name, ca_domain, store_dir)
        if not ca.exists():
            return OperationResult(
                success=False,
                message=f"CA not found: {ca_domain}_{ca_name}"
            )

        manager = CertificateManager(store_dir)
        return manager.create(
            cn=cn,
            ca=ca,
            company=company,
            country=country,
            key_length=key_length,
            lifetime=lifetime,
            cert_type=cert_type,
        )

    @classmethod
    def delete_certificate(cls, cn: str) -> OperationResult:
        """Delete a certificate.

        Args:
            cn: Certificate Common Name or path.

        Returns:
            OperationResult with success status.
        """
        manager = cls.get_manager()
        return manager.delete(cn)

    @classmethod
    def get_expired_certificates(cls) -> list[dict[str, Any]]:
        """Get all expired certificates.

        Returns:
            List of dictionaries containing expired certificate information.
        """
        certs = cls.list_certificates()
        return [cert for cert in certs if cert.get("is_expired")]

    @classmethod
    def get_certificate_stats(cls) -> dict[str, int]:
        """Get certificate statistics.

        Returns:
            Dictionary with certificate counts.
        """
        certs = cls.list_certificates()
        expired = sum(1 for cert in certs if cert.get("is_expired"))

        return {
            "total": len(certs),
            "expired": expired,
            "valid": len(certs) - expired,
        }
