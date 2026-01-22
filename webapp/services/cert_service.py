"""Certificate service layer for the KDC web application.

Supports multi-tenant directory structure:
    CAs/<domain>/<ca-name>/STORE/certs/
"""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path
from typing import Any

from flask import current_app, render_template_string

# Add scripts directory to path for kdc import
_scripts_dir = Path(__file__).resolve().parent.parent.parent / "central" / "scripts"
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))

from kdc import CA, CertificateManager, OperationResult, parse_cert_info, run, get_cert_info_openssl, has_ipsec_pki

from .ca_service import CAService


class CertificateService:
    """Service for managing certificates in multi-tenant mode."""

    @staticmethod
    def get_store_dir() -> Path:
        """Get the legacy STORE directory (single-tenant mode)."""
        try:
            return Path(current_app.config["STORE_DIR"])
        except RuntimeError:
            return _scripts_dir / "STORE"

    @classmethod
    def get_manager_for_ca(cls, domain: str, ca_name: str) -> CertificateManager:
        """Get a CertificateManager for a specific CA.

        Args:
            domain: CA domain.
            ca_name: CA name.

        Returns:
            CertificateManager configured with the CA's store directory.
        """
        store_dir = CAService.get_ca_store_dir(domain, ca_name)
        return CertificateManager(store_dir)

    @classmethod
    def list_certificates(cls, domain: str | None = None, ca_name: str | None = None) -> list[dict[str, Any]]:
        """List certificates, optionally filtered by domain/CA.

        Args:
            domain: Optional domain filter.
            ca_name: Optional CA name filter (requires domain).

        Returns:
            List of dictionaries containing certificate information.
        """
        certs = []

        if CAService.is_multi_tenant():
            cas_root = CAService.get_cas_root_dir()
            if not cas_root.exists():
                return []

            # Determine which domains to scan
            if domain:
                domains = [domain]
            else:
                domains = CAService.list_domains()

            for dom in domains:
                domain_dir = cas_root / dom
                if not domain_dir.exists():
                    continue

                # Determine which CAs to scan
                if ca_name and domain == dom:
                    ca_names = [ca_name]
                else:
                    ca_names = [
                        d.name for d in domain_dir.iterdir()
                        if d.is_dir() and not d.name.startswith(".")
                    ]

                for ca_n in ca_names:
                    store_dir = domain_dir / ca_n / "STORE"
                    certs_dir = store_dir / "certs"

                    if not certs_dir.exists():
                        continue

                    for cert_file in certs_dir.glob("*.pem"):
                        cert_info = cls._parse_cert(cert_file, dom, ca_n, store_dir)
                        if cert_info:
                            certs.append(cert_info)
        else:
            # Legacy single-tenant mode
            store_dir = cls.get_store_dir()
            manager = CertificateManager(store_dir)
            return manager.list_certificates()

        return certs

    @classmethod
    def _parse_cert(
        cls, cert_path: Path, domain: str, ca_name: str, store_dir: Path
    ) -> dict[str, Any] | None:
        """Parse a certificate file and extract information.

        Args:
            cert_path: Path to the certificate.
            domain: Domain name.
            ca_name: CA name.
            store_dir: Path to the STORE directory.

        Returns:
            Dictionary with certificate information, or None on error.
        """
        try:
            # Try ipsec pki first, fall back to openssl
            if has_ipsec_pki():
                result = run(
                    ["ipsec", "pki", "--print", "--in", str(cert_path)],
                    capture=True
                )
                info = parse_cert_info(result.stdout)
            else:
                # Use openssl fallback
                info = get_cert_info_openssl(cert_path)

            info["cert_path"] = str(cert_path)
            info["domain"] = domain
            info["ca_name"] = ca_name
            info["store_dir"] = str(store_dir)

            # Extract CN from filename if not in parsed info
            if "subject_cn" not in info:
                # Filename format: <cn>-<ca_name>.pem
                basename = cert_path.stem
                if f"-{ca_name}" in basename:
                    info["cn"] = basename.replace(f"-{ca_name}", "")
                else:
                    info["cn"] = basename

            # Find corresponding private key
            key_path = store_dir / "private" / cert_path.name
            info["key_path"] = str(key_path) if key_path.exists() else None

            # Check for p12 file and password
            p12_path = store_dir / "p12" / f"{cert_path.stem}.p12"
            info["p12_path"] = str(p12_path) if p12_path.exists() else None

            pass_path = store_dir / "p12" / f"{cert_path.stem}.pass"
            if pass_path.exists():
                try:
                    info["p12_password"] = pass_path.read_text().strip()
                except Exception:
                    info["p12_password"] = None
            else:
                info["p12_password"] = None

            return info
        except Exception as exc:
            return {
                "cert_path": str(cert_path),
                "domain": domain,
                "ca_name": ca_name,
                "cn": cert_path.stem,
                "error": str(exc),
            }

    @classmethod
    def get_certificate(
        cls, cn: str, domain: str | None = None, ca_name: str | None = None
    ) -> dict[str, Any] | None:
        """Get a specific certificate by CN.

        Args:
            cn: Certificate Common Name.
            domain: Optional domain filter.
            ca_name: Optional CA name filter.

        Returns:
            Dictionary with certificate information, or None if not found.
        """
        # Search all certificates
        certs = cls.list_certificates(domain=domain, ca_name=ca_name)

        # First pass: exact match on CN
        for cert in certs:
            cert_cn = cert.get("subject_cn") or cert.get("cn", "")
            if cn == cert_cn:
                return cert

        # Second pass: exact match on filename stem (without CA suffix)
        for cert in certs:
            cert_path = cert.get("cert_path", "")
            if cert_path:
                # Filename format: <cn>-<ca_name>.pem
                filename = Path(cert_path).stem
                # Check if cn matches the part before -<ca_name>
                if filename.startswith(cn + "-") or filename == cn:
                    return cert

        # Third pass: partial match (fallback for legacy compatibility)
        for cert in certs:
            cert_cn = cert.get("subject_cn") or cert.get("cn", "")
            cert_path = cert.get("cert_path", "")
            # Only match if cn is a complete segment (not a substring of another name)
            if cn in cert_cn:
                # Avoid matching "rene.zingerle" in "rene.zingerle.phone"
                # by checking if it's followed by nothing or a hyphen
                idx = cert_cn.find(cn)
                end_idx = idx + len(cn)
                if end_idx == len(cert_cn) or cert_cn[end_idx] == '-':
                    return cert

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
        # Get defaults from config
        try:
            country = country or current_app.config["DEFAULT_COUNTRY"]
            key_length = key_length or current_app.config["DEFAULT_CERT_KEY_LENGTH"]
            lifetime = lifetime or current_app.config["DEFAULT_CERT_LIFETIME"]
        except RuntimeError:
            country = country or "AT"
            key_length = key_length or 3072
            lifetime = lifetime or 181

        # Get the correct store directory for this CA
        store_dir = CAService.get_ca_store_dir(ca_domain, ca_name)

        # Check CA exists
        ca = CA(ca_name, ca_domain, store_dir)
        if not ca.exists():
            return OperationResult(
                success=False,
                message=f"CA not found: {ca_domain}/{ca_name}"
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
    def delete_certificate(
        cls, cn: str, domain: str | None = None, ca_name: str | None = None
    ) -> OperationResult:
        """Delete a certificate.

        Args:
            cn: Certificate Common Name or path.
            domain: Optional domain (required for multi-tenant).
            ca_name: Optional CA name (required for multi-tenant).

        Returns:
            OperationResult with success status.
        """
        # First find the certificate to get its location
        cert = cls.get_certificate(cn, domain=domain, ca_name=ca_name)
        if not cert:
            return OperationResult(
                success=False,
                message=f"Certificate not found: {cn}"
            )

        # Get the correct store directory
        cert_domain = cert.get("domain")
        cert_ca_name = cert.get("ca_name")

        if cert_domain and cert_ca_name:
            store_dir = CAService.get_ca_store_dir(cert_domain, cert_ca_name)
        else:
            store_dir = cls.get_store_dir()

        manager = CertificateManager(store_dir)
        cert_path = cert.get("cert_path")
        if cert_path:
            return manager.delete(Path(cert_path))
        return manager.delete(cn)

    @classmethod
    def get_expired_certificates(cls) -> list[dict[str, Any]]:
        """Get all expired certificates across all CAs.

        Returns:
            List of dictionaries containing expired certificate information.
        """
        certs = cls.list_certificates()
        return [cert for cert in certs if cert.get("is_expired")]

    @classmethod
    def get_certificate_stats(cls, domain: str | None = None, ca_name: str | None = None) -> dict[str, int]:
        """Get certificate statistics.

        Args:
            domain: Optional domain filter.
            ca_name: Optional CA name filter.

        Returns:
            Dictionary with certificate counts.
        """
        certs = cls.list_certificates(domain=domain, ca_name=ca_name)
        expired = sum(1 for cert in certs if cert.get("is_expired"))

        return {
            "total": len(certs),
            "expired": expired,
            "valid": len(certs) - expired,
        }

    @classmethod
    def list_certificates_by_ca(cls, domain: str, ca_name: str) -> list[dict[str, Any]]:
        """List all certificates for a specific CA.

        Args:
            domain: Domain name.
            ca_name: CA name.

        Returns:
            List of certificate information dictionaries.
        """
        return cls.list_certificates(domain=domain, ca_name=ca_name)

    @classmethod
    def generate_p12(
        cls,
        cn: str,
        domain: str | None = None,
        ca_name: str | None = None,
        company: str = "Unknown",
    ) -> OperationResult:
        """Generate a P12 bundle for an existing certificate.

        Args:
            cn: Certificate Common Name or path.
            domain: Optional domain filter.
            ca_name: Optional CA name filter.
            company: Company name for P12 friendly name.

        Returns:
            OperationResult with p12_path and password.
        """
        # First find the certificate to get its location
        cert = cls.get_certificate(cn, domain=domain, ca_name=ca_name)
        if not cert:
            return OperationResult(
                success=False,
                message=f"Certificate not found: {cn}"
            )

        # Get the CA
        cert_domain = cert.get("domain")
        cert_ca_name = cert.get("ca_name")

        if not cert_domain or not cert_ca_name:
            return OperationResult(
                success=False,
                message="Cannot determine CA for this certificate"
            )

        # Get CA object
        from .ca_service import CAService
        ca = CAService.get_ca_object(cert_ca_name, cert_domain)
        if not ca.exists():
            return OperationResult(
                success=False,
                message=f"CA not found: {cert_domain}/{cert_ca_name}"
            )

        # Get the store directory and manager
        store_dir = CAService.get_ca_store_dir(cert_domain, cert_ca_name)
        manager = CertificateManager(store_dir)

        # Generate P12
        cert_path = cert.get("cert_path")
        return manager.generate_p12(
            cert=cert_path,
            ca=ca,
            company=company,
        )

    @classmethod
    def generate_vpn_bundle(
        cls,
        cn: str,
        target_os: str,
        domain: str | None = None,
        ca_name: str | None = None,
        vpn_gateway: str | None = None,
    ) -> tuple[io.BytesIO, str] | None:
        """Generate a VPN setup bundle (ZIP) for a certificate.

        Args:
            cn: Certificate Common Name or path.
            target_os: Target OS ("linux", "mac", "windows").
            domain: Optional domain filter.
            ca_name: Optional CA name filter.
            vpn_gateway: VPN gateway address (defaults to config).

        Returns:
            Tuple of (BytesIO with ZIP data, filename) or None on error.
        """
        # Get certificate info
        cert = cls.get_certificate(cn, domain=domain, ca_name=ca_name)
        if not cert:
            return None

        # Get P12 path - generate if needed
        p12_path = cert.get("p12_path")
        p12_password = cert.get("p12_password")

        if not p12_path or not Path(p12_path).exists():
            # Try to generate P12
            result = cls.generate_p12(
                cn=cn,
                domain=domain,
                ca_name=ca_name,
                company=cert.get("subject_o", "Unknown"),
            )
            if result.success:
                p12_path = result.data.get("p12_path")
                p12_password = result.data.get("p12_password")
            else:
                return None

        if not p12_path or not Path(p12_path).exists():
            return None

        # Get VPN gateway from CA settings or config
        if not vpn_gateway:
            from .settings_service import SettingsService
            cert_domain = cert.get("domain")
            cert_ca_name = cert.get("ca_name")
            if cert_domain:
                vpn_gateway = SettingsService.get_vpn_gateway(cert_domain, cert_ca_name)
            else:
                try:
                    vpn_gateway = current_app.config.get("VPN_GATEWAY", "vpn.example.com")
                except RuntimeError:
                    vpn_gateway = "vpn.example.com"

        # Get CN for filenames
        cert_cn = cert.get("subject_cn") or cert.get("cn", cn)
        safe_cn = cert_cn.replace("@", "-").replace(".", "-")

        # Get company and country from certificate info
        company = cert.get("subject_o", "Unknown Company")
        country = cert.get("subject_c", "AT")

        # Template context
        context = {
            "cn": cert_cn,
            "p12_filename": Path(p12_path).name,
            "p12_password": p12_password or "unknown",
            "vpn_gateway": vpn_gateway,
            "company": company,
            "country": country,
        }

        # Get template directory
        template_dir = Path(__file__).parent.parent / "templates" / "guides"

        # Create ZIP in memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            # Add P12 file
            zf.write(p12_path, Path(p12_path).name)

            # Add OS-specific guide
            if target_os == "linux":
                # Add setup guide
                guide_template = (template_dir / "linux-vpn-setup.md.j2").read_text()
                guide_content = render_template_string(guide_template, **context)
                zf.writestr("VPN-Setup-Guide.md", guide_content)

                # Add setup script
                script_template = (template_dir / "vpn-setup.sh.j2").read_text()
                script_content = render_template_string(script_template, **context)
                zf.writestr("vpn-setup.sh", script_content)

                filename = f"vpn-{safe_cn}-linux.zip"

            elif target_os == "mac":
                guide_template = (template_dir / "mac-vpn-setup.md.j2").read_text()
                guide_content = render_template_string(guide_template, **context)
                zf.writestr("VPN-Setup-Guide.md", guide_content)
                filename = f"vpn-{safe_cn}-mac.zip"

            elif target_os == "windows":
                guide_template = (template_dir / "windows-vpn-setup.md.j2").read_text()
                guide_content = render_template_string(guide_template, **context)
                zf.writestr("VPN-Setup-Guide.md", guide_content)
                filename = f"vpn-{safe_cn}-windows.zip"

            else:
                return None

        zip_buffer.seek(0)
        return zip_buffer, filename
