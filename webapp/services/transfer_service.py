"""Transfer service layer for the KDC web application.

This service wraps the existing shell scripts for certificate transfer,
revocation, and reissue operations. Also provides Python-native reissue
for multi-tenant mode.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from flask import current_app

# Add scripts directory to path for kdc import
_scripts_dir = Path(__file__).resolve().parent.parent.parent / "central" / "scripts"
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))

from kdc import OperationResult, CA, CertificateManager

from .ca_service import CAService


class TransferService:
    """Service for certificate transfer and related operations."""

    @staticmethod
    def get_scripts_dir() -> Path:
        """Get the scripts directory from config or default."""
        try:
            return Path(current_app.config["SCRIPTS_DIR"])
        except RuntimeError:
            # Outside application context, use default
            return _scripts_dir

    @staticmethod
    def get_store_dir() -> Path:
        """Get the STORE directory from config or default."""
        try:
            return Path(current_app.config["STORE_DIR"])
        except RuntimeError:
            return _scripts_dir / "STORE"

    @classmethod
    def _run_script(
        cls,
        script_name: str,
        args: list[str],
        timeout: int = 300,
    ) -> OperationResult:
        """Run a shell script and capture output.

        Args:
            script_name: Name of the script to run.
            args: Arguments to pass to the script.
            timeout: Timeout in seconds.

        Returns:
            OperationResult with success status and output.
        """
        scripts_dir = cls.get_scripts_dir()
        script_path = scripts_dir / script_name

        if not script_path.exists():
            return OperationResult(
                success=False,
                message=f"Script not found: {script_name}",
                error=f"Script path does not exist: {script_path}"
            )

        try:
            result = subprocess.run(
                [str(script_path)] + args,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(scripts_dir),
            )

            if result.returncode == 0:
                return OperationResult(
                    success=True,
                    message=f"Script {script_name} completed successfully",
                    output=result.stdout,
                    data={"returncode": result.returncode}
                )
            else:
                return OperationResult(
                    success=False,
                    message=f"Script {script_name} failed with code {result.returncode}",
                    output=result.stdout,
                    error=result.stderr,
                    data={"returncode": result.returncode}
                )

        except subprocess.TimeoutExpired:
            return OperationResult(
                success=False,
                message=f"Script {script_name} timed out after {timeout}s",
                error="Operation timed out"
            )
        except Exception as exc:
            return OperationResult(
                success=False,
                message=f"Failed to run script {script_name}: {exc}",
                error=str(exc)
            )

    @classmethod
    def transfer_certificate(
        cls,
        cert_path: str,
        domain: str | None = None,
        ca_name: str | None = None,
    ) -> OperationResult:
        """Transfer a certificate to the IPSEC gateway.

        Uses SSH settings from CA configuration if available,
        otherwise falls back to cert-transfer.sh script.

        Args:
            cert_path: Path to the certificate file.
            domain: CA domain (for SSH settings lookup).
            ca_name: CA name (for SSH settings lookup).

        Returns:
            OperationResult with success status.
        """
        from .settings_service import SettingsService

        # Try to use Python-native transfer with SSH settings
        if domain and ca_name:
            ssh_config = SettingsService.get_ssh_config(domain, ca_name)

            if ssh_config.get("host") and ssh_config.get("key_path"):
                return cls._transfer_with_ssh(cert_path, domain, ca_name, ssh_config)

        # Fall back to shell script
        scripts_dir = cls.get_scripts_dir()

        if not cert_path.startswith("STORE/"):
            cert_path_obj = Path(cert_path)
            if cert_path_obj.is_absolute():
                try:
                    cert_path = str(cert_path_obj.relative_to(scripts_dir))
                except ValueError:
                    pass

        return cls._run_script("cert-transfer.sh", [cert_path])

    @classmethod
    def _transfer_with_ssh(
        cls,
        cert_path: str,
        domain: str,
        ca_name: str,
        ssh_config: dict,
    ) -> OperationResult:
        """Transfer certificate files using SSH with configured settings.

        Args:
            cert_path: Path to the certificate file.
            domain: CA domain.
            ca_name: CA name.
            ssh_config: SSH configuration dict with host, port, user, key_path.

        Returns:
            OperationResult with success status.
        """
        cert_path_obj = Path(cert_path)
        if not cert_path_obj.exists():
            return OperationResult(
                success=False,
                message=f"Certificate not found: {cert_path}"
            )

        ssh_host = ssh_config["host"]
        ssh_port = ssh_config.get("port", "22")
        ssh_user = ssh_config.get("user", "root")
        ssh_key = ssh_config.get("key_path")

        # Build SSH options (ignore system ssh config to avoid permission issues in container)
        ssh_opts = [
            "-F", "/dev/null",  # Ignore system SSH config
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "BatchMode=yes",
            "-o", "UserKnownHostsFile=/dev/null",
            "-p", ssh_port,
        ]
        if ssh_key:
            ssh_opts.extend(["-i", ssh_key])

        ssh_target = f"{ssh_user}@{ssh_host}"

        # Get the store directory for this CA
        store_dir = CAService.get_ca_store_dir(domain, ca_name)

        # Determine files to transfer
        cert_basename = cert_path_obj.stem
        files_to_transfer = []
        transferred = []
        errors = []

        # Certificate file -> /etc/ipsec.d/certs/
        files_to_transfer.append({
            "src": cert_path_obj,
            "dest": "/etc/ipsec.d/certs/",
            "desc": "certificate"
        })

        # Private key -> /etc/ipsec.d/private/
        key_path = store_dir / "private" / cert_path_obj.name
        if key_path.exists():
            files_to_transfer.append({
                "src": key_path,
                "dest": "/etc/ipsec.d/private/",
                "desc": "private key"
            })

        # CA certificate -> /etc/ipsec.d/cacerts/
        cacerts_dir = store_dir / "cacerts"
        if cacerts_dir.exists():
            for ca_cert in cacerts_dir.glob("*.pem"):
                files_to_transfer.append({
                    "src": ca_cert,
                    "dest": "/etc/ipsec.d/cacerts/",
                    "desc": "CA certificate"
                })
                break  # Only need one CA cert

        # CRL -> /etc/ipsec.d/crls/
        crls_dir = store_dir / "crls"
        if crls_dir.exists():
            for crl_file in crls_dir.glob("*.pem"):
                files_to_transfer.append({
                    "src": crl_file,
                    "dest": "/etc/ipsec.d/crls/",
                    "desc": "CRL"
                })

        # Transfer each file using rsync
        for file_info in files_to_transfer:
            src = file_info["src"]
            dest = file_info["dest"]
            desc = file_info["desc"]

            if not src.exists():
                continue

            try:
                rsync_cmd = [
                    "rsync", "-az",
                    "-e", f"ssh {' '.join(ssh_opts)}",
                    str(src),
                    f"{ssh_target}:{dest}"
                ]

                result = subprocess.run(
                    rsync_cmd,
                    capture_output=True,
                    text=True,
                    timeout=60
                )

                if result.returncode == 0:
                    transferred.append(f"{desc}: {src.name}")
                else:
                    errors.append(f"{desc}: {result.stderr.strip()}")

            except subprocess.TimeoutExpired:
                errors.append(f"{desc}: transfer timed out")
            except Exception as exc:
                errors.append(f"{desc}: {exc}")

        # Reload IPsec on the gateway
        if transferred and not errors:
            try:
                reload_cmd = [
                    "ssh", *ssh_opts,
                    ssh_target,
                    "ipsec reload || systemctl reload strongswan || true"
                ]
                subprocess.run(reload_cmd, capture_output=True, timeout=30)
            except Exception:
                pass  # Non-fatal if reload fails

        if errors:
            return OperationResult(
                success=False,
                message=f"Transfer errors: {'; '.join(errors)}",
                data={"transferred": transferred, "errors": errors},
                error="; ".join(errors)
            )

        return OperationResult(
            success=True,
            message=f"Certificate transferred to {ssh_host}",
            data={
                "transferred": transferred,
                "ssh_host": ssh_host,
            }
        )

    @classmethod
    def revoke_certificate(cls, cert_path: str) -> OperationResult:
        """Revoke a certificate and remove associated files.

        This calls the cert-revoke-remove.sh script.

        Args:
            cert_path: Path to the certificate file.

        Returns:
            OperationResult with success status.
        """
        scripts_dir = cls.get_scripts_dir()

        if not cert_path.startswith("STORE/"):
            cert_path_obj = Path(cert_path)
            if cert_path_obj.is_absolute():
                try:
                    cert_path = str(cert_path_obj.relative_to(scripts_dir))
                except ValueError:
                    pass

        return cls._run_script("cert-revoke-remove.sh", [cert_path])

    @classmethod
    def reissue_certificate(
        cls,
        cert_path: str,
        domain: str | None = None,
        ca_name: str | None = None,
    ) -> OperationResult:
        """Reissue a certificate (delete old, create new with same CN).

        For multi-tenant mode, uses Python-native reissue.
        For single-tenant, falls back to shell script.

        Args:
            cert_path: Path to the certificate file.
            domain: CA domain (required for multi-tenant).
            ca_name: CA name (required for multi-tenant).

        Returns:
            OperationResult with success status.
        """
        # Use Python implementation for multi-tenant mode
        if CAService.is_multi_tenant() and domain and ca_name:
            cert_path_obj = Path(cert_path)

            if not cert_path_obj.exists():
                return OperationResult(
                    success=False,
                    message=f"Certificate not found: {cert_path}"
                )

            # Get the CA
            ca = CAService.get_ca_object(ca_name, domain)
            if not ca.exists():
                return OperationResult(
                    success=False,
                    message=f"CA not found: {domain}/{ca_name}. "
                            f"Expected cert at {ca.cert_path}, key at {ca.key_path}"
                )

            # Get the store directory for this CA
            store_dir = CAService.get_ca_store_dir(domain, ca_name)
            manager = CertificateManager(store_dir)

            # Get lifetime from config
            try:
                lifetime = current_app.config.get("DEFAULT_CERT_LIFETIME", 365)
            except RuntimeError:
                lifetime = 365

            # Reissue the certificate
            result = manager.reissue(cert_path_obj, ca, lifetime=lifetime)

            # Add debug info
            if result.success:
                result.data["debug"] = {
                    "ca_cert_used": str(ca.cert_path),
                    "ca_key_used": str(ca.key_path),
                    "store_dir": str(store_dir),
                }

            return result

        # Fall back to shell script for single-tenant mode
        scripts_dir = cls.get_scripts_dir()

        if not cert_path.startswith("STORE/"):
            cert_path_obj = Path(cert_path)
            if cert_path_obj.is_absolute():
                try:
                    cert_path = str(cert_path_obj.relative_to(scripts_dir))
                except ValueError:
                    pass

        return cls._run_script("cert-reissue.sh", [cert_path], timeout=600)

    @classmethod
    def get_certificate_info(cls, cert_path: str) -> OperationResult:
        """Get certificate information using the shell script.

        This calls the cert-info.sh script.

        Args:
            cert_path: Path to the certificate file.

        Returns:
            OperationResult with certificate information.
        """
        scripts_dir = cls.get_scripts_dir()

        if not cert_path.startswith("STORE/"):
            cert_path_obj = Path(cert_path)
            if cert_path_obj.is_absolute():
                try:
                    cert_path = str(cert_path_obj.relative_to(scripts_dir))
                except ValueError:
                    pass

        return cls._run_script("cert-info.sh", [cert_path])
