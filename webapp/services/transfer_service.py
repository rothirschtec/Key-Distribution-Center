"""Transfer service layer for the KDC web application.

This service wraps the existing shell scripts for certificate transfer,
revocation, and reissue operations.
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

from kdc import OperationResult


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
    def transfer_certificate(cls, cert_path: str) -> OperationResult:
        """Transfer a certificate to the IPSEC gateway.

        This calls the cert-transfer.sh script.

        Args:
            cert_path: Path to the certificate file (relative to scripts dir
                or absolute).

        Returns:
            OperationResult with success status.
        """
        # Ensure path is relative to scripts dir for the shell script
        store_dir = cls.get_store_dir()
        scripts_dir = cls.get_scripts_dir()

        if not cert_path.startswith("STORE/"):
            # Try to make relative path
            cert_path_obj = Path(cert_path)
            if cert_path_obj.is_absolute():
                try:
                    cert_path = str(cert_path_obj.relative_to(scripts_dir))
                except ValueError:
                    # Path not under scripts_dir, use as-is
                    pass

        return cls._run_script("cert-transfer.sh", [cert_path])

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
    def reissue_certificate(cls, cert_path: str) -> OperationResult:
        """Reissue a certificate (revoke, recreate, transfer).

        This calls the cert-reissue.sh script.

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
