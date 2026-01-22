#!/usr/bin/env python3
"""Python-based CLI and library for managing the Key Distribution Center.

This tool provides Python replacements for the original shell scripts. It
relies on the ``ipsec pki`` utility for the heavy lifting but exposes a
friendly command line interface for automation.

Can be used as a library by importing the classes and functions directly,
or as a CLI by running the script with arguments.
"""

from __future__ import annotations

import argparse
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
STORE_DIR = BASE_DIR / "STORE"


@dataclass
class OperationResult:
    """Structured result from KDC operations."""
    success: bool
    message: str
    data: dict[str, Any] = field(default_factory=dict)
    output: str = ""
    error: str = ""


def run(cmd: list[str], capture: bool = False, **kwargs) -> subprocess.CompletedProcess:
    """Run a command and raise RuntimeError on failure.

    Args:
        cmd: Command and arguments to run.
        capture: If True, capture stdout/stderr as strings.
        **kwargs: Additional arguments passed to subprocess.run.

    Returns:
        CompletedProcess instance with captured output if requested.
    """
    try:
        if capture:
            kwargs.setdefault("capture_output", True)
            kwargs.setdefault("text", True)
        return subprocess.run(cmd, check=True, **kwargs)
    except FileNotFoundError:
        raise RuntimeError(f"Command not found: {cmd[0]}")
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{exc}")


def has_ipsec_pki() -> bool:
    """Check if ipsec pki command is available."""
    try:
        subprocess.run(["ipsec", "pki", "--help"], capture_output=True, check=False)
        return True
    except FileNotFoundError:
        return False


def get_cert_info_openssl(cert_path: str | Path) -> dict[str, Any]:
    """Get certificate info using openssl (fallback when ipsec pki unavailable).

    Args:
        cert_path: Path to the certificate file.

    Returns:
        Dictionary with parsed certificate information.
    """
    cert_path = Path(cert_path)
    info: dict[str, Any] = {}

    try:
        # Get subject
        result = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-subject"],
            capture_output=True, text=True, check=True
        )
        subject_line = result.stdout.strip()
        info["subject"] = subject_line.replace("subject=", "").strip()

        # Parse subject components
        for part in info["subject"].split(","):
            part = part.strip()
            if part.startswith("CN =") or part.startswith("CN="):
                info["subject_cn"] = part.split("=", 1)[1].strip()
            elif part.startswith("O =") or part.startswith("O="):
                info["subject_o"] = part.split("=", 1)[1].strip()
            elif part.startswith("C =") or part.startswith("C="):
                info["subject_c"] = part.split("=", 1)[1].strip()

        # Get issuer
        result = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-issuer"],
            capture_output=True, text=True, check=True
        )
        info["issuer"] = result.stdout.strip().replace("issuer=", "").strip()

        # Get dates
        result = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-dates"],
            capture_output=True, text=True, check=True
        )
        for line in result.stdout.strip().split("\n"):
            if line.startswith("notBefore="):
                info["not_before"] = line.replace("notBefore=", "").strip()
            elif line.startswith("notAfter="):
                info["not_after"] = line.replace("notAfter=", "").strip()
                # Parse expiration date
                try:
                    # Format: "Jan 22 08:52:05 2026 GMT"
                    not_after_str = info["not_after"].replace(" GMT", "")
                    not_after_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y")
                    info["not_after_dt"] = not_after_dt.isoformat()
                    info["is_expired"] = not_after_dt < datetime.now()
                except (ValueError, KeyError):
                    info["is_expired"] = None

        # Get serial
        result = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-serial"],
            capture_output=True, text=True, check=True
        )
        info["serial"] = result.stdout.strip().replace("serial=", "").strip()

        # Get public key info
        result = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-text"],
            capture_output=True, text=True, check=True
        )
        info["raw_output"] = result.stdout
        # Parse key size
        key_match = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", result.stdout)
        if key_match:
            info["pubkey_bits"] = int(key_match.group(1))
        # Check for RSA
        if "rsaEncryption" in result.stdout:
            info["pubkey_type"] = "RSA"

        # Check if CA
        info["is_ca"] = "CA:TRUE" in result.stdout

        return info

    except subprocess.CalledProcessError as exc:
        return {"error": str(exc), "cert_path": str(cert_path)}
    except Exception as exc:
        return {"error": str(exc), "cert_path": str(cert_path)}


class CA:
    """Represents a certificate authority stored under ``STORE``."""

    def __init__(self, name: str, domain: str, store_dir: Path = STORE_DIR):
        self.name = name
        self.domain = domain
        self.store_dir = store_dir
        self.private_dir = store_dir / "private"
        self.cacert_dir = store_dir / "cacerts"
        self.private_dir.mkdir(parents=True, exist_ok=True)
        self.cacert_dir.mkdir(exist_ok=True)
        # Cache for discovered paths
        self._cert_path: Path | None = None
        self._key_path: Path | None = None

    @property
    def key_path(self) -> Path:
        """Get CA private key path, auto-discovering if needed."""
        if self._key_path and self._key_path.exists():
            return self._key_path
        # Try standard naming first
        standard_path = self.private_dir / f"ca.{self.domain}_{self.name}.pem"
        if standard_path.exists():
            self._key_path = standard_path
            return standard_path
        # Try to find any CA key that matches
        for key_file in self.private_dir.glob("ca*.pem"):
            self._key_path = key_file
            return key_file
        # Return standard path even if doesn't exist (for creation)
        return standard_path

    @property
    def cert_path(self) -> Path:
        """Get CA certificate path, auto-discovering if needed."""
        if self._cert_path and self._cert_path.exists():
            return self._cert_path
        # Try standard naming first
        standard_path = self.cacert_dir / f"ca.{self.domain}_{self.name}.pem"
        if standard_path.exists():
            self._cert_path = standard_path
            return standard_path
        # Try to find any CA cert in cacerts directory
        for cert_file in self.cacert_dir.glob("*.pem"):
            self._cert_path = cert_file
            return cert_file
        # Return standard path even if doesn't exist (for creation)
        return standard_path

    def exists(self) -> bool:
        """Check if the CA already exists."""
        return self.cert_path.exists() and self.key_path.exists()

    def create(self, company: str, country: str = "AT", key_length: int = 4096, lifetime: int = 3650) -> OperationResult:
        """Create the CA key and certificate.

        Returns:
            OperationResult with success status and details.
        """
        if self.exists():
            return OperationResult(
                success=False,
                message=f"CA already exists: {self.cert_path}",
                data={"cert_path": str(self.cert_path), "key_path": str(self.key_path)}
            )

        try:
            with open(self.key_path, "wb") as key_file:
                run([
                    "ipsec", "pki", "--gen", "--type", "rsa",
                    "--size", str(key_length), "--outform", "pem",
                ], stdout=key_file)

            with open(self.cert_path, "wb") as cert_file:
                run([
                    "ipsec", "pki", "--self", "--ca", "--lifetime", str(lifetime),
                    "--in", str(self.key_path), "--type", "rsa",
                    "--dn", f"C={country}, O={company}, CN=strongSwan Root CA | {self.name}",
                    "--outform", "pem",
                ], stdout=cert_file)

            return OperationResult(
                success=True,
                message=f"CA created: {self.cert_path}",
                data={
                    "name": self.name,
                    "domain": self.domain,
                    "cert_path": str(self.cert_path),
                    "key_path": str(self.key_path),
                    "company": company,
                    "country": country,
                    "key_length": key_length,
                    "lifetime": lifetime,
                }
            )
        except RuntimeError as exc:
            return OperationResult(
                success=False,
                message=str(exc),
                error=str(exc)
            )

    def info(self) -> OperationResult:
        """Get CA certificate information.

        Returns:
            OperationResult with parsed certificate info.
        """
        if not self.exists():
            return OperationResult(
                success=False,
                message=f"CA does not exist: {self.cert_path}"
            )

        try:
            result = run(
                ["ipsec", "pki", "--print", "--in", str(self.cert_path)],
                capture=True
            )
            info = parse_cert_info(result.stdout)
            info["name"] = self.name
            info["domain"] = self.domain
            info["cert_path"] = str(self.cert_path)
            info["key_path"] = str(self.key_path)
            return OperationResult(
                success=True,
                message="CA info retrieved",
                data=info,
                output=result.stdout
            )
        except RuntimeError as exc:
            return OperationResult(
                success=False,
                message=str(exc),
                error=str(exc)
            )

    @staticmethod
    def list_cas(store_dir: Path = STORE_DIR) -> list[dict[str, Any]]:
        """List all CAs in the store.

        Returns:
            List of dictionaries with CA information.
        """
        cacert_dir = store_dir / "cacerts"
        if not cacert_dir.exists():
            return []

        cas = []
        for cert_file in cacert_dir.glob("ca.*.pem"):
            # Parse filename: ca.<domain>_<name>.pem
            name_part = cert_file.stem[3:]  # Remove "ca." prefix
            if "_" in name_part:
                domain, name = name_part.rsplit("_", 1)
            else:
                domain = ""
                name = name_part

            ca = CA(name, domain, store_dir)
            info_result = ca.info()
            if info_result.success:
                cas.append(info_result.data)
            else:
                cas.append({
                    "name": name,
                    "domain": domain,
                    "cert_path": str(cert_file),
                    "error": info_result.message,
                })

        return cas


def parse_cert_info(output: str) -> dict[str, Any]:
    """Parse ipsec pki --print output into a dictionary.

    Args:
        output: Output from ipsec pki --print command.

    Returns:
        Dictionary with parsed certificate information.
    """
    info: dict[str, Any] = {"raw_output": output}

    # Parse subject DN
    subject_match = re.search(r'subject:\s*"([^"]+)"', output)
    if subject_match:
        info["subject"] = subject_match.group(1)
        # Parse individual DN components
        dn = subject_match.group(1)
        for component in ["C", "O", "CN"]:
            match = re.search(rf'{component}=([^,]+)', dn)
            if match:
                info[f"subject_{component.lower()}"] = match.group(1).strip()

    # Parse issuer DN
    issuer_match = re.search(r'issuer:\s*"([^"]+)"', output)
    if issuer_match:
        info["issuer"] = issuer_match.group(1)

    # Parse validity dates
    not_before_match = re.search(r'not before:\s*(.+)', output)
    if not_before_match:
        info["not_before"] = not_before_match.group(1).strip()

    not_after_match = re.search(r'not after:\s*(.+)', output)
    if not_after_match:
        info["not_after"] = not_after_match.group(1).strip()
        # Try to parse as datetime and check if expired
        try:
            # Format: "Jan 22 08:52:05 2026"
            not_after_dt = datetime.strptime(
                info["not_after"].split(",")[0].strip(),
                "%b %d %H:%M:%S %Y"
            )
            info["not_after_dt"] = not_after_dt.isoformat()
            info["is_expired"] = not_after_dt < datetime.now()
        except (ValueError, IndexError):
            info["is_expired"] = None

    # Parse serial number
    serial_match = re.search(r'serial:\s*([0-9a-f:]+)', output, re.IGNORECASE)
    if serial_match:
        info["serial"] = serial_match.group(1).strip()

    # Parse public key info
    pubkey_match = re.search(r'pubkey:\s*(\w+)\s+(\d+)\s*bits', output)
    if pubkey_match:
        info["pubkey_type"] = pubkey_match.group(1)
        info["pubkey_bits"] = int(pubkey_match.group(2))

    # Parse SAN (Subject Alternative Names)
    san_match = re.search(r'altNames:\s*(.+)', output)
    if san_match:
        info["san"] = san_match.group(1).strip()

    # Check for CA flag
    info["is_ca"] = "CA" in output or "ca" in output.lower()

    return info


class CertificateManager:
    """Manages certificates stored under ``STORE``."""

    def __init__(self, store_dir: Path = STORE_DIR):
        self.store_dir = store_dir
        self.private_dir = store_dir / "private"
        self.cert_dir = store_dir / "certs"
        self.p12_dir = store_dir / "p12"
        self.private_dir.mkdir(parents=True, exist_ok=True)
        self.cert_dir.mkdir(exist_ok=True)
        self.p12_dir.mkdir(exist_ok=True)

    def create(
        self,
        cn: str,
        ca: CA,
        company: str,
        country: str = "AT",
        key_length: int = 3072,
        lifetime: int = 181,
        cert_type: str = "user",
        target_os: str = "linux",
    ) -> OperationResult:
        """Create a certificate signed by ``ca``.

        Args:
            cn: Common Name for the certificate.
            ca: CA to sign the certificate.
            company: Company name for the DN.
            country: Country code for the DN.
            key_length: RSA key size in bits.
            lifetime: Certificate validity in days.
            cert_type: Type of certificate: "user", "vpn", or "host".
            target_os: Target OS for user certs: "linux", "mac", "android".

        Returns:
            OperationResult with success status and details.
        """
        # Determine certificate filename (include CA name for uniqueness)
        cert_basename = f"{cn}-{ca.name}"
        private_key = self.private_dir / f"{cert_basename}.pem"
        cert_file = self.cert_dir / f"{cert_basename}.pem"

        if cert_file.exists():
            return OperationResult(
                success=False,
                message=f"Certificate already exists: {cert_file}",
                data={"cert_path": str(cert_file)}
            )

        if not ca.exists():
            return OperationResult(
                success=False,
                message=f"CA does not exist: {ca.cert_path}"
            )

        p12_path = None
        p12_password = None

        try:
            if has_ipsec_pki():
                # Use ipsec pki (preferred)
                self._create_with_ipsec(
                    private_key, cert_file, ca, cn, company, country,
                    key_length, lifetime, cert_type
                )
            else:
                # Fallback to OpenSSL
                self._create_with_openssl(
                    private_key, cert_file, ca, cn, company, country,
                    key_length, lifetime, cert_type
                )

            # Create PKCS#12 bundle for all certificate types
            p12_result = self._create_p12(
                cert_file, private_key, ca, cn, company, target_os
            )
            if p12_result:
                p12_path, p12_password = p12_result

            result_data = {
                "cn": cn,
                "cert_path": str(cert_file),
                "key_path": str(private_key),
                "ca_name": ca.name,
                "ca_domain": ca.domain,
                "cert_type": cert_type,
                "company": company,
                "country": country,
                "key_length": key_length,
                "lifetime": lifetime,
            }

            if p12_path:
                result_data["p12_path"] = str(p12_path)
                result_data["p12_password"] = p12_password

            return OperationResult(
                success=True,
                message=f"Certificate created: {cert_file}",
                data=result_data
            )
        except RuntimeError as exc:
            # Clean up on failure
            private_key.unlink(missing_ok=True)
            cert_file.unlink(missing_ok=True)
            return OperationResult(
                success=False,
                message=str(exc),
                error=str(exc)
            )

    def _create_with_ipsec(
        self,
        private_key: Path,
        cert_file: Path,
        ca: CA,
        cn: str,
        company: str,
        country: str,
        key_length: int,
        lifetime: int,
        cert_type: str,
    ) -> None:
        """Create certificate using ipsec pki."""
        # Generate private key
        with open(private_key, "wb") as key_file:
            run([
                "ipsec", "pki", "--gen", "--type", "rsa",
                "--size", str(key_length), "--outform", "pem",
            ], stdout=key_file)
        private_key.chmod(0o600)

        # Get public key
        pub = run([
            "ipsec", "pki", "--pub", "--in", str(private_key), "--type", "rsa",
        ], stdout=subprocess.PIPE)

        # Build issue command based on cert type
        issue_cmd = [
            "ipsec", "pki", "--issue", "--lifetime", str(lifetime),
            "--cacert", str(ca.cert_path), "--cakey", str(ca.key_path),
            "--dn", f"C={country}, O={company}, CN={cn}",
            "--san", cn, "--outform", "pem",
        ]

        # Add flags for VPN gateway certificates
        if cert_type.lower() == "vpn":
            issue_cmd.extend(["--flag", "serverAuth", "--flag", "ikeIntermediate"])

        with open(cert_file, "wb") as cf:
            run(issue_cmd, input=pub.stdout, stdout=cf)

    def _create_with_openssl(
        self,
        private_key: Path,
        cert_file: Path,
        ca: CA,
        cn: str,
        company: str,
        country: str,
        key_length: int,
        lifetime: int,
        cert_type: str,
    ) -> None:
        """Create certificate using OpenSSL (fallback when ipsec pki unavailable)."""
        # Generate private key
        subprocess.run([
            "openssl", "genrsa", "-out", str(private_key), str(key_length)
        ], check=True, capture_output=True)
        private_key.chmod(0o600)

        # Create CSR
        csr_file = private_key.with_suffix(".csr")
        subject = f"/C={country}/O={company}/CN={cn}"
        subprocess.run([
            "openssl", "req", "-new", "-key", str(private_key),
            "-out", str(csr_file), "-subj", subject
        ], check=True, capture_output=True)

        # Create extensions file for SAN
        ext_file = private_key.with_suffix(".ext")
        ext_content = f"subjectAltName=email:{cn}\n"
        if cert_type.lower() == "vpn":
            ext_content += "extendedKeyUsage=serverAuth\n"
        ext_file.write_text(ext_content)

        try:
            # Sign with CA
            subprocess.run([
                "openssl", "x509", "-req",
                "-in", str(csr_file),
                "-CA", str(ca.cert_path),
                "-CAkey", str(ca.key_path),
                "-CAcreateserial",
                "-out", str(cert_file),
                "-days", str(lifetime),
                "-sha384",
                "-extfile", str(ext_file),
            ], check=True, capture_output=True)
        finally:
            # Clean up temp files
            csr_file.unlink(missing_ok=True)
            ext_file.unlink(missing_ok=True)

    def _create_p12(
        self,
        cert_file: Path,
        private_key: Path,
        ca: CA,
        cn: str,
        company: str,
        target_os: str = "linux",
    ) -> tuple[Path, str] | None:
        """Create a PKCS#12 bundle for user certificates.

        Args:
            cert_file: Path to the certificate.
            private_key: Path to the private key.
            ca: Certificate Authority.
            cn: Common Name.
            company: Company name.
            target_os: Target OS ("linux", "mac", "android").

        Returns:
            Tuple of (p12_path, password) or None on failure.
        """
        try:
            # Generate password using pwgen if available, otherwise use secrets
            try:
                result = subprocess.run(
                    ["pwgen", "-s", "-A", "-B", "22", "1"],
                    capture_output=True, text=True, check=True
                )
                password = result.stdout.strip().replace("/", "").replace("&", "")
            except (FileNotFoundError, subprocess.CalledProcessError):
                import secrets
                import string
                chars = string.ascii_letters + string.digits
                password = "".join(secrets.choice(chars) for _ in range(22))

            p12_path = self.p12_dir / f"{cert_file.stem}.p12"
            pass_path = self.p12_dir / f"{cert_file.stem}.pass"

            # Build openssl pkcs12 command
            openssl_cmd = [
                "openssl", "pkcs12", "-export",
                "-inkey", str(private_key),
                "-in", str(cert_file),
                "-name", f"VPN Certificate - {company}, {cn}",
                "-certfile", str(ca.cert_path),
                "-password", f"pass:{password}",
                "-out", str(p12_path),
            ]

            # Add -legacy flag for macOS and Android compatibility
            if target_os.lower() in ("mac", "android"):
                openssl_cmd.append("-legacy")

            subprocess.run(openssl_cmd, check=True, capture_output=True)

            # Save password to file
            pass_path.write_text(password)
            pass_path.chmod(0o600)

            return p12_path, password

        except Exception as exc:
            # Log but don't fail certificate creation
            print(f"Warning: Failed to create p12: {exc}")
            return None

    def generate_p12(
        self,
        cert: Path | str,
        ca: CA,
        company: str = "Unknown",
        target_os: str = "linux",
    ) -> OperationResult:
        """Generate a P12 bundle for an existing certificate.

        Args:
            cert: Path to the certificate file or CN.
            ca: CA that signed the certificate.
            company: Company name for the P12 friendly name.
            target_os: Target OS ("linux", "mac", "android").

        Returns:
            OperationResult with p12_path and password.
        """
        # Find the certificate
        if isinstance(cert, str) and not cert.endswith(".pem"):
            matches = list(self.cert_dir.glob(f"{cert}*.pem"))
            if not matches:
                return OperationResult(
                    success=False,
                    message=f"Certificate not found: {cert}"
                )
            cert_path = matches[0]
        else:
            cert_path = Path(cert) if isinstance(cert, str) else cert

        if not cert_path.exists():
            return OperationResult(
                success=False,
                message=f"Certificate not found: {cert_path}"
            )

        # Find the private key
        private_key = self.private_dir / cert_path.name
        if not private_key.exists():
            return OperationResult(
                success=False,
                message=f"Private key not found: {private_key}"
            )

        # Extract CN from filename
        basename = cert_path.stem
        if f"-{ca.name}" in basename:
            cn = basename.replace(f"-{ca.name}", "")
        else:
            cn = basename

        # Check if P12 already exists
        p12_path = self.p12_dir / f"{cert_path.stem}.p12"
        if p12_path.exists():
            # Read existing password
            pass_path = self.p12_dir / f"{cert_path.stem}.pass"
            password = pass_path.read_text().strip() if pass_path.exists() else None
            return OperationResult(
                success=True,
                message=f"P12 bundle already exists: {p12_path}",
                data={
                    "p12_path": str(p12_path),
                    "p12_password": password,
                    "already_existed": True,
                }
            )

        # Create the P12 bundle
        p12_result = self._create_p12(
            cert_path, private_key, ca, cn, company, target_os
        )

        if p12_result:
            p12_path, password = p12_result
            return OperationResult(
                success=True,
                message=f"P12 bundle created: {p12_path}",
                data={
                    "p12_path": str(p12_path),
                    "p12_password": password,
                    "cn": cn,
                }
            )
        else:
            return OperationResult(
                success=False,
                message="Failed to create P12 bundle"
            )

    def info(self, cert: Path | str) -> OperationResult:
        """Get certificate information.

        Args:
            cert: Path to the certificate file.

        Returns:
            OperationResult with parsed certificate info.
        """
        cert_path = Path(cert) if isinstance(cert, str) else cert

        if not cert_path.exists():
            return OperationResult(
                success=False,
                message=f"Certificate not found: {cert_path}"
            )

        try:
            result = run(
                ["ipsec", "pki", "--print", "--in", str(cert_path)],
                capture=True
            )
            info = parse_cert_info(result.stdout)
            info["cert_path"] = str(cert_path)

            # Try to find corresponding private key
            key_path = self.private_dir / cert_path.name
            info["key_path"] = str(key_path) if key_path.exists() else None

            return OperationResult(
                success=True,
                message="Certificate info retrieved",
                data=info,
                output=result.stdout
            )
        except RuntimeError as exc:
            return OperationResult(
                success=False,
                message=str(exc),
                error=str(exc)
            )

    def list_certificates(self) -> list[dict[str, Any]]:
        """List all certificates in the store.

        Returns:
            List of dictionaries with certificate information.
        """
        if not self.cert_dir.exists():
            return []

        certs = []
        for cert_file in self.cert_dir.glob("*.pem"):
            # Skip CA certificates that might be in wrong directory
            if cert_file.name.startswith("ca."):
                continue

            info_result = self.info(cert_file)
            if info_result.success:
                certs.append(info_result.data)
            else:
                certs.append({
                    "cert_path": str(cert_file),
                    "cn": cert_file.stem,
                    "error": info_result.message,
                })

        return certs

    def revoke(self, cert: Path | str, ca: CA, reason: str = "key-compromise") -> OperationResult:
        """Revoke a certificate and update the CRL.

        Args:
            cert: Path to the certificate file or CN.
            ca: Certificate Authority that issued the certificate.
            reason: Revocation reason (key-compromise, ca-compromise,
                    affiliation-changed, superseded, cessation-of-operation).

        Returns:
            OperationResult with success status.
        """
        # Resolve certificate path
        if isinstance(cert, str) and not cert.endswith(".pem"):
            matches = list(self.cert_dir.glob(f"{cert}*.pem"))
            if not matches:
                return OperationResult(
                    success=False,
                    message=f"Certificate not found: {cert}"
                )
            cert_path = matches[0]
        else:
            cert_path = Path(cert) if isinstance(cert, str) else cert

        if not cert_path.exists():
            return OperationResult(
                success=False,
                message=f"Certificate not found: {cert_path}"
            )

        if not ca.exists():
            return OperationResult(
                success=False,
                message=f"CA does not exist: {ca.cert_path}"
            )

        # Ensure CRL directory exists
        crl_dir = self.store_dir / "crls"
        crl_dir.mkdir(exist_ok=True)

        crl_file = crl_dir / f"crl.{ca.domain}_{ca.name}.pem"

        try:
            if has_ipsec_pki():
                self._revoke_with_ipsec(cert_path, ca, crl_file, crl_dir, reason)
            else:
                self._revoke_with_openssl(cert_path, ca, crl_file, reason)

            return OperationResult(
                success=True,
                message=f"Certificate revoked: {cert_path.name}",
                data={
                    "cert_path": str(cert_path),
                    "crl_path": str(crl_file),
                    "reason": reason,
                }
            )

        except RuntimeError as exc:
            return OperationResult(
                success=False,
                message=f"Failed to revoke certificate: {exc}",
                error=str(exc)
            )

    def _revoke_with_ipsec(
        self, cert_path: Path, ca: CA, crl_file: Path, crl_dir: Path, reason: str
    ) -> None:
        """Revoke certificate and update CRL using ipsec pki."""
        signcrl_cmd = [
            "ipsec", "pki", "--signcrl",
            "--reason", reason,
            "--cacert", str(ca.cert_path),
            "--cakey", str(ca.key_path),
            "--cert", str(cert_path),
            "--outform", "pem",
        ]

        if crl_file.exists():
            crl_tmp = crl_dir / f"crl.{ca.domain}_{ca.name}.pem.tmp"
            crl_tmp.write_bytes(crl_file.read_bytes())
            signcrl_cmd.extend(["--lastcrl", str(crl_tmp)])
            result = run(signcrl_cmd, capture=True)
            crl_file.write_text(result.stdout)
            crl_tmp.unlink()
        else:
            result = run(signcrl_cmd, capture=True)
            crl_file.write_text(result.stdout)

    def _revoke_with_openssl(
        self, cert_path: Path, ca: CA, crl_file: Path, reason: str
    ) -> None:
        """Revoke certificate and update CRL using OpenSSL."""
        # Get certificate serial number
        result = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-serial"],
            capture_output=True, text=True, check=True
        )
        serial = result.stdout.strip().replace("serial=", "")

        # Map reason to OpenSSL reason code
        reason_map = {
            "key-compromise": "keyCompromise",
            "ca-compromise": "CACompromise",
            "affiliation-changed": "affiliationChanged",
            "superseded": "superseded",
            "cessation-of-operation": "cessationOfOperation",
        }
        openssl_reason = reason_map.get(reason, "unspecified")

        # Create/update index file for tracking revoked certs
        index_file = self.store_dir / "index.txt"
        index_attr = self.store_dir / "index.txt.attr"
        crlnumber_file = self.store_dir / "crlnumber"

        # Initialize files if they don't exist
        if not index_file.exists():
            index_file.touch()
        if not index_attr.exists():
            index_attr.write_text("unique_subject = no\n")
        if not crlnumber_file.exists():
            crlnumber_file.write_text("01\n")

        # Get certificate subject for index entry
        result = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-subject", "-nameopt", "compat"],
            capture_output=True, text=True, check=True
        )
        subject = result.stdout.strip().replace("subject=", "").strip()

        # Get certificate expiry date
        result = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-enddate"],
            capture_output=True, text=True, check=True
        )
        # Parse "notAfter=Jul 22 16:26:04 2026 GMT" to "260722162604Z" format
        end_date_str = result.stdout.strip().replace("notAfter=", "")
        try:
            end_date = datetime.strptime(end_date_str.replace(" GMT", ""), "%b %d %H:%M:%S %Y")
            expiry = end_date.strftime("%y%m%d%H%M%SZ")
        except ValueError:
            expiry = "000000000000Z"

        # Add revoked entry to index (format: R\texpiry\trevoke_time,reason\tserial\tunknown\tsubject)
        revoke_time = datetime.now().strftime("%y%m%d%H%M%SZ")
        index_entry = f"R\t{expiry}\t{revoke_time},{openssl_reason}\t{serial}\tunknown\t{subject}\n"

        with open(index_file, "a") as f:
            f.write(index_entry)

        # Create minimal OpenSSL config for CRL generation
        openssl_cnf = self.store_dir / "openssl_crl.cnf"
        openssl_cnf.write_text(f"""
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = {self.store_dir}
database = $dir/index.txt
crlnumber = $dir/crlnumber
certificate = {ca.cert_path}
private_key = {ca.key_path}
default_md = sha384
default_crl_days = 30

[ crl_ext ]
authorityKeyIdentifier = keyid:always
""")

        try:
            # Generate CRL
            subprocess.run([
                "openssl", "ca", "-gencrl",
                "-config", str(openssl_cnf),
                "-out", str(crl_file),
            ], check=True, capture_output=True)
        finally:
            openssl_cnf.unlink(missing_ok=True)

    def revoke_and_delete(self, cert: Path | str, ca: CA, reason: str = "key-compromise") -> OperationResult:
        """Revoke a certificate, update CRL, and delete all associated files.

        Args:
            cert: Path to the certificate file or CN.
            ca: Certificate Authority that issued the certificate.
            reason: Revocation reason.

        Returns:
            OperationResult with success status.
        """
        # First revoke (update CRL)
        revoke_result = self.revoke(cert, ca, reason)
        if not revoke_result.success:
            return revoke_result

        # Then delete files
        delete_result = self.delete(cert)
        if not delete_result.success:
            # CRL was updated but delete failed
            return OperationResult(
                success=False,
                message=f"Certificate revoked but delete failed: {delete_result.message}",
                data={
                    "crl_updated": True,
                    "crl_path": revoke_result.data.get("crl_path"),
                },
                error=delete_result.error
            )

        # Combine results
        return OperationResult(
            success=True,
            message=f"Certificate revoked and deleted: {revoke_result.data.get('cert_path')}",
            data={
                "crl_path": revoke_result.data.get("crl_path"),
                "deleted_files": delete_result.data.get("deleted_files", []),
            }
        )

    def delete(self, cert: Path | str) -> OperationResult:
        """Delete a certificate and its associated files.

        Args:
            cert: Path to the certificate file or CN.

        Returns:
            OperationResult with success status.
        """
        if isinstance(cert, str) and not cert.endswith(".pem"):
            # Treat as CN, find the certificate
            matches = list(self.cert_dir.glob(f"{cert}*.pem"))
            if not matches:
                return OperationResult(
                    success=False,
                    message=f"Certificate not found: {cert}"
                )
            cert_path = matches[0]
        else:
            cert_path = Path(cert) if isinstance(cert, str) else cert

        if not cert_path.exists():
            return OperationResult(
                success=False,
                message=f"Certificate not found: {cert_path}"
            )

        basename = cert_path.stem
        deleted_files = []

        # Delete certificate
        cert_path.unlink()
        deleted_files.append(str(cert_path))

        # Delete private key
        key_path = self.private_dir / f"{basename}.pem"
        if key_path.exists():
            key_path.unlink()
            deleted_files.append(str(key_path))

        # Delete p12 files
        p12_path = self.p12_dir / f"{basename}.p12"
        if p12_path.exists():
            p12_path.unlink()
            deleted_files.append(str(p12_path))

        pass_path = self.p12_dir / f"{basename}.pass"
        if pass_path.exists():
            pass_path.unlink()
            deleted_files.append(str(pass_path))

        return OperationResult(
            success=True,
            message=f"Certificate deleted: {basename}",
            data={"deleted_files": deleted_files}
        )

    def reissue(
        self,
        cert: Path | str,
        ca: CA,
        company: str | None = None,
        country: str | None = None,
        key_length: int | None = None,
        lifetime: int | None = None,
        cert_type: str | None = None,
    ) -> OperationResult:
        """Reissue a certificate (delete old, create new with same CN).

        Args:
            cert: Path to the certificate file or CN.
            ca: CA to sign the new certificate.
            company: Company name (extracted from old cert if not provided).
            country: Country code (defaults to "AT" if not extractable).
            key_length: RSA key size (defaults to 3072 if not extractable).
            lifetime: Certificate validity in days (defaults to 181).
            cert_type: Type of certificate: "user", "vpn", or "host".

        Returns:
            OperationResult with success status and details.
        """
        # Find the certificate
        if isinstance(cert, str) and not cert.endswith(".pem"):
            matches = list(self.cert_dir.glob(f"{cert}*.pem"))
            if not matches:
                return OperationResult(
                    success=False,
                    message=f"Certificate not found: {cert}"
                )
            cert_path = matches[0]
        else:
            cert_path = Path(cert) if isinstance(cert, str) else cert

        if not cert_path.exists():
            return OperationResult(
                success=False,
                message=f"Certificate not found: {cert_path}"
            )

        # Get existing certificate info
        try:
            if has_ipsec_pki():
                result = run(
                    ["ipsec", "pki", "--print", "--in", str(cert_path)],
                    capture=True
                )
                old_info = parse_cert_info(result.stdout)
            else:
                old_info = get_cert_info_openssl(cert_path)
        except RuntimeError as exc:
            return OperationResult(
                success=False,
                message=f"Failed to read certificate info: {exc}",
                error=str(exc)
            )

        # Extract CN from certificate info or filename
        cn = old_info.get("subject_cn")
        if not cn:
            # Try to extract from filename: <cn>-<ca_name>.pem
            basename = cert_path.stem
            if f"-{ca.name}" in basename:
                cn = basename.replace(f"-{ca.name}", "")
            else:
                cn = basename

        # Use provided parameters or extract from old cert / use defaults
        company = company or old_info.get("subject_o", "Unknown")
        country = country or old_info.get("subject_c", "AT")
        key_length = key_length or old_info.get("pubkey_bits", 3072)
        lifetime = lifetime or 365

        # Detect cert type from flags if not provided
        if not cert_type:
            raw_output = old_info.get("raw_output", "")
            if "serverAuth" in raw_output or "ikeIntermediate" in raw_output:
                cert_type = "vpn"
            elif "@" in cn:
                cert_type = "user"
            else:
                cert_type = "host"

        # Revoke the old certificate (updates CRL) and delete files
        # Now supports both ipsec pki and OpenSSL for CRL generation
        revoke_result = self.revoke_and_delete(cert_path, ca, reason="superseded")
        if not revoke_result.success:
            return OperationResult(
                success=False,
                message=f"Failed to revoke old certificate: {revoke_result.message}",
                error=revoke_result.error
            )

        # Create the new certificate (with p12 bundle)
        create_result = self.create(
            cn=cn,
            ca=ca,
            company=company,
            country=country,
            key_length=key_length,
            lifetime=lifetime,
            cert_type=cert_type,
        )

        if create_result.success:
            create_result.message = f"Certificate reissued: {cn}"
            create_result.data["old_cert_revoked"] = True
            create_result.data["crl_path"] = revoke_result.data.get("crl_path")
            create_result.data["old_cert_deleted"] = revoke_result.data.get("deleted_files", [])

        return create_result


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for the Key Distribution Center.

    Args:
        argv: Command line arguments (defaults to sys.argv).

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    parser = argparse.ArgumentParser(prog="kdc", description="Python Key Distribution Center")
    sub = parser.add_subparsers(dest="cmd")

    # Create CA command
    ca_p = sub.add_parser("create-ca", help="create a certificate authority")
    ca_p.add_argument("--name", required=True)
    ca_p.add_argument("--domain", required=True)
    ca_p.add_argument("--company", required=True)
    ca_p.add_argument("--country", default="AT")
    ca_p.add_argument("--key-length", type=int, default=4096)
    ca_p.add_argument("--lifetime", type=int, default=3650)

    # List CAs command
    sub.add_parser("list-cas", help="list all certificate authorities")

    # Create certificate command
    cert_p = sub.add_parser("create-cert", help="create a certificate")
    cert_p.add_argument("cn")
    cert_p.add_argument("--ca-name", required=True)
    cert_p.add_argument("--domain", required=True)
    cert_p.add_argument("--company", required=True)
    cert_p.add_argument("--country", default="AT")
    cert_p.add_argument("--key-length", type=int, default=3072)
    cert_p.add_argument("--lifetime", type=int, default=181)
    cert_p.add_argument("--type", choices=["user", "vpn", "host"], default="user",
                        help="Certificate type (default: user)")

    # List certificates command
    sub.add_parser("list-certs", help="list all certificates")

    # Certificate info command
    info_p = sub.add_parser("info", help="print certificate information")
    info_p.add_argument("cert")

    # Delete certificate command
    del_p = sub.add_parser("delete-cert", help="delete a certificate")
    del_p.add_argument("cert", help="Certificate path or CN")

    args = parser.parse_args(argv)

    if args.cmd == "create-ca":
        ca = CA(args.name, args.domain)
        result = ca.create(args.company, args.country, args.key_length, args.lifetime)
        print(result.message)
        return 0 if result.success else 1

    elif args.cmd == "list-cas":
        cas = CA.list_cas()
        if not cas:
            print("No CAs found.")
            return 0
        for ca_info in cas:
            print(f"  {ca_info.get('domain', 'unknown')}_{ca_info.get('name', 'unknown')}")
            if "subject_cn" in ca_info:
                print(f"    CN: {ca_info['subject_cn']}")
            if "not_after" in ca_info:
                print(f"    Expires: {ca_info['not_after']}")
        return 0

    elif args.cmd == "create-cert":
        ca = CA(args.ca_name, args.domain)
        cert_mgr = CertificateManager()
        result = cert_mgr.create(
            args.cn, ca, args.company, args.country,
            args.key_length, args.lifetime, args.type
        )
        print(result.message)
        return 0 if result.success else 1

    elif args.cmd == "list-certs":
        cert_mgr = CertificateManager()
        certs = cert_mgr.list_certificates()
        if not certs:
            print("No certificates found.")
            return 0
        for cert_info in certs:
            cn = cert_info.get("subject_cn", cert_info.get("cn", "unknown"))
            expired = cert_info.get("is_expired")
            status = " [EXPIRED]" if expired else ""
            print(f"  {cn}{status}")
            if "not_after" in cert_info:
                print(f"    Expires: {cert_info['not_after']}")
        return 0

    elif args.cmd == "info":
        cert_mgr = CertificateManager()
        result = cert_mgr.info(Path(args.cert))
        if result.success:
            print(result.output)
        else:
            print(result.message)
        return 0 if result.success else 1

    elif args.cmd == "delete-cert":
        cert_mgr = CertificateManager()
        result = cert_mgr.delete(args.cert)
        print(result.message)
        if result.success and result.data.get("deleted_files"):
            for f in result.data["deleted_files"]:
                print(f"  Deleted: {f}")
        return 0 if result.success else 1

    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
