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

    @property
    def key_path(self) -> Path:
        return self.private_dir / f"ca.{self.domain}_{self.name}.pem"

    @property
    def cert_path(self) -> Path:
        return self.cacert_dir / f"ca.{self.domain}_{self.name}.pem"

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

        try:
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

            return OperationResult(
                success=True,
                message=f"Certificate created: {cert_file}",
                data={
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
