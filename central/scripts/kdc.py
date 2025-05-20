#!/usr/bin/env python3
"""Python-based CLI for managing the Key Distribution Center.

This tool provides Python replacements for the original shell scripts. It
relies on the ``ipsec pki`` utility for the heavy lifting but exposes a
friendly command line interface for automation.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
STORE_DIR = BASE_DIR / "STORE"


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command and raise RuntimeError on failure."""
    try:
        return subprocess.run(cmd, check=True, **kwargs)
    except FileNotFoundError:
        raise RuntimeError(f"Command not found: {cmd[0]}")
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{exc}")


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

    def create(self, company: str, country: str = "AT", key_length: int = 4096, lifetime: int = 3650) -> None:
        """Create the CA key and certificate."""
        run([
            "ipsec", "pki", "--gen", "--type", "rsa",
            "--size", str(key_length), "--outform", "pem",
        ], stdout=open(self.key_path, "wb"))
        run([
            "ipsec", "pki", "--self", "--ca", "--lifetime", str(lifetime),
            "--in", str(self.key_path), "--type", "rsa",
            "--dn", f"C={country}, O={company}, CN=strongSwan Root CA | {self.name}",
            "--outform", "pem",
        ], stdout=open(self.cert_path, "wb"))
        print(f"CA created: {self.cert_path}")


class CertificateManager:
    def __init__(self, store_dir: Path = STORE_DIR):
        self.store_dir = store_dir
        self.private_dir = store_dir / "private"
        self.cert_dir = store_dir / "certs"
        self.private_dir.mkdir(parents=True, exist_ok=True)
        self.cert_dir.mkdir(exist_ok=True)

    def create(self, cn: str, ca: CA, company: str, key_length: int = 3072, lifetime: int = 181) -> None:
        """Create a certificate signed by ``ca``."""
        private_key = self.private_dir / f"{cn}.pem"
        cert_file = self.cert_dir / f"{cn}.pem"
        run([
            "ipsec", "pki", "--gen", "--type", "rsa",
            "--size", str(key_length), "--outform", "pem",
        ], stdout=open(private_key, "wb"))
        pub = run([
            "ipsec", "pki", "--pub", "--in", str(private_key), "--type", "rsa",
        ], stdout=subprocess.PIPE)
        run([
            "ipsec", "pki", "--issue", "--lifetime", str(lifetime),
            "--cacert", str(ca.cert_path), "--cakey", str(ca.key_path),
            "--dn", f"C=AT, O={company}, CN={cn}",
            "--san", cn, "--outform", "pem",
        ], input=pub.stdout, stdout=open(cert_file, "wb"))
        print(f"Certificate created: {cert_file}")

    def info(self, cert: Path) -> None:
        run(["ipsec", "pki", "--print", "--in", str(cert)])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kdc", description="Python Key Distribution Center")
    sub = parser.add_subparsers(dest="cmd")

    ca_p = sub.add_parser("create-ca", help="create a certificate authority")
    ca_p.add_argument("--name", required=True)
    ca_p.add_argument("--domain", required=True)
    ca_p.add_argument("--company", required=True)
    ca_p.add_argument("--country", default="AT")
    ca_p.add_argument("--key-length", type=int, default=4096)
    ca_p.add_argument("--lifetime", type=int, default=3650)

    cert_p = sub.add_parser("create-cert", help="create a certificate")
    cert_p.add_argument("cn")
    cert_p.add_argument("--ca-name", required=True)
    cert_p.add_argument("--domain", required=True)
    cert_p.add_argument("--company", required=True)
    cert_p.add_argument("--key-length", type=int, default=3072)
    cert_p.add_argument("--lifetime", type=int, default=181)

    info_p = sub.add_parser("info", help="print certificate information")
    info_p.add_argument("cert")

    args = parser.parse_args(argv)

    if args.cmd == "create-ca":
        ca = CA(args.name, args.domain)
        ca.create(args.company, args.country, args.key_length, args.lifetime)
    elif args.cmd == "create-cert":
        ca = CA(args.ca_name, args.domain)
        cert_mgr = CertificateManager()
        cert_mgr.create(args.cn, ca, args.company, args.key_length, args.lifetime)
    elif args.cmd == "info":
        cert_mgr = CertificateManager()
        cert_mgr.info(Path(args.cert))
    else:
        parser.print_help()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
