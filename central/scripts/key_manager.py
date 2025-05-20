#!/usr/bin/env python3
"""Simple Python-based certificate manager for the Key Distribution Center.

This script provides a Python interface around the existing strongSwan
``ipsec pki`` tooling.  It aims to make certificate handling a bit easier
by providing a single entry point with sub commands.

The script does not yet cover all features of the original shell
implementation but demonstrates how the project could evolve towards a
Python code base.
"""

import argparse
import subprocess
import sys
from pathlib import Path


CONFIG_DIR = Path(__file__).resolve().parent / "CONFIGS"
STORE_DIR = Path(__file__).resolve().parent / "STORE"


class KeyManager:
    """Manage certificates using ``ipsec pki`` commands."""

    def __init__(self, config_dir: Path = CONFIG_DIR, store_dir: Path = STORE_DIR):
        self.config_dir = config_dir
        self.store_dir = store_dir

    def create_cert(self, cn: str, key_length: int = 3072, lifetime: int = 181):
        """Create a certificate for ``cn`` using ``ipsec pki``."""
        private_key = self.store_dir / "private" / f"{cn}.pem"
        cert_file = self.store_dir / "certs" / f"{cn}.pem"
        self.store_dir.mkdir(parents=True, exist_ok=True)
        (self.store_dir / "private").mkdir(exist_ok=True)
        (self.store_dir / "certs").mkdir(exist_ok=True)

        try:
            subprocess.run(
                [
                    "ipsec",
                    "pki",
                    "--gen",
                    "--type",
                    "rsa",
                    "--size",
                    str(key_length),
                    "--outform",
                    "pem",
                ],
                check=True,
                stdout=open(private_key, "wb"),
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            print(f"Failed to create key: {exc}", file=sys.stderr)
            return

        try:
            subprocess.run(
                [
                    "ipsec",
                    "pki",
                    "--pub",
                    "--in",
                    str(private_key),
                    "--type",
                    "rsa",
                    ],
                check=True,
                stdout=subprocess.PIPE,
            )
            # Additional certificate issuance would take place here.
            # For brevity we only generate the key in this example.
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            print(f"Failed to create certificate: {exc}", file=sys.stderr)
            return

        print(f"Created key: {private_key}")
        print(f"Certificate placeholder: {cert_file}")

    def print_info(self, cert_path: Path):
        """Print certificate information using ``ipsec pki --print``."""
        try:
            subprocess.run(["ipsec", "pki", "--print", "--in", str(cert_path)], check=True)
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            print(f"Failed to read certificate: {exc}", file=sys.stderr)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Python certificate manager")
    sub = parser.add_subparsers(dest="cmd")

    create_p = sub.add_parser("create", help="create a new certificate")
    create_p.add_argument("cn", help="Common name for certificate")
    create_p.add_argument("--key-length", type=int, default=3072)
    create_p.add_argument("--lifetime", type=int, default=181)

    info_p = sub.add_parser("info", help="print certificate information")
    info_p.add_argument("cert")

    args = parser.parse_args(argv)
    km = KeyManager()

    if args.cmd == "create":
        km.create_cert(args.cn, key_length=args.key_length, lifetime=args.lifetime)
    elif args.cmd == "info":
        km.print_info(Path(args.cert))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
