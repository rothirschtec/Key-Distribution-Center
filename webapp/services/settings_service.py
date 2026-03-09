"""Settings service layer for the KDC web application.

Manages per-CA settings stored in CAs/<domain>/<ca_name>/settings.json
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from flask import current_app

from .ca_service import CAService


class SettingsService:
    """Service for managing CA-specific settings."""

    SETTINGS_FILENAME = "settings.json"
    SSH_KEY_FILENAME = "ssh_key"

    # Default settings template
    DEFAULT_SETTINGS = {
        "vpn_gateway": "",
        "ssh_host": "",
        "ssh_port": "22",
        "ssh_user": "root",
        "company_name": "",
        "support_email": "",
        "support_phone": "",
        "notes": "",
    }

    @classmethod
    def get_ca_dir(cls, domain: str, ca_name: str) -> Path:
        """Get the CA directory path.

        Args:
            domain: Domain name.
            ca_name: CA name.

        Returns:
            Path to the CA directory.
        """
        cas_root = CAService.get_cas_root_dir()
        return cas_root / domain / ca_name

    @classmethod
    def get_settings_path(cls, domain: str, ca_name: str) -> Path:
        """Get the path to settings file for a CA.

        Args:
            domain: Domain name.
            ca_name: CA name.

        Returns:
            Path to the settings.json file.
        """
        return cls.get_ca_dir(domain, ca_name) / cls.SETTINGS_FILENAME

    @classmethod
    def get_ssh_key_path(cls, domain: str, ca_name: str) -> Path:
        """Get the path to SSH key file for a CA.

        Args:
            domain: Domain name.
            ca_name: CA name.

        Returns:
            Path to the SSH key file.
        """
        return cls.get_ca_dir(domain, ca_name) / cls.SSH_KEY_FILENAME

    @classmethod
    def get_ca_settings(cls, domain: str, ca_name: str) -> dict[str, Any]:
        """Get settings for a specific CA.

        Args:
            domain: Domain name.
            ca_name: CA name.

        Returns:
            Dictionary with CA settings.
        """
        settings_path = cls.get_settings_path(domain, ca_name)

        settings = {**cls.DEFAULT_SETTINGS, "domain": domain, "ca_name": ca_name}

        if settings_path.exists():
            try:
                with open(settings_path, "r") as f:
                    saved_settings = json.load(f)
                settings.update(saved_settings)
            except (json.JSONDecodeError, IOError):
                pass

        # Check if SSH key exists
        ssh_key_path = cls.get_ssh_key_path(domain, ca_name)
        settings["has_ssh_key"] = ssh_key_path.exists()

        return settings

    @classmethod
    def save_ca_settings(cls, domain: str, ca_name: str, settings: dict[str, Any]) -> bool:
        """Save settings for a specific CA.

        Args:
            domain: Domain name.
            ca_name: CA name.
            settings: Dictionary with settings to save.

        Returns:
            True if saved successfully, False otherwise.
        """
        settings_path = cls.get_settings_path(domain, ca_name)

        # Ensure CA directory exists
        settings_path.parent.mkdir(parents=True, exist_ok=True)

        # Filter to only save known settings (excluding computed fields)
        save_data = {
            key: settings.get(key, cls.DEFAULT_SETTINGS.get(key, ""))
            for key in cls.DEFAULT_SETTINGS.keys()
        }

        try:
            with open(settings_path, "w") as f:
                json.dump(save_data, f, indent=2)
            return True
        except IOError:
            return False

    @classmethod
    def save_ssh_key(cls, domain: str, ca_name: str, ssh_key_content: str) -> bool:
        """Save SSH private key for a CA.

        Args:
            domain: Domain name.
            ca_name: CA name.
            ssh_key_content: SSH private key content.

        Returns:
            True if saved successfully, False otherwise.
        """
        ssh_key_path = cls.get_ssh_key_path(domain, ca_name)

        # Ensure CA directory exists
        ssh_key_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(ssh_key_path, "w") as f:
                f.write(ssh_key_content)
            # Set secure permissions (600)
            os.chmod(ssh_key_path, 0o600)
            return True
        except IOError:
            return False

    @classmethod
    def delete_ssh_key(cls, domain: str, ca_name: str) -> bool:
        """Delete SSH private key for a CA.

        Args:
            domain: Domain name.
            ca_name: CA name.

        Returns:
            True if deleted successfully, False otherwise.
        """
        ssh_key_path = cls.get_ssh_key_path(domain, ca_name)

        try:
            if ssh_key_path.exists():
                ssh_key_path.unlink()
            return True
        except IOError:
            return False

    @classmethod
    def get_vpn_gateway(cls, domain: str, ca_name: str | None = None) -> str:
        """Get VPN gateway for a CA, with fallback to global config.

        Args:
            domain: Domain name.
            ca_name: CA name (optional, will search all CAs in domain if not provided).

        Returns:
            VPN gateway address.
        """
        if ca_name:
            settings = cls.get_ca_settings(domain, ca_name)
            vpn_gateway = settings.get("vpn_gateway", "").strip()
            if vpn_gateway:
                return vpn_gateway
        else:
            # Search all CAs in the domain for a VPN gateway
            cas_root = CAService.get_cas_root_dir()
            domain_dir = cas_root / domain
            if domain_dir.exists():
                for ca_dir in domain_dir.iterdir():
                    if ca_dir.is_dir():
                        settings = cls.get_ca_settings(domain, ca_dir.name)
                        vpn_gateway = settings.get("vpn_gateway", "").strip()
                        if vpn_gateway:
                            return vpn_gateway

        # Fall back to global config
        try:
            return current_app.config.get("VPN_GATEWAY", "vpn.example.com")
        except RuntimeError:
            return "vpn.example.com"

    @classmethod
    def get_ssh_config(cls, domain: str, ca_name: str) -> dict[str, Any]:
        """Get SSH configuration for a CA.

        Args:
            domain: Domain name.
            ca_name: CA name.

        Returns:
            Dictionary with SSH config (host, port, user, key_path).
        """
        settings = cls.get_ca_settings(domain, ca_name)
        ssh_key_path = cls.get_ssh_key_path(domain, ca_name)

        return {
            "host": settings.get("ssh_host", "").strip(),
            "port": settings.get("ssh_port", "22").strip() or "22",
            "user": settings.get("ssh_user", "root").strip() or "root",
            "key_path": str(ssh_key_path) if ssh_key_path.exists() else None,
        }

    @classmethod
    def list_all_ca_settings(cls) -> list[dict[str, Any]]:
        """List settings for all CAs.

        Returns:
            List of settings dictionaries for each CA.
        """
        result = []
        cas_root = CAService.get_cas_root_dir()

        if not cas_root.exists():
            return result

        for domain_dir in cas_root.iterdir():
            if not domain_dir.is_dir() or domain_dir.name.startswith("."):
                continue
            domain = domain_dir.name

            for ca_dir in domain_dir.iterdir():
                if not ca_dir.is_dir() or ca_dir.name.startswith("."):
                    continue
                ca_name = ca_dir.name

                # Only include if it has a STORE directory (is a valid CA)
                if (ca_dir / "STORE").exists():
                    result.append(cls.get_ca_settings(domain, ca_name))

        return result

    # Legacy compatibility methods for domain-level settings
    @classmethod
    def get_domain_settings(cls, domain: str) -> dict[str, Any]:
        """Get settings for a domain (returns first CA's settings).

        Args:
            domain: Domain name.

        Returns:
            Dictionary with domain settings.
        """
        cas_root = CAService.get_cas_root_dir()
        domain_dir = cas_root / domain

        if domain_dir.exists():
            for ca_dir in domain_dir.iterdir():
                if ca_dir.is_dir() and (ca_dir / "STORE").exists():
                    return cls.get_ca_settings(domain, ca_dir.name)

        return {**cls.DEFAULT_SETTINGS, "domain": domain}
