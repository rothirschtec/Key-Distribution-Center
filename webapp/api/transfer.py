"""Transfer operation REST API endpoints."""

from flask import jsonify, request

from ..services import TransferService
from . import api_bp


@api_bp.route("/certificates/<cn>/transfer", methods=["POST"])
def transfer_certificate(cn: str):
    """Transfer a certificate to the IPSEC gateway.

    Args:
        cn: Certificate Common Name.

    Request body (optional):
        {
            "cert_path": "string (optional, full path to cert)"
        }

    Returns:
        JSON object with transfer status.
    """
    data = request.get_json() or {}

    # Build cert path from CN if not provided
    cert_path = data.get("cert_path")
    if not cert_path:
        # Assume standard location
        cert_path = f"STORE/certs/{cn}.pem"

    result = TransferService.transfer_certificate(cert_path)

    if result.success:
        return jsonify({
            "message": result.message,
            "output": result.output,
        })
    else:
        return jsonify({
            "error": result.message,
            "output": result.output,
            "stderr": result.error,
        }), 400


@api_bp.route("/certificates/<cn>/revoke", methods=["POST"])
def revoke_certificate(cn: str):
    """Revoke a certificate.

    Args:
        cn: Certificate Common Name.

    Request body (optional):
        {
            "cert_path": "string (optional, full path to cert)"
        }

    Returns:
        JSON object with revocation status.
    """
    data = request.get_json() or {}

    cert_path = data.get("cert_path")
    if not cert_path:
        cert_path = f"STORE/certs/{cn}.pem"

    result = TransferService.revoke_certificate(cert_path)

    if result.success:
        return jsonify({
            "message": result.message,
            "output": result.output,
        })
    else:
        return jsonify({
            "error": result.message,
            "output": result.output,
            "stderr": result.error,
        }), 400


@api_bp.route("/certificates/<cn>/reissue", methods=["POST"])
def reissue_certificate(cn: str):
    """Reissue a certificate (revoke, recreate, transfer).

    Args:
        cn: Certificate Common Name.

    Request body (optional):
        {
            "cert_path": "string (optional, full path to cert)"
        }

    Returns:
        JSON object with reissue status.
    """
    data = request.get_json() or {}

    cert_path = data.get("cert_path")
    if not cert_path:
        cert_path = f"STORE/certs/{cn}.pem"

    result = TransferService.reissue_certificate(cert_path)

    if result.success:
        return jsonify({
            "message": result.message,
            "output": result.output,
        })
    else:
        return jsonify({
            "error": result.message,
            "output": result.output,
            "stderr": result.error,
        }), 400


@api_bp.route("/certificates/<cn>/info", methods=["GET"])
def certificate_info(cn: str):
    """Get certificate information using shell script.

    This provides more detailed output from ipsec pki.

    Args:
        cn: Certificate Common Name.

    Returns:
        JSON object with certificate information.
    """
    cert_path = f"STORE/certs/{cn}.pem"
    result = TransferService.get_certificate_info(cert_path)

    if result.success:
        return jsonify({
            "output": result.output,
        })
    else:
        return jsonify({
            "error": result.message,
            "stderr": result.error,
        }), 404
