"""Certificate REST API endpoints."""

from flask import jsonify, request

from ..services import CertificateService
from . import api_bp


@api_bp.route("/certificates", methods=["GET"])
def list_certificates():
    """List all certificates.

    Query params:
        expired: Filter to only expired certificates (true/false).

    Returns:
        JSON array of certificate objects.
    """
    expired_only = request.args.get("expired", "").lower() == "true"

    if expired_only:
        certs = CertificateService.get_expired_certificates()
    else:
        certs = CertificateService.list_certificates()

    return jsonify(certs)


@api_bp.route("/certificates/stats", methods=["GET"])
def certificate_stats():
    """Get certificate statistics.

    Returns:
        JSON object with certificate counts.
    """
    stats = CertificateService.get_certificate_stats()
    return jsonify(stats)


@api_bp.route("/certificates/<cn>", methods=["GET"])
def get_certificate(cn: str):
    """Get a specific certificate by CN.

    Args:
        cn: Certificate Common Name.

    Returns:
        JSON object with certificate details, or 404 if not found.
    """
    cert = CertificateService.get_certificate(cn)
    if cert is None:
        return jsonify({"error": f"Certificate not found: {cn}"}), 404
    return jsonify(cert)


@api_bp.route("/certificates", methods=["POST"])
def create_certificate():
    """Create a new certificate.

    Request body:
        {
            "cn": "string (required)",
            "ca_name": "string (required)",
            "ca_domain": "string (required)",
            "company": "string (required)",
            "country": "string (optional, default: AT)",
            "key_length": "int (optional, default: 3072)",
            "lifetime": "int (optional, default: 181)",
            "cert_type": "string (optional, default: user)"
        }

    Returns:
        JSON object with created certificate details, or error.
    """
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body required"}), 400

    # Validate required fields
    required_fields = ["cn", "ca_name", "ca_domain", "company"]
    missing = [f for f in required_fields if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    # Validate cert_type if provided
    cert_type = data.get("cert_type", "user")
    if cert_type not in ["user", "vpn", "host"]:
        return jsonify({"error": f"Invalid cert_type: {cert_type}. Must be user, vpn, or host."}), 400

    result = CertificateService.create_certificate(
        cn=data["cn"],
        ca_name=data["ca_name"],
        ca_domain=data["ca_domain"],
        company=data["company"],
        country=data.get("country"),
        key_length=data.get("key_length"),
        lifetime=data.get("lifetime"),
        cert_type=cert_type,
    )

    if result.success:
        return jsonify(result.data), 201
    else:
        return jsonify({"error": result.message}), 400


@api_bp.route("/certificates/<cn>", methods=["DELETE"])
def delete_certificate(cn: str):
    """Delete a certificate.

    Args:
        cn: Certificate Common Name.

    Returns:
        JSON object with deletion status.
    """
    result = CertificateService.delete_certificate(cn)

    if result.success:
        return jsonify({
            "message": result.message,
            "deleted_files": result.data.get("deleted_files", [])
        })
    else:
        return jsonify({"error": result.message}), 404
