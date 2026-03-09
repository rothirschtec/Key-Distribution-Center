"""CA REST API endpoints."""

from flask import jsonify, request

from ..services import CAService
from . import api_bp


@api_bp.route("/cas", methods=["GET"])
def list_cas():
    """List all Certificate Authorities.

    Returns:
        JSON array of CA objects.
    """
    cas = CAService.list_cas()
    return jsonify(cas)


@api_bp.route("/cas/<domain>/<name>", methods=["GET"])
def get_ca(domain: str, name: str):
    """Get a specific CA by domain and name.

    Args:
        domain: CA domain.
        name: CA name.

    Returns:
        JSON object with CA details, or 404 if not found.
    """
    ca = CAService.get_ca(domain, name)
    if ca is None:
        return jsonify({"error": f"CA not found: {domain}_{name}"}), 404
    return jsonify(ca)


@api_bp.route("/cas", methods=["POST"])
def create_ca():
    """Create a new Certificate Authority.

    Request body:
        {
            "name": "string (required)",
            "domain": "string (required)",
            "company": "string (required)",
            "country": "string (optional, default: AT)",
            "key_length": "int (optional, default: 4096)",
            "lifetime": "int (optional, default: 3650)"
        }

    Returns:
        JSON object with created CA details, or error.
    """
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body required"}), 400

    # Validate required fields
    required_fields = ["name", "domain", "company"]
    missing = [f for f in required_fields if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    result = CAService.create_ca(
        name=data["name"],
        domain=data["domain"],
        company=data["company"],
        country=data.get("country"),
        key_length=data.get("key_length"),
        lifetime=data.get("lifetime"),
    )

    if result.success:
        return jsonify(result.data), 201
    else:
        return jsonify({"error": result.message}), 400
