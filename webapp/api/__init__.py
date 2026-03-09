"""REST API blueprint for the KDC web application."""

from flask import Blueprint

api_bp = Blueprint("api", __name__)

from . import ca, certificates, transfer  # noqa: E402, F401
