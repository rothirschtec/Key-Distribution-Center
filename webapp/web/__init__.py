"""Web UI blueprint for the KDC web application."""

from flask import Blueprint

web_bp = Blueprint(
    "web",
    __name__,
    template_folder="../templates",
    static_folder="../static",
)

from . import views  # noqa: E402, F401
