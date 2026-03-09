"""KDC Web Application - Flask app factory.

This module provides the Flask application factory for the Key Distribution
Center web interface and REST API.
"""

from flask import Flask


def create_app(config_class: str | None = None) -> Flask:
    """Create and configure the Flask application.

    Args:
        config_class: Python path to configuration class.
            Defaults to 'webapp.config.Config'.

    Returns:
        Configured Flask application instance.
    """
    app = Flask(__name__)

    # Load configuration
    app.config.from_object(config_class or "webapp.config.Config")

    # Register blueprints
    from .api import api_bp
    from .web import web_bp

    app.register_blueprint(api_bp, url_prefix="/api/v1")
    app.register_blueprint(web_bp)

    # Register error handlers
    @app.errorhandler(404)
    def not_found(e):
        from flask import request, jsonify, render_template

        if request.path.startswith("/api/"):
            return jsonify({"error": "Not found"}), 404
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def internal_error(e):
        from flask import request, jsonify, render_template

        if request.path.startswith("/api/"):
            return jsonify({"error": "Internal server error"}), 500
        return render_template("errors/500.html"), 500

    return app
