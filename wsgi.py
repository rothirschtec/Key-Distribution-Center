"""WSGI entry point for the KDC web application."""

import os

from webapp import create_app

# Determine config based on environment
config_name = os.environ.get("FLASK_ENV", "production")
config_map = {
    "development": "webapp.config.DevelopmentConfig",
    "production": "webapp.config.ProductionConfig",
    "testing": "webapp.config.TestingConfig",
}
config_class = config_map.get(config_name, "webapp.config.Config")

app = create_app(config_class)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
