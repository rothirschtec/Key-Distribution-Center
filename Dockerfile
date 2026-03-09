FROM python:3.11-slim

# Install required packages
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        strongswan strongswan-pki pwgen openssh-client rsync openssl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . /app

# Expose web server port
EXPOSE 5000

# Environment variables
ENV FLASK_APP=wsgi.py
ENV FLASK_ENV=production
ENV STORE_DIR=/app/central/scripts/STORE
ENV SCRIPTS_DIR=/app/central/scripts

# Default command runs the web application
# Use gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "wsgi:app"]
