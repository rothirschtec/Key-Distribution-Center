FROM python:3.11-slim

# Install required packages
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        strongswan strongswan-pki pwgen openssh-client rsync \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
WORKDIR /app
COPY . /app

# Default entrypoint runs the Python CLI
ENTRYPOINT ["python3", "central/scripts/kdc.py"]
CMD ["--help"]
