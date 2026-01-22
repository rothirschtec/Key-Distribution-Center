#!/bin/bash
# Build script for KDC webapp on systems with limited Docker networking
# (e.g., ClearFog Base with bridge: none configuration)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DAEMON_JSON="/etc/docker/daemon.json"
BACKUP_FILE="/tmp/daemon.json.backup"

# Check if running as root or with sudo for daemon.json modification
need_network_fix() {
    if [ -f "$DAEMON_JSON" ]; then
        grep -q '"bridge".*:.*"none"' "$DAEMON_JSON" 2>/dev/null
        return $?
    fi
    return 1
}

restore_daemon_config() {
    if [ -f "$BACKUP_FILE" ]; then
        echo "Restoring Docker daemon configuration..."
        sudo cp "$BACKUP_FILE" "$DAEMON_JSON"
        sudo systemctl restart docker
        rm -f "$BACKUP_FILE"
        echo "Docker daemon configuration restored."
    fi
}

# Set trap to restore config on exit
trap restore_daemon_config EXIT

if need_network_fix; then
    echo "Detected bridge: none configuration. Temporarily enabling networking for build..."

    # Backup current config
    sudo cp "$DAEMON_JSON" "$BACKUP_FILE"

    # Create temporary config without bridge: none
    sudo tee "$DAEMON_JSON" > /dev/null <<EOF
{
  "storage-driver": "vfs",
  "iptables": false
}
EOF

    echo "Restarting Docker daemon..."
    sudo systemctl restart docker

    # Wait for Docker to be ready
    sleep 2

    echo "Building Docker image with networking enabled..."
    docker compose build --no-cache

    echo "Build complete. Restoring original configuration..."
    # trap will handle restoration
else
    echo "Building Docker image..."
    docker compose build
fi

echo ""
echo "Build completed successfully!"
echo "Run 'docker compose up -d' to start the webapp."
