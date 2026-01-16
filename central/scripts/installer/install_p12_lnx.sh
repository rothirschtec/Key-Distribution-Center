#!/bin/bash
# =============================================================================
# P12 Certificate Installer (Wrapper)
# =============================================================================
# This script is a backwards-compatible wrapper for install_lnx.sh
# It handles P12/PKCS#12 certificate installation.
#
# Usage:
#   ./install_p12_lnx.sh [password]
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if main installer exists
if [[ ! -x "${SCRIPT_DIR}/install_lnx.sh" ]]; then
    echo "ERROR: install_lnx.sh not found in ${SCRIPT_DIR}" >&2
    exit 1
fi

# Get password from argument or prompt
if [[ -n "${1:-}" ]]; then
    exec "${SCRIPT_DIR}/install_lnx.sh" --p12-password "$1"
else
    exec "${SCRIPT_DIR}/install_lnx.sh"
fi
