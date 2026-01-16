#!/bin/bash
# =============================================================================
# StrongSwan VPN Client Installer for Linux
# =============================================================================
# Author: René Zingerle, Rothirsch Tech. GmbH
# Installs VPN certificates and configures strongSwan client
#
# Supports:
#   - PEM certificates (certs/, private/, cacerts/ directories)
#   - P12/PKCS#12 certificates (*.p12 file)
#   - systemd-resolved DNS integration
#
# Usage:
#   ./install_lnx.sh [--p12-password <password>] [--no-dns-fix] [--backup-only]
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly IPSEC_DIR="/etc/ipsec.d"
readonly IPSEC_CONF="/etc/ipsec.conf"
readonly IPSEC_SECRETS="/etc/ipsec.secrets"
readonly BACKUP_DIR="/etc/ipsec.d/backups/$(date +%Y%m%d_%H%M%S)"
readonly CLIENT_INFO="${SCRIPT_DIR}/client_info.md"

# Colors (disabled if not a terminal)
if [[ -t 1 ]]; then
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly BLUE='\033[0;34m'
    readonly NC='\033[0m' # No Color
else
    readonly RED='' GREEN='' YELLOW='' BLUE='' NC=''
fi

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------
log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()       { log_error "$*"; exit 1; }

# Escape string for use in sed replacement
sed_escape() {
    printf '%s' "$1" | sed -e 's/[\/&$*.^[]/\\&/g'
}

# Read value from client_info.md
read_client_info() {
    local key="$1"
    local value=""
    if [[ -f "$CLIENT_INFO" ]]; then
        value=$(grep -E "^${key}:" "$CLIENT_INFO" 2>/dev/null | sed "s/^${key}:[[:space:]]*//" | head -1)
    fi
    printf '%s' "$value"
}

# Create backup of existing configuration
create_backup() {
    if [[ -d "$IPSEC_DIR" ]] || [[ -f "$IPSEC_CONF" ]] || [[ -f "$IPSEC_SECRETS" ]]; then
        log_info "Creating backup in ${BACKUP_DIR}..."
        mkdir -p "$BACKUP_DIR"

        [[ -f "$IPSEC_CONF" ]] && cp "$IPSEC_CONF" "$BACKUP_DIR/"
        [[ -f "$IPSEC_SECRETS" ]] && cp "$IPSEC_SECRETS" "$BACKUP_DIR/"
        [[ -d "$IPSEC_DIR/certs" ]] && cp -r "$IPSEC_DIR/certs" "$BACKUP_DIR/"
        [[ -d "$IPSEC_DIR/private" ]] && cp -r "$IPSEC_DIR/private" "$BACKUP_DIR/"
        [[ -d "$IPSEC_DIR/cacerts" ]] && cp -r "$IPSEC_DIR/cacerts" "$BACKUP_DIR/"

        log_ok "Backup created: ${BACKUP_DIR}"
    fi
}

# -----------------------------------------------------------------------------
# Certificate Installation Functions
# -----------------------------------------------------------------------------

# Install PEM certificates from directories
install_pem_certs() {
    log_info "Installing PEM certificates..."

    local dirs=("certs" "private" "cacerts")
    for dir in "${dirs[@]}"; do
        if [[ -d "${SCRIPT_DIR}/${dir}" ]]; then
            mkdir -p "${IPSEC_DIR}/${dir}"
            cp -v "${SCRIPT_DIR}/${dir}/"* "${IPSEC_DIR}/${dir}/" 2>/dev/null || true

            # Set proper permissions for private keys
            if [[ "$dir" == "private" ]]; then
                chmod 600 "${IPSEC_DIR}/${dir}/"* 2>/dev/null || true
            fi
        fi
    done

    log_ok "PEM certificates installed"
}

# Install P12 certificate
install_p12_cert() {
    local p12_file="$1"
    local password="$2"

    log_info "Installing P12 certificate: $(basename "$p12_file")..."

    local p12_basename
    p12_basename=$(basename "$p12_file")

    mkdir -p "${IPSEC_DIR}/private"
    cp "$p12_file" "${IPSEC_DIR}/private/"
    chmod 600 "${IPSEC_DIR}/private/${p12_basename}"

    # Update ipsec.secrets
    update_p12_secret "$p12_basename" "$password"

    log_ok "P12 certificate installed"
}

# -----------------------------------------------------------------------------
# IPsec Secrets Management
# -----------------------------------------------------------------------------

# Update RSA key in ipsec.secrets
update_rsa_secret() {
    local keyfile="$1"
    local password="$2"

    local escaped_pw
    escaped_pw=$(sed_escape "$password")

    if grep -q "RSA.*${keyfile}" "$IPSEC_SECRETS" 2>/dev/null; then
        # Key exists - check if password changed
        local current_pw
        current_pw=$(grep "RSA.*${keyfile}" "$IPSEC_SECRETS" | grep -oP '"\K[^"]+(?=")' | head -1)

        if [[ "$current_pw" == "$password" ]]; then
            log_info "RSA key already configured with same password"
        else
            log_info "Updating RSA key password..."
            # Use awk for safer replacement
            awk -v key="$keyfile" -v pw="$password" '
                $0 ~ "RSA.*" key {
                    print ": RSA " key " \"" pw "\""
                    next
                }
                { print }
            ' "$IPSEC_SECRETS" > "${IPSEC_SECRETS}.tmp"
            mv "${IPSEC_SECRETS}.tmp" "$IPSEC_SECRETS"
            chmod 600 "$IPSEC_SECRETS"
            log_ok "RSA key password updated"
        fi
    else
        log_info "Adding new RSA key to ipsec.secrets..."
        echo ": RSA ${keyfile} \"${password}\"" >> "$IPSEC_SECRETS"
        chmod 600 "$IPSEC_SECRETS"
        log_ok "RSA key added"
    fi
}

# Update P12 key in ipsec.secrets
update_p12_secret() {
    local p12file="$1"
    local password="$2"

    if grep -q ": P12 ${p12file}" "$IPSEC_SECRETS" 2>/dev/null; then
        log_info "Updating P12 key in ipsec.secrets..."
        awk -v p12="$p12file" -v pw="$password" '
            $0 ~ ": P12 " p12 {
                print ": P12 " p12 " \047" pw "\047"
                next
            }
            { print }
        ' "$IPSEC_SECRETS" > "${IPSEC_SECRETS}.tmp"
        mv "${IPSEC_SECRETS}.tmp" "$IPSEC_SECRETS"
    else
        log_info "Adding P12 key to ipsec.secrets..."
        echo ": P12 ${p12file} '${password}'" >> "$IPSEC_SECRETS"
    fi
    chmod 600 "$IPSEC_SECRETS"
    log_ok "P12 key configured"
}

# -----------------------------------------------------------------------------
# IPsec Configuration Management
# -----------------------------------------------------------------------------

# Update ipsec.conf with connection configuration
update_ipsec_conf() {
    local subject="$1"

    if grep -q "$subject" "$IPSEC_CONF" 2>/dev/null; then
        log_info "Connection for subject already exists in ipsec.conf"
        return 0
    fi

    if [[ ! -f "${SCRIPT_DIR}/ipsec.conf" ]]; then
        log_warn "No ipsec.conf template found in package"
        return 0
    fi

    if grep -q "conn rt.conn" "$IPSEC_CONF" 2>/dev/null; then
        log_warn "Existing rt.conn found in ipsec.conf"
        echo ""
        echo "Options:"
        echo "  1) Keep existing configuration"
        echo "  2) Append new connection (may cause conflicts)"
        echo "  3) Replace entire ipsec.conf (CAUTION: overwrites all connections)"
        echo ""
        read -rp "Select option [1]: " choice
        choice="${choice:-1}"

        case "$choice" in
            2)
                log_info "Appending connection configuration..."
                echo "" >> "$IPSEC_CONF"
                echo "# Added by VPN installer $(date +%Y-%m-%d)" >> "$IPSEC_CONF"
                sed -n '/conn rt.conn/,$p' "${SCRIPT_DIR}/ipsec.conf" >> "$IPSEC_CONF"
                log_ok "Connection appended"
                ;;
            3)
                read -rp "Are you sure you want to replace ipsec.conf? [y/N]: " confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    cp "${SCRIPT_DIR}/ipsec.conf" "$IPSEC_CONF"
                    log_ok "ipsec.conf replaced"
                else
                    log_info "Keeping existing configuration"
                fi
                ;;
            *)
                log_info "Keeping existing configuration"
                ;;
        esac
    else
        log_info "Adding connection to ipsec.conf..."
        echo "" >> "$IPSEC_CONF"
        echo "# Rothirsch Tech. VPN connection - Added $(date +%Y-%m-%d)" >> "$IPSEC_CONF"
        sed -n '/conn rt.conn/,$p' "${SCRIPT_DIR}/ipsec.conf" >> "$IPSEC_CONF"
        log_ok "Connection added to ipsec.conf"
    fi
}

# -----------------------------------------------------------------------------
# systemd-resolved DNS Integration
# -----------------------------------------------------------------------------

install_dns_updown_script() {
    local updown_script="/etc/strongswan.d/vpn-dns-updown.sh"

    log_info "Installing DNS integration script for systemd-resolved..."

    cat > "$updown_script" << 'UPDOWN_EOF'
#!/bin/bash
# VPN DNS integration for systemd-resolved
# Sets VPN DNS as default route when tunnel comes up

case "$PLUTO_VERB" in
    up-client|up-host)
        if command -v resolvectl &>/dev/null; then
            # Get the interface from PLUTO or find the VPN interface
            iface="${PLUTO_INTERFACE:-}"
            if [[ -z "$iface" ]]; then
                # Try to detect from routing
                iface=$(ip route get "${PLUTO_PEER:-8.8.8.8}" 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
            fi

            if [[ -n "$iface" ]]; then
                logger -t strongswan-dns "Setting DNS default-route on $iface"
                resolvectl default-route "$iface" true 2>/dev/null || true
            fi
        fi
        ;;
    down-client|down-host)
        if command -v resolvectl &>/dev/null; then
            iface="${PLUTO_INTERFACE:-}"
            if [[ -n "$iface" ]]; then
                logger -t strongswan-dns "Removing DNS default-route from $iface"
                resolvectl default-route "$iface" false 2>/dev/null || true
            fi
        fi
        ;;
esac

exit 0
UPDOWN_EOF

    chmod 755 "$updown_script"
    log_ok "DNS updown script installed: $updown_script"

    echo ""
    log_info "To enable DNS integration, add to your connection in /etc/ipsec.conf:"
    echo "    leftupdown=/etc/strongswan.d/vpn-dns-updown.sh"
}

# -----------------------------------------------------------------------------
# Main Installation Logic
# -----------------------------------------------------------------------------

detect_cert_type() {
    # Check for P12 files
    local p12_files
    p12_files=$(find "$SCRIPT_DIR" -maxdepth 1 -name "*.p12" 2>/dev/null | head -1)

    if [[ -n "$p12_files" ]]; then
        echo "p12:${p12_files}"
        return
    fi

    # Check for PEM directories
    if [[ -d "${SCRIPT_DIR}/certs" ]] || [[ -d "${SCRIPT_DIR}/private" ]]; then
        echo "pem"
        return
    fi

    echo "unknown"
}

show_usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Options:
    --p12-password <pw>   Password for P12 certificate (prompted if not provided)
    --no-dns-fix          Skip installing systemd-resolved DNS integration
    --backup-only         Only create backup, don't install
    --help                Show this help message

Examples:
    $(basename "$0")                          # Interactive installation
    $(basename "$0") --p12-password secret    # Non-interactive P12 install
EOF
}

main() {
    local p12_password=""
    local skip_dns_fix=false
    local backup_only=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --p12-password)
                p12_password="$2"
                shift 2
                ;;
            --no-dns-fix)
                skip_dns_fix=true
                shift
                ;;
            --backup-only)
                backup_only=true
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
    done

    echo ""
    echo "=========================================="
    echo " StrongSwan VPN Client Installer"
    echo "=========================================="
    echo ""

    # Check root
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root (use sudo)"
    fi

    # Check strongSwan installed
    if ! command -v ipsec &>/dev/null; then
        die "strongSwan (ipsec) is not installed. Please install it first."
    fi

    # Create backup
    create_backup

    if [[ "$backup_only" == true ]]; then
        log_ok "Backup complete. Exiting."
        exit 0
    fi

    # Detect certificate type
    local cert_type
    cert_type=$(detect_cert_type)

    case "$cert_type" in
        p12:*)
            local p12_file="${cert_type#p12:}"
            log_info "Detected P12 certificate: $(basename "$p12_file")"

            if [[ -z "$p12_password" ]]; then
                read -rsp "Enter P12 password: " p12_password
                echo ""
            fi

            install_p12_cert "$p12_file" "$p12_password"
            ;;

        pem)
            log_info "Detected PEM certificates"
            install_pem_certs

            # Read key info from client_info.md
            local keyfile passphrase subject
            keyfile=$(read_client_info "ckey")
            passphrase=$(read_client_info "pass")
            subject=$(read_client_info "subj")

            if [[ -n "$keyfile" ]] && [[ -n "$passphrase" ]]; then
                update_rsa_secret "$keyfile" "$passphrase"
            else
                log_warn "No key info found in client_info.md - skipping secrets update"
            fi

            if [[ -n "$subject" ]]; then
                update_ipsec_conf "$subject"
            fi
            ;;

        *)
            die "No certificates found. Expected .p12 file or certs/private/cacerts directories."
            ;;
    esac

    # Install DNS integration
    if [[ "$skip_dns_fix" != true ]] && command -v resolvectl &>/dev/null; then
        echo ""
        read -rp "Install systemd-resolved DNS integration? [Y/n]: " install_dns
        install_dns="${install_dns:-Y}"
        if [[ "$install_dns" =~ ^[yY]$ ]]; then
            install_dns_updown_script
        fi
    fi

    # Restart strongSwan
    echo ""
    read -rp "Restart strongSwan and bring up connection? [Y/n]: " restart_ipsec
    restart_ipsec="${restart_ipsec:-Y}"

    if [[ "$restart_ipsec" =~ ^[yY]$ ]]; then
        log_info "Restarting strongSwan..."
        if systemctl is-active --quiet strongswan 2>/dev/null; then
            systemctl restart strongswan
        elif systemctl is-active --quiet strongswan-starter 2>/dev/null; then
            systemctl restart strongswan-starter
        else
            ipsec restart
        fi

        sleep 2

        if grep -q "conn rt.conn" "$IPSEC_CONF" 2>/dev/null; then
            log_info "Bringing up VPN connection..."
            ipsec up rt.conn || log_warn "Failed to bring up connection (may need manual intervention)"
        fi
    fi

    echo ""
    echo "=========================================="
    log_ok "Installation complete!"
    echo "=========================================="
    echo ""
    echo "Useful commands:"
    echo "  ipsec status          - Show connection status"
    echo "  ipsec up rt.conn      - Connect to VPN"
    echo "  ipsec down rt.conn    - Disconnect from VPN"
    echo "  resolvectl status     - Check DNS configuration"
    echo ""

    if [[ -d "$BACKUP_DIR" ]]; then
        echo "Backup location: ${BACKUP_DIR}"
        echo "To restore: cp -r ${BACKUP_DIR}/* /etc/"
        echo ""
    fi
}

main "$@"
