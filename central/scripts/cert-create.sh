#!/bin/bash
# Author: René Zingerle
# Revised to allow using '-legacy' mode for macOS user certificates.

# # #
# Check dependencies
check_dependencies() {
    dep=("ipsec" "pwgen")

    ni=0
    for x in "${dep[@]}"; do
        which $x &> /dev/null
        if [ $? -ne 0 ]; then
            echo "$x: is not installed"
            ni=$(($ni + 1))
        fi
    done
    return $ni
}
check_dependencies
if [ $? -gt 0 ]; then
    echo "The script found missing dependencies. Install them first."
    echo "http://blog.rothirsch.tech/server_farm/configurations/strongswan/#!install"
    exit 1
fi

# # #
# Use host config if exists
host_config=$1

# # #
# Create directories and get templates
cd $(dirname $0)
hdir="$PWD/"

# # #
# Read configuration
function readconfig {
    cat "${hdir}CONFIGS/ca-infos" | grep "$1" | awk -F": " '{print $NF}'
}

ca=$(readconfig "CA Name")
company=$(readconfig "CA Company")
ca_domain=$(readconfig "CA Domain")
ca_cert=$(readconfig "CA Certificate")
ca_key=$(readconfig "CA Private Key")
ca_name=$(readconfig "CA Full Name")

# # #
# Ask user or restore from existing config
function askorrestore() {
    local varname="$1"
    local defaultval="$2"
    local prompt="$3"
    local answer=""

    # If host_config file is provided, try to read the value from it
    if [ -n "$host_config" ] && [ -f "$host_config" ]; then
        answer=$(grep "$varname" "$host_config" | awk -F": " '{print $NF}')
    fi

    # If no answer found in config, ask interactively
    if [[ -z "$answer" ]]; then
        read -e -p "${prompt} - ${varname}: " -i "$defaultval" answer
        # Save to config file if it exists
        if [ -n "$host_config" ] && [ -f "$host_config" ]; then
            echo "$varname: $answer" >> "$host_config"
        fi
    fi

    printf "%s" "$answer"
}

# # #
# Function to ask OS only if user certificate
function ask_os_if_user() {
    local default_os="$1"  # e.g. "linux"
    local prompt_os="Which OS is the user on? (mac/android/linux)"

    # We do not store OS in the config by default,
    # but you could do so if desired. For brevity, let's just do read:
    read -e -p "${prompt_os} " -i "$default_os" user_os
    echo "$user_os"
}

# # #
# Gateway or host?
hosttype=$(askorrestore 'Hosttype' '' '(U)ser/(v)pngateway/(h)ost')

# Get user or host name
if [[ $hosttype =~ [vV] ]]; then
    cert_cn=$(askorrestore 'Cert CN' "" "The hostname will be added to the CAs Domain .${ca_domain}:")
    cert_cn=$(sed "s/.$ca_domain//g" <<< "$cert_cn")
    cert_cn="${cert_cn}.${ca_domain}"
    hosttype=v
elif [[ $hosttype =~ [hH] ]]; then
    cert_cn=$(askorrestore "Cert CN" "" "The hostname will be added to the CAs Domain .${ca_domain}")
    cert_cn=$(sed "s/@$ca_domain//g" <<< "$cert_cn")
    cert_cn="${cert_cn}@${ca_domain}"
    hosttype=h
else
    cert_cn=$(askorrestore "Cert CN" "" "The username will be added to the CAs Domain .${ca_domain}")
    cert_cn=$(sed "s/@$ca_domain//g" <<< "$cert_cn")
    cert_cn="${cert_cn}@${ca_domain}"
    hosttype=u
fi

# # #
# Initialize cert config
if [ -z "$host_config" ]; then
    echo ""
    echo "Saving certificate infos..."
    host_config="${hdir}CONFIGS/${cert_cn}-${ca}.configs"
    echo "" > "$host_config"
    echo "Configuration for $cert_cn" >> "$host_config"
    echo "Hosttype: $hosttype" >> "$host_config"
    echo "Cert CN: $cert_cn" >> "$host_config"
    echo ""
fi

# # #
# If user certificate, ask additional info
if [[ $hosttype =~ [uU] ]]; then
    user_mail=$(askorrestore "User Mail" "" "User e-mail address. The p12 password will be sent to this address")
    user_name=$(askorrestore "User Name" "" "User name. To personally address the user")
fi

cert_country=$(askorrestore "Cert Country" "AT" "Country short name (2 letters)")
echo "CA Company Name: $company"
cert_lifetime=$(askorrestore "Cert Lifetime" "181" "Lifetime of user certificate (days)")
cert_keylength=$(askorrestore "Cert Keylength" "3072" "RSA key size [2048|3072|4096]")

# # #
# Create certificate directories
echo ""
echo "Create certificate..."
ca_dir="${hdir}STORE/"
mkdir -p "${ca_dir}private/" "${ca_dir}certs/" "${ca_dir}p12/"

# # #
# Keyfile
echo "Creating private key..."
cert_private="${ca_dir}private/${cert_cn}-${ca}.pem"
ipsec pki --gen --type rsa --size "$cert_keylength" --outform pem > "$cert_private"
chmod 600 "$cert_private"

# # #
# Certificate
echo "Creating certificate..."
cert_file="${ca_dir}certs/${cert_cn}-${ca}.pem"

if [[ $hosttype == "v" ]]; then
    # VPN Gateway
    ipsec pki --pub --in "$cert_private" --type rsa | \
        ipsec pki --issue --lifetime "$cert_lifetime" \
        --cacert "${ca_dir}${ca_cert}" \
        --cakey  "${ca_dir}${ca_key}" \
        --dn "C=${cert_country}, O=${company}, CN=${cert_cn}" \
        --san "$cert_cn" \
        --flag serverAuth --flag ikeIntermediate \
        --outform pem > "$cert_file"

elif [[ $hosttype == "h" ]]; then
    # Host
    ipsec pki --pub --in "$cert_private" --type rsa | \
        ipsec pki --issue --lifetime "$cert_lifetime" \
        --cacert "${ca_dir}${ca_cert}" \
        --cakey  "${ca_dir}${ca_key}" \
        --dn "C=${cert_country}, O=${company}, CN=${cert_cn}" \
        --san "$cert_cn" \
        --outform pem > "$cert_file"

else
    # User
    ipsec pki --pub --in "$cert_private" --type rsa | \
        ipsec pki --issue --lifetime "$cert_lifetime" \
        --cacert "${ca_dir}${ca_cert}" \
        --cakey  "${ca_dir}${ca_key}" \
        --dn "C=${cert_country}, O=${company}, CN=${cert_cn}" \
        --san "$cert_cn" \
        --outform pem > "$cert_file"

    # Prompt for OS if user cert
    user_os=$(ask_os_if_user "linux")

    # p12 certificate with password
    echo "Creating p12 certificate..."
    cert_p12="${ca_dir}p12/${cert_cn}-${ca}.p12"

    # 22-char ASCII password, no ambiguous chars
    cert_pw=$(pwgen -s -A -B 22 1 | tr -d '/&')

    # Safety net: ensure the password is pure ASCII
    if ! LC_ALL=C grep -qx '[[:print:]]\{1,\}' <<<"$cert_pw" ; then
        echo "Non-ASCII character detected in generated password, regenerating..."
        cert_pw=$(pwgen -s -A -B 22 1 | tr -d '/&')
    fi
    echo "$cert_pw" > "${ca_dir}p12/${cert_cn}-${ca}.pass"

    # --------  PKCS#12 export options  --------
    openssl_opts=(
        -export
        -inkey  "$cert_private"
        -in     "$cert_file"
        -name   "VPN Certificate - $company, $cert_cn"
        -certfile "${ca_dir}${ca_cert}"
        -password "pass:${cert_pw}"
        -out    "$cert_p12"
    )

    case "$user_os" in
        mac|android)
            # Both Android ≤11 and older macOS need the legacy PBE (3DES/RC2 + SHA-1)
            openssl_opts+=( -legacy )
            ;;
        *)
            # Modern Linux etc. – keep OpenSSL 3.x defaults (AES/PBKDF2/SHA-256)
            ;;
    esac

    # Build the PKCS#12
    openssl pkcs12 "${openssl_opts[@]}"

    # # #
    # Send mail to user with the p12 password
    echo ""
    echo "Sending mail to user..."
    echo -e "\
Hi $user_name,\n\n\
A new certificate is available for you. \n\
The certificate was provided by ${ca_name}.\n\n\
!!! IMPORTANT: Please delete this e-mail after you have installed the key.\n\
If you believe that a third party has stolen your key and password, please inform your administrator.\n\n\
Please use the following password: ${cert_pw}\n" \
    | mail -s "[$(date +%d.%m.%y)] Certificate released by ${ca_name}" \
            -a "From: ca@${ca_domain}" \
            "$user_mail"

fi

# # #
# Check certificate
echo ""
echo "Show certificate..."
ipsec pki --print --in "$cert_file"

echo ""
echo "Your certificate has been created!"

