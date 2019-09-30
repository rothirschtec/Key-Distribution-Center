#!/bin/bash
# Author: René Zingerle
# Thanks to: 
# - https://www.danballard.com/references/strongswan/www.zeitgeist.se/2013/11/22/strongswan-howto-create-your-own-vpn/index.html
# - https://wiki.strongswan.org/

# # #
# Check dependencies
check_dependencies() {

    # # #
    # Checks dependencies and tries to install them
    dep=("ipsec" "pwgen")

    ni=0
    for x in "${dep[@]}"; do
        which $x &> /dev/null
        if [ $? -eq 1 ]; then
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
#
# # #


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
    cat ${hdir}CONFIGS/ca-infos | grep "$1" | awk -F": " '{print $NF}'
}
ca=$(readconfig "CA Name")
company=$(readconfig "CA Company")
ca_domain=$(readconfig "CA Domain")
ca_cert=$(readconfig "CA Certificate")
ca_key=$(readconfig "CA Private Key")
ca_name=$(readconfig "CA Full Name")

# # #
# Ask user about necessary parameters
function askorrestore() {

    if [ ! -z $host_config ] && [ -f $host_config ]; then
        answer=$(cat $host_config | grep "$1" | awk -F": " '{print $NF}')
        echo $answer

    fi

    if [[ $answer == "" ]]; then
        read -e -p "${3} - ${1}: " -i "$2" answer
        if [ ! -z $host_config ] && [ -f $host_config ]; then
            echo "$1: $answer" >> $host_config
        fi
        echo $answer
    fi
}


# # #
# Gateway or host?
hosttype=$(askorrestore 'Hosttype' '' '(U)ser/(v)pngateway')

# Get user or host name
if [[ $hosttype =~ [vV] ]]; then
    cert_cn=$(askorrestore 'Cert CN' "" "The hostname will be added to the CAs Domain .${ca_domain}:")
    cert_cn=$(sed "s/.$ca_domain//g" <<< $cert_cn)
    cert_cn="${cert_cn}.${ca_domain}" 
    hosttype=v
else
    cert_cn=$(askorrestore "Cert CN" "" "The username will be added to the CAs Domain .${ca_domain}")
    cert_cn=$(sed "s/@$ca_domain//g" <<< $cert_cn)
    cert_cn="${cert_cn}@${ca_domain}"
    hosttype=u
fi

# # #
# Initialize cert config
if [ -z $host_config ]; then
    echo ""; echo "Saving certificate infos..."
    host_config="${hdir}CONFIGS/${cert_cn}-${ca}.configs"
    echo "" > $host_config 
    echo "Configuration for $cert_cn" >> $host_config
    echo "Hosttype: $hosttype" >> $host_config
    echo "Cert CN: $cert_cn" >> $host_config
    echo ""
fi


if [[ $hosttype =~ [uU] ]]; then
    user_mail=$(askorrestore "User Mail" "" "User e-mail address. The p12 password will be send to this address")
    user_name=$(askorrestore "User Name" "" "User name. To personally address the User")
fi

cert_country=$(askorrestore "Cert Country" "AT" "Country short name (2 letters)")
echo "CA Company Name: $company"
cert_lifetime=$(askorrestore "Cert Lifetime" "181" "Lifetime of user certificate")
cert_keylength=$(askorrestore "Cert Keylength" "3096" "RSA claims that 2048-bit keys are sufficient until 2030. Keylength options (2048|3096|4096)bit" )
#read -p "CA State: " ca_state
#read -p "CA City: " ca_city
#read -p "CA Unit [Company - Server/Client (specific)]: " ca_unit


# # #
# Create certificate
echo ""; echo "Create certificate..."
ca_dir="${hdir}STORE/"


# Keyfile
echo "Creating CA private key..."
cert_private="${ca_dir}private/${cert_cn}-${ca}.pem"
mkdir -p ${ca_dir}private/
ipsec pki --gen --type rsa --size $cert_keylength \
    --outform pem \
    > $cert_private
chmod 600 $cert_private


# Certificate
echo "Creating CA certificate..."
cert_file="${ca_dir}certs/${cert_cn}-${ca}.pem"
mkdir -p ${ca_dir}certs/


if [[ $hosttype == "v" ]]; then
    # # #
    # VPN Gateway
    ipsec pki --pub --in ${cert_private} --type rsa | \
        ipsec pki --issue --lifetime $cert_lifetime \
        --cacert ${ca_dir}$ca_cert \
        --cakey ${ca_dir}$ca_key \
        --dn "C=${cert_country}, O=${company}, CN=${cert_cn}" \
        --san $cert_cn \
        --flag serverAuth --flag ikeIntermediate \
        --outform pem > $cert_file
else
    # # #
    # User
    ipsec pki --pub --in ${cert_private} --type rsa | \
        ipsec pki --issue --lifetime $cert_lifetime \
        --cacert ${ca_dir}$ca_cert \
        --cakey ${ca_dir}$ca_key \
        --dn "C=${cert_country}, O=${company}, CN=${cert_cn}" \
        --san $cert_cn \
        --outform pem > $cert_file
    # # #

    # p12 certificat with password
    mkdir -p ${ca_dir}p12/
    cert_pw=$(pwgen -sy -c1 16)
    echo $cert_pw > "${ca_dir}p12/${cert_cn}-${ca}.pass"
    echo "Creating p12 certificates..."
    cert_p12="${ca_dir}p12/${cert_cn}-${ca}.p12"

    openssl pkcs12 -export -inkey $cert_private \
        -in $cert_file -name "VPN Certificate - $company, $cert_cn" \
        -certfile ${ca_dir}$ca_cert \
        -caname "${ca_name}" \
        -password "pass:${cert_pw}" \
        -out $cert_p12
fi


# # #
# Check certificate
echo ""; echo "Show certificate..."
ipsec pki --print --in $cert_file

echo ""; echo "Your certificate has been created!"


# # #
# Send mail
if [[ $hosttype == "u" ]]; then
    echo ""; echo "Sending mail to user..."
    echo -e "\
Hy $user_name,\n\n\
a new certficate is available for you. \n\
The certificate was provided by ${ca_name}. \n\n\
!!! IMPORTANT, Please delete this e-mail after you have installed the key inside your machine.\n\
If you believe that a third party has stolen your key and password, Please tell your administrator about it.\n\n\
Please use following password: ${cert_pw}" | mail -s "[$(date +%d.%m.%y)] Certificate released by ${ca_name}" -a "From: ca@$ca_domain" $user_mail
fi
