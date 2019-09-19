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
    dep=("ipsec")

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
ca_cert=$(readconfig "CA Certificate")
ca_key=$(readconfig "CA Private Key")

# # #
# Ask user about necessary parameters
echo "You will now create a subject for your CA. These are information"
echo "the strongswan gateway will use to identify the senders and receivers"
echo "Additionally this script saves the parameters you choose as default"
echo "values for later use."
read -p "CA Country (2 Letters): " ca_country
#read -p "CA State: " ca_state
#read -p "CA City: " ca_city
echo "CA Company Name: $company"
#read -p "CA Unit [Company - Server/Client (specific)]: " ca_unit
echo ""
echo "Your server name like host.domain.local"
read -p "CA CommonName: " cert_cn
echo ""
echo "Liftime for certificate before you have to reissue it"
read -e -p "Cert lifetime (181 - aka 0.5 years): " -i "181" cert_lifetime

echo ""
echo "A 4096bit key length can result in MTU issues on some ISPs"
echo "For higher compatibility, e.g. for mobile devices, use a smaller length like"
echo "2048bit but you have to reissue them more often. It's not recommended to use"
echo "a key lenght less than 1024bit. For a site to site connection you"
echo "should probably use the 4096bit lenght."
read -e -p "Key length (1024|2048|4096): " -i "2048" cert_keysize



# # #
# Create certificate
echo ""; echo "Create certificate..."

ca_dir="${hdir}STORE/"

# Keyfile
echo "Creating CA private key..."
cert_private="${ca_dir}private/${cert_cn}-${ca}.pem"
mkdir -p ${ca_dir}private/
ipsec pki --gen --type rsa --size $cert_keysize \
    --outform pem \
    > $cert_private
chmod 600 $cert_private

# Cert
echo "Creating CA certificate..."
cert_file="${ca_dir}certs/${cert_cn}-${ca}.pem"
mkdir -p ${ca_dir}certs/
ipsec pki --pub --in ${cert_private} --type rsa | \
    ipsec pki --issue --lifetime $cert_lifetime \
    --cacert ${ca_dir}$ca_cert \
    --cakey ${ca_dir}$ca_key \
    --dn 'C='"$ca_country"', O='"$company"', CN='"$cert_cn"'' \
    --san $cert_cn \
    --flag serverAuth --flag ikeIntermediate \
    --outform pem > $cert_file
# # #

echo ""; echo "Show CA certificate..."
ipsec pki --print --in $cert_file

echo ""; echo "Your certificate has been created!"
