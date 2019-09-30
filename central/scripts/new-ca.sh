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
# Get Company
i=0

# create default company directory if not exist
mkdir -p ${hdir}CAs/

# # #
# Variables and arrays for the next steps
declare -a cho_company=""
declare -a ssl_value=""
declare -i newca=1
num_company=0

# # #
# loop through CAs subdirectory
declare -a cho_company
while read file
do
    ((i++))
    echo "[$i] $file"
    cho_company[(($i-1))]=$file
done < <(ls "${hdir}CAs/")

if find ${hdir}CAs/ -mindepth 1 | read; then
    read -p "Do you wanna use one of the exisiting CAs? [(Number)|no(n)|exit(e)]: " decision

else
    decision="n"

fi

nValid=1
while [  $nValid -eq 1 ]; do

    re='^[0-9]+$'
    if [[ $decision =~ $re ]]; then
        ca_domain="${cho_company[$num_company-1]}"
        nValid=0

    elif [ $decision == "n" ] || [ $decision == "no" ] ; then
        read -p "Choose a company domain name (like \"domain.local\"): " ca_domain
        mkdir -p "${hdir}CAs/$ca_domain"
        nValid=0

    elif [ $decision == "e" ] || [ $decision == "exit" ] ; then
        exit 0

    else
        read -p "Wrong decision please choose \"y\" or \"n\": " decision
        nValid=1

    fi

done
echo "Using company domain name: $ca_domain ..."
echo ""

# # #
# loop through company subdirectories
while read file
do
    ((i++))
    echo "[$i] $file"
    cho_company[(($i-1))]=$file
done < <(ls "${hdir}CAs/$ca_domain/")

if find ${hdir}CAs/$ca_domain/ -mindepth 1 | read; then
    read -p "Do you wanna use one of the exisiting CAs? [(Number)|no(n)|exit(e)]: " decision

else
    decision="n"

fi

nValid=1
while [  $nValid -eq 1 ]; do

    if [[ $decision =~ $re ]]; then
        ca="${cho_company[$num_company-1]}"
        nValid=0
        newca=0

    elif [ $decision == "n" ] || [ $decision == "no" ] ; then
        read -p "Choose a shortname for the CA like ca2k: " ca
        mkdir "${hdir}CAs/$ca_domain/$ca"
        nValid=0
        newca=1

    else
        read -p "Wrong decision please choose \"y\" or \"n\": " decision
        nValid=1

    fi
done
echo "Using CA name: $ca ..."
echo ""


# # #
# Ask user about necessary parameters
echo "You will now create a subject for your CA. These are information"
echo "the strongswan gateway will use to identify the senders and receivers"
echo "Additionally this script saves the parameters you choose as default"
echo "values for later use."
read -e -p "CA Country (2 Letters): " -i "AT" ca_country
#read -p "CA State: " ca_state
#read -p "CA City: " ca_city
read -p "CA Company Name: " ca_company
#read -p "CA Unit [Company - Server/Client (specific)]: " ca_unit
echo ""
#echo "Your server name like ca.domain.local"
#read -p "CA CommonName: " ca_cn
echo ""
echo "Liftime for CA before you have to reissue it"
read -e -p "CA Lifetime (3650 - aka 10 years): " -i "3650" ca_lifetime

echo ""
echo "A 4096bit key length can result in MTU issues on some ISPs"
echo "For higher compatibility, e.g. for mobile devices, use a smaller length like"
echo "2048bit but you have to reissue them more often. It's not recommended to use"
echo "a key lenght less than 1024bit. For a site to site connection you"
echo "should probably use the 4096bit lenght."
read -e -p "RSA claims that 2048-bit keys are sufficient until 2030. Keylength options (2048|3072|4096)bit. Key length (1024|2048|4096): " -i "4096" ca_klength



# # #
# Create CA
echo ""
echo "Create CA..."

ca_dir="${hdir}CAs/$ca_domain/$ca/"

# Keyfile
echo "Creating CA private key..."
ca_private="${ca_dir}STORE/private/ca.${ca_domain}_${ca}.pem"
mkdir -p ${ca_dir}STORE/private/
ipsec pki --gen --type rsa --size $ca_klength \
    --outform pem \
    > $ca_private
chmod 600 $ca_private


# Cert
echo "Creating CA certificate..."
ca_cert="${ca_dir}STORE/cacerts/ca.${ca_domain}_${ca}.pem"
ca_name="strongSwan Root CA | $ca"
mkdir -p ${ca_dir}STORE/cacerts/
ipsec pki --self --ca --lifetime $ca_lifetime \
    --in $ca_private --type rsa \
    --dn 'C='"$ca_country"', O='"$ca_company"', CN='"$ca_name"'' \
    --outform pem \
    > $ca_cert
# # #

echo ""; echo "Show CA certificate..."
ipsec pki --print --in $ca_cert


echo ""; echo "Your certificate authority has been created!"

# # #
# Link management scripts
echo "Linking files..."
ln -rsf ${hdir}central/scripts/cert-create.sh ${ca_dir}cert-create
ln -rsf ${hdir}central/scripts/cert-create.sh ${ca_dir}cert-create
ln -rsf ${hdir}central/scripts/cert-transfer.sh ${ca_dir}cert-transfer
ln -rsf ${hdir}central/scripts/cert-revoke-remove.sh ${ca_dir}cert-revoke-remove
ln -rsf ${hdir}central/scripts/cert-info.sh ${ca_dir}cert-info

# # #
# Write configuration file
mkdir -p ${ca_dir}CONFIGS
echo "CA Name: $ca" > ${ca_dir}CONFIGS/ca-infos
echo "CA Company: $ca_company" >> ${ca_dir}CONFIGS/ca-infos
echo "CA Domain: ${ca_domain}" >> ${ca_dir}CONFIGS/ca-infos
echo "CA Certificate: ${ca_cert##*STORE/}" >> ${ca_dir}CONFIGS/ca-infos
echo "CA Private Key: ${ca_private##*STORE/}" >> ${ca_dir}CONFIGS/ca-infos
echo "CA Full Name: ${ca_name}" >> ${ca_dir}CONFIGS/ca-infos


echo "All files are in:"
echo "${ca_dir}"
