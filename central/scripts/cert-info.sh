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
    cat $2 | grep "$1" | awk -F": " '{print $NF}'
}
ca=$(readconfig "CA Name" "${hdir}CONFIGS/ca-infos")
ca_cert=$(readconfig "CA Certificate" "${hdir}CONFIGS/ca-infos")
ca_key=$(readconfig "CA Private Key" "${hdir}CONFIGS/ca-infos")
ca_name=$(readconfig "CA Full Name" "${hdir}CONFIGS/ca-infos")
ca_domain=$(readconfig "CA Domain" "${hdir}CONFIGS/ca-infos")

cert=${1##*/}
conf=${hdir}CONFIGS/${cert%.*}.configs
user_mail=$(readconfig "User Mail" "$conf")
user_name=$(readconfig "User Name" "$conf")
hosttype=$(readconfig "Hosttype" "$conf")


if [ -z $1 ]; then
    echo "Please provide a filename with path..."
    echo "For example: STORE/certs/test.domain.local.pem"
    exit 1
fi

# # #
# Revoke cert
if [ -f $1 ] && [[ "${1##*.}" == "pem" ]] && [[ ${1} =~ "STORE/certs/" ]]; then
    echo ""; echo "Show certificate info..."
    ipsec pki --print --i $1 

else 
    echo $1
    echo "File does not exist or does not fill in the requierements."
    exit 2
fi
