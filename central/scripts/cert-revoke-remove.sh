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
    echo ""; echo "Revoke certificate..."
    mkdir -p ${hdir}STORE/crls/


    # # #
    # Write revoked certificate to crl
    if [ -f ${hdir}STORE/crls/crl.${ca_domain}_${ca}.pem ]; then
        # Write to existing CRL
        cp ${hdir}STORE/crls/crl.${ca_domain}_${ca}.pem ${hdir}STORE/crls/crl.${ca_domain}_${ca}.pem.tmp
        ipsec pki --signcrl --reason key-compromise \
                --cacert ${hdir}STORE/${ca_cert} \
                --cakey ${hdir}STORE/${ca_key} \
                --cert $1 \
                --lastcrl ${hdir}STORE/crls/crl.${ca_domain}_${ca}.pem.tmp \
                --outform pem > ${hdir}STORE/crls/crl.${ca_domain}_${ca}.pem
        rm ${hdir}STORE/crls/crl.${ca_domain}_${ca}.pem.tmp

    else 
        # Create crl with first revoke
        ipsec pki --signcrl --reason key-compromise \
                --cacert ${hdir}STORE/$ca_cert \
                --cakey ${hdir}STORE/$ca_key \
                --cert $1 \
                --outform pem > ${hdir}STORE/crls/crl.${ca_domain}_${ca}.pem

    fi


    # # #
    # Remove files
    echo "Remove: "
    file="STORE/private/${cert%.*}.pem"; echo "- $file"; rm -f ${hdir}$file
    file="STORE/certs/${cert%.*}.pem"; echo "- $file"; rm -f ${hdir}$file
    file="STORE/p12/${cert%.*}.p12"; echo "- $file"; rm -f ${hdir}$file
    file="STORE/p12/${cert%.*}.pass"; echo "- $file"; rm -f ${hdir}$file

    if ! cat ${hdir}CONFIGS/ca-infos | grep "SSH Host"; then
        while ((i++)); read -r p 
        do
            echo [$i] $p
            sshhosts[$i]=$p
        done < <(cat ~/.ssh/config | grep ^Host | awk -F" " '{print $NF}')
        read -p "Choose IPSEC gateway in ~/.ssh/config for further use [0-9]: " dec
        ssh_host=${sshhosts[$dec]}
        echo "Storing SSH host ${sshhosts[$dec]} inside CONFIGS/ca-infos for later use"
        echo "SSH Host: ${sshhosts[$dec]}" >> ${hdir}CONFIGS/ca-infos

    else
        ssh_host=$(readconfig "SSH Host" "${hdir}CONFIGS/ca-infos")

    fi
    file="/etc/ipsec.d/certs/${cert%.*}.pem"; echo "- $file on $ssh_host"; ssh $ssh_host rm -f $file
    file="STORE/crls/crl.${ca_domain}_${ca}.pem"; echo "- SYNC: $file"; rsync -a ${hdir}$file ${ssh_host}:/etc/ipsec.d/crls/

else 
    echo $1
    echo "File does not exist or does not fill in the requierements."
    exit 2
fi

# # #
# Send mail
if [[ $hosttype =~ [uU] ]]; then

    echo ""; echo "Sending mail to user..."
    echo -e "\
    Hy $user_name,\n\
    \n\
    Your certificate has been revoked because of security concerns \n\
    The certificate was revoked by ${ca_name}." | mail -s "[$(date +%d.%m.%y)] Certificate revoked by ${ca_name}" -a "From: ca@$ca_domain" $user_mail
    
fi
