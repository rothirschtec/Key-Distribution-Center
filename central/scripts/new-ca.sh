#!/bin/bash

# # # # # # # # # 
# Variables
declare -a cho_company=""
declare -a ssl_value=""
declare -i newca=1
declare -i perform=0
num_company=0
# # # # # # # # # 

# # # # # # # # # # 
# Functions
function create_password {
	if [[ $1 == "test" ]]; then
		pass="test"
		echo $pass
	else
   pass=""
   	for x in {1..2}
   	do
      	pass+=`pwgen -1nc`
   	done
   	echo $pass
	fi
}

# # #
# Check dependencies
    check_dependencies() {

        # # #
        # Checks dependencies and tries to install them
        dep=("openssl" "perl" "pwgen" "uuid-runtime")

        for x in "${dep[@]}"; do
            dpkg -s $x &> /dev/null
            if [ $? -eq 1 ]; then
                echo "$x: is not installed"
                apt-get -y install $x
                ni=$(($ni + $?))
            fi
        done
        return $ni
    }
    if ! check_dependencies; then
        echo "Problems with dependencies detected"
        exit 1
    fi
#
# # #


count=0
function change_openssl_config {
    read -p "$1: " value
    sed -i "s/$2/$value/g" ${tdir}openssl.cnf
    ssl_value[(($count))]=$value
    (( count++ ))
}


# # # # # # # # #
# Create directories and get templates
cd $(dirname $0)
hdir="$PWD/"

runID=$(uuidgen)
tdir=${hdir}.tmp/${runID}/
rm -rf ${hdir}.tmp
mkdir -p $tdir

cp ${hdir}central/templates/openssl.cnf ${tdir}openssl.cnf
cp ${hdir}central/openssl/CA.pl ${tdir}CA.pl
# # # # # # # # # 


# # # # # # # # #
# Start message
echo ""
# # # # # # # # # 


# # # # # # # # # 
# Get Company
i=0
if [ $perform -eq 0 ] ;then

    while read file
    do
        ((i++))
        echo "[$i] $file"
        cho_company[(($i-1))]=$file
    done < <(ls "${hdir}companies/")

    if find ${hdir}companies/ -mindepth 1 | read; then
        read -p "Do you wanna use one of the exisiting companies? [(Number)|no(n)|exit(e)]: " decision
    else
        decision="n"
    fi

    nValid=1
    while [  $nValid -eq 1 ]; do

        re='^[0-9]+$'
        if [[ $decision =~ $re ]]; then
            company="${cho_company[$num_company-1]}"
            nValid=0

        elif [ $decision == "n" ] || [ $decision == "no" ] ; then
            read -p "Choose a company domain name (like \"domain.local\"): " company
            mkdir -p "${hdir}companies/$company"
            nValid=0

        elif [ $decision == "e" ] || [ $decision == "exit" ] ; then

            exit 0
        else

            read -p "Wrong decision please choose \"y\" or \"n\": " decision
            nValid=1
        fi

    done
    echo "Using company name: $company ..."
    echo ""
fi
# # # # # # # # # 


# # # # # # # # # 
# Choose CA
i=0
if [ $perform -eq 0 ]; then

    while read file
    do
        ((i++))
        echo "[$i] $file"
        cho_company[(($i-1))]=$file
    done < <(ls "${hdir}companies/$company/")

    if find ${hdir}companies/$company/ -mindepth 1 | read; then
        read -p "Do you wanna use one of the exisiting companies? [(Number)|no(n)|exit(e)]: " decision
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
            mkdir "${hdir}companies/$company/$ca"
            nValid=0
            newca=1

        else
            read -p "Wrong decision please choose \"y\" or \"n\": " decision
            nValid=1

        fi
    done
    echo "Using CA name: $ca ..."
    echo ""
fi
# # # # # # # # # 


# # # # # # # # # 
# Change CAs defaults 
if [ $perform -eq 0 ] ;then

    echo "You will now create a subject for your CA. These are information"
    echo "the strongswan gateway will use to identify the senders and receivers"
    echo "Additionally this script saves the parameters you choose as default"
    echo "values for later use."
    change_openssl_config "CA Country (2 Letters): " "0xCountryNamex0"
    change_openssl_config "CA State: " "0xStateNamex0"
    change_openssl_config "CA City: " "0xHometownx0"
    change_openssl_config "CA Company Name: " "0xCompanyx0"
    change_openssl_config "CA Unit (Company: Server/Client (specific): " "x0Unit0x"
    echo ""
    echo "Your server name like ca.domain.local"
    change_openssl_config "CA CommonName: " "x0commonNamex0"
    change_openssl_config "CA nsComment (optional): " "0x!nsComment!x0"
    echo ""
    echo "What will the generale liftime of a certificate, created with this CA, be?"
    echo "You have to reissue any certificate after this periode"
    echo "The certificate of the CA itself has a lifetime of 3 year (1095 days)"
    change_openssl_config "CA Certificate Lifetime (30): " "!0AcertificateLifetime"
    export subject="/C=${ssl_value[0]}/ST=${ssl_value[1]}/L=${ssl_value[2]}/O=${ssl_value[3]}/OU=${ssl_value[4]}/CN=${ssl_value[5]}"
    echo "Using Subject: $subject"
fi
# # # # # # # # # 


# # # # # # # # # 
# Choose keylength and gateway name
if [ $perform -eq 0 ]; then
    if [ $newca -eq 1 ]; then
        rsync -a ${hdir}central/templates/openssl.cnf ${hdir}companies/$company/$ca/
        rsync -a ${hdir}central/templates/configs ${hdir}companies/$company/$ca/
        # Copy templates to new folder
    else
        rm -rf ${hdir}companies/$company/$ca/demoCA
    fi
    echo ""
    echo "A 4096bit key length can result in MTU issues on some ISPs"
    echo "For higher compatibility, e.g. for mobile devices, use a smaller length like"
    echo "2048bit but you have to reissue them more often. It's not recommended to use"
    echo "a key lenght less than 1024bit. For a site to site connection you"
    echo "should probably use the 4096bit lenght."
    change_openssl_config "Key length (1024|2048|4096)" "x0keyStrength0x"
    # Key strength

    echo ""
    echo "In some situations VPN clients and servers reading if the Domain name "
    echo "of the ipsec gateway exists and resolves to the IP Adress of the gateway."
    echo "So if you use this parameter wrong your certificates will not authenticate."
    echo "Please add 'DNS:' at the beginning if you use a DNS Name."
    echo "Please add 'IP:' before the IP if you use a static IP."
    change_openssl_config "Server (IP:... or DNS:...)" "x0serverIp0x"
    # Server IP
fi
# # # # # # # # # 

# # # # # # # # # 
# Get CA
if [ $perform -eq 0 ] ;then

    newpass=`create_password $1`
    echo ""
    echo "New password: $newpass"
    export password=$newpass

    echo ""
    echo "Create CA..."
    export OPENSSL\_CONF=${tdir}openssl.cnf
    perl ${tdir}CA.pl -newca
    if [ $? -gt 0 ]; then
        echo ""
        echo "Something went wrong. The CA has not been created!"
        exit 1
    fi

    echo ""
    echo "Move all files and information into destination directory..."
    if [ $perform -eq 0 ] ;then
        for x in ${tdir}openssl.cnf ${hdir}demoCA ${tdir}CA.pl
        do
            mv $x ${hdir}companies/$company/$ca/
        done
    fi

    cp ${hdir}central/templates/configs/certs.pass  ${tdir}certs.pass
    sed -i "s/x0caPass0x/$newpass/g"                ${tdir}certs.pass
    sed -i "s/x0caCert0x/$ca/g"                     ${tdir}certs.pass
    sed -i "s/x0domain0x/$company/g"                ${tdir}certs.pass

    mkdir -p ${hdir}companies/$company/$ca/configs/
    echo $ca > ${hdir}companies/$company/$ca/configs/cacert.name
    mv ${tdir}certs.pass ${hdir}companies/$company/$ca/configs/certs.pass

    ln -rsf ${hdir}central/scripts/request-new-cert.sh  ${hdir}companies/$company/$ca/request-new-cert.sh
    ln -rsf ${hdir}central/scripts/check-cert.sh        ${hdir}companies/$company/$ca/check-cert.sh
    ln -rsf ${hdir}central/scripts/revoke-cert.sh       ${hdir}companies/$company/$ca/revoke-cert.sh
    echo ""
    echo "Your certificate authority has been created!"
    echo "All files are in:"
    echo "${hdir}companies/$company/$ca/"
fi
# # # # # # # # # 
