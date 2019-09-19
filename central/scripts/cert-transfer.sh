#/bin/bash

cd $(dirname $0)
hdir=$PWD/
cd ../../../
mdir=$PWD/
cd $hdir

maillog=false
if [ -f ${mdir}config ]; then source ${mdir}config
    if [[ ${ocdata##*/} != "" ]]; then
        ocdata=${ocdata}/
    fi
else
    echo "Please copy ${mdir}central/templates/defaults.sh"
    echo "to: ${mdir}config"
    echo "and configure it."
    exit 1
fi

mkdir -p ${hdir}certs.keys/certs/
mkdir -p ${hdir}certs.keys/private/
mkdir -p ${hdir}certs.keys/p12/
mkdir -p ${hdir}certs.keys/packages/
mkdir -p ${hdir}.tmp/
rm -rf ${hdir}.tmp/*
runId=$(uuidgen)
tdir="${hdir}.tmp/"

if [ ! -f ${hdir}.revokeCert ]; then
    cd $hdir
    ln -rsf ../../../central/scripts/revoke-cert.sh .revokeCert
fi

# # # # #

# # #
# Check dependencies
    check_dependencies() {

        # # #
        # Checks dependencies and tries to install them
        dep=("openssl" "perl" "pwgen" "uuid-runtime" "zip" "mailutils")

        ni=0
        for x in "${dep[@]}"; do
            dpkg -s $x &> /dev/null
            if [ $? -eq 1 ]; then
                echo "$x: is not installed"
                #apt-get -y install $x
                ni=$(($ni + 1))
            fi
        done
        return $ni
    }
    check_dependencies
    if [ $? -gt 0 ]; then
        echo "The script found missing dependencies. Install them first."
        exit 1
    fi
#
# # #


## LOG
function log {
    if [ $maillog == true ]; then
        echo $1 >> ${tdir}exchange.log
        if [ -z $2 ]; then
            if [[ $2 -eq 1 ]]; then
                echo ""  >> ${tdir}exchange.log
            fi
        fi
    else
        echo $1
        if [[ -z $2 ]]; then
            if [[ $2 -eq 1 ]]; then
                echo "" 
            fi
        fi
    fi
}
# # # 


function create_password {
    # Creates a Password with pwdgen
    pass=""
    for x in {1..2} 
    do
        pass+=`pwgen -1nc`
    done
    echo $pass
}
function create_client {
    # Writes the client into the clients file
    # Remove existing
    sed -i '/--'"$1"'--/,/--'"$1"'--/d' ${7}configs/certs.pass
    sed -i 'N;/^\n$/D;P;D;' ${7}configs/certs.pass
    echo ""                     >> ${7}configs/certs.pass
    echo "--$1--"               >> ${7}configs/certs.pass
    echo "clie: $1"             >> ${7}configs/certs.pass
    echo "pass: $2"             >> ${7}configs/certs.pass
    echo "p12PW: $3"            >> ${7}configs/certs.pass
    echo "eapPW: ${10}"         >> ${7}configs/certs.pass
    echo "subj: /C=${4##*/C=}"  >> ${7}configs/certs.pass
    echo "cert: $5"             >> ${7}configs/certs.pass
    echo "ckey: $6"             >> ${7}configs/certs.pass
    if [[ "$5" == "$9" ]]; then
        echo "main: 1: $5"      >> ${7}configs/certs.pass
    elif [[ $8 == "main" ]]; then
        echo "main: 1: $5"      >> ${7}configs/certs.pass
    else
        echo "main: 0: $5"      >> ${7}configs/certs.pass
    fi
    echo "--$1--"               >> ${7}configs/certs.pass
}
function chk_pass {
    if [ "$newpass" == "No certificate" ]; then
        i=0
        while read file
        do
            if [ $i == $certnum ]; then
                newpass=${file##*pass: }
                echo $newpass
            fi
            ((i++))
        done < <(sed -n "/^pass:/p" ${hdir}configs/certs.pass)
    else
        echo $newpass
    fi
}
# # # # # # # # # # 


# # # # # # # # # # 
# Get parameters
if [ -z $1 ]; then
    log "Mode: Testphase... [deactivated]" 1 "${mdir}"

    echo ''
    echo 'Different Modis'
    echo '---------------'
    echo 'Transfer Modi (trans)'
    echo 'Transfers an existing certificate to the main server'
    echo 'If certname is unknown write "unknown" instead of "certname"'
    echo 'If you want to change the keys password on the servers'
    echo 'ipsec.secrets add "main" as fourth argument'
    echo 'Short command: ./manageCerts "trans" "servername" "certname"'
    echo ''
    echo 'Transfer All Modi (transall)'
    echo 'Transfers all existing certificate to the main server'
    echo 'If certname is unknown write "unknown" instead of "certname"'
    echo 'Short command: ./manageCerts "transall"'
    echo ''
    echo 'Recreate Modi (recreate)'
    echo 'Revokes and then creates or recreates a certificate'
    echo 'You have to tell the CA if this is the certificate of the gateway.'
    echo 'If so write "main" as 4th parameter. If not leave it be.'
    echo 'Short command: ./manageCerts "recreate" "certs@domain.at" "certname" "main"'
    echo ''
    echo 'Renew All (renew)'
    echo 'Revokes and then distributes all existing certificates to the'
    echo 'distribution folder. Additional it sends the zip passwords to'
    echo 'the clients from a clientlist or if you set an e-Mail Adress'
    echo 'as 2nd attribute all certs will be send to that one'
    echo 'Short command: ./manageCerts "renew"'
    echo '---------------'
    read -p "Did you know that you can also execute this script as an oneliner? (b)eta: " ol
    if [[ $ol != "b" ]]; then
        log "Mode: BETA tools" 1 "${mdir}"
        exit 1
    fi
    if [[ $cmd == "" ]]; then
        cmd="empty"
    fi
    echo ""
else
    cmd=$1
    if [ "$cmd" == "test" ]; then
        log "Mode: Testphase... [activated]" 1 "${mdir}"
    fi
fi

if [ -z $2 ]; then
    # Server address
    if [ $cmd == "transall" ]; then
        #0xtransall
        if [[ $ipsecgw != "" ]]; then
            sendto=$ipsecgw
        else
            echo "Please configure the ipsec gateway in defaults.sh or config"
            exit 1
        fi
        trans=t
    else
        sendto="unknown"
    fi
else
    sendto=$2
fi

declare -a newcert
ac=0
if [ -z $3 ]; then
    # E-Mail Address
    newcert[0]="unknown"
else
    newcert[0]=$3
fi

if [ -z $4 ]; then
    # E-Mail Address
    snd_to_cmp="empty"
else
    snd_to_cmp=$4
fi


perform=0
if [ "$cmd" == "test" ]; then
    win_pass="test"
    newpass="test"
else
    win_pass="No windows certificate"
    newpass="No certificate"
fi
certnum=0

export OPENSSL\_CONF=${hdir}openssl.cnf


certs=${hdir}certs.keys/certs
keys=${hdir}certs.keys/private
newconf=${tdir}newcert/new.conf

firstOne=0
    # This variable shows if a certificate has never existed before

# # # # # # # # # # 


# # # # # # # # # # 
# Find cacert name

mainca=`cat ${hdir}configs/cacert.name`
if [[ $mainca == "" ]] ; then
    read -p " -> No cacert detected (name): " mainca
else
    log "  -> Cacert detected: $mainca" 1 "${mdir}"
fi
echo 

# # # # # # # # # # 


# # #
# End script if there is no "main" cert
if ! cat ${hdir}configs/certs.pass |grep "main: 1" &>/dev/null; then
    echo "Couldn't find a main certificate!"
    if [[ $cmd != "recreate" ]]; then
        echo 'Please create it first with: manageCerts "recreate" "certs@domain.at" "certname" "main"'
        echo 'The parameter "main" at the end of the line inidicates the choosen certificate as main'
        exit 1
        
    elif [[ $cmd == "recreate" ]] && [[ $snd_to_cmp == "empty" ]]; then
        echo 'Please create it first with: manageCerts "recreate" "certs@domain.at" "certname" "main"'
        echo 'The parameter "main" at the end of the line inidicates the choosen certificate as main'
        exit 1

    else
        echo "But will be created in this round..."
        company=$(ls ../../)
        gwcert="${newcert[ac]}.${company}.${mainca}.cert.pem"
    fi
else
    gwcert=$(awk -F ":" '{print $3}' <<< $(cat ${hdir}configs/certs.pass | grep "main: 1"))
    gwcert=$(sed 's/ //g' <<< $gwcert)

    # # #
    # Get gateway certs subject
    maini=1
    while read mainc
    do
        if [[ $mainc == "main: 1:"* ]]; then
            mii=$maini
        fi
        ((maini++))
    done < <(cat ${hdir}configs/certs.pass  |grep "main:.*:")
    maini=1
    while read subjc
    do
        if [ $maini -eq $mii ]; then
            subjgw=$(sed -n "${mii}p" <<< $subjc)
            subjgw=${subjgw#subj: *}
        fi
        ((maini++))
    done < <(cat ${hdir}configs/certs.pass  |grep "subj: ")
# # #
fi
# # #


# # # # # # # # # # 
# Choose a certname
domain=`sed -n "/^ca_domain:/p" ${hdir}configs/certs.pass`
domain="${domain##*: }"

if [ ${newcert[$ac]} == "unknown" ] && [[ $cmd != "transall" ]]; then

    if [ $(sed -n "/^cert:/p" ${hdir}configs/certs.pass | wc -l) -gt 0 ]; then

        i=0
        while read file
        do
            cert="${file##*:}"
            cert="${cert%%.*}"
            cert=$(sed 's/ //g' <<< ${cert})

            newcert[$i]=$cert
            log "[$i] ${newcert[$i]}" 0 "${mdir}"
            (( i++ ))

        done < <(sed -n "/^cert:/p" ${hdir}configs/certs.pass)

        echo "Choose cert from existing [Number] or"

    fi

    cexistens=false
        # Checks if the user uses an existing certificate
    if [ ${cmd} != "renew" ]; then

        read -p "Write a new shortname for Server/Client: " dec

        re="^[0-9]$" 
        if [[ $dec =~ $re ]]; then
            newcert[$ac]=${newcert[$dec]}
            cexistens=true
        elif [[ $dec == "" ]]; then
            echo "You have to choose at least one certificate."
            exit 1
        else
            newcert[$ac]=$dec
        fi
    fi
fi
# # # # # # # # # # 


# # # # # # # # # # 
# Rsync certs to gateway (transall)
if [[ $cmd == "transall" ]]; then
    #0xtransall

    log "" 1 "${mdir}"
    log "Rsync certs to destination device... " 1 "${mdir}"

    echo "Test connection..."
    if ssh -q root@$sendto exit; then
        echo "...connection established..."

        echo "Transfering certs to the gateway..."
        if [[ ${newcert[$ac]} != "unknown" ]];then
            rsync -a ${hdir}demoCA/cacert.pem root@$sendto:/etc/ipsec.d/cacerts/$mainca.cacert.${domain}.pem
            rsync -a ${hdir}demoCA/crl/crl.pem root@$sendto:/etc/ipsec.d/crls/$mainca.crl.${domain}.pem
        fi
    else
        echo "Not able to connect to destination server"
        echo "Destination: $sendto"
        exit 1
    fi
    i=0
    while read file
    do
        cert="${file##*:}"
        cert="${cert%%.*}"
        cert=$(sed 's/ //g' <<< ${cert})
        newcert[$i]=$cert
        (( i++ ))
    done < <(sed -n "/^cert:/p" ${hdir}configs/certs.pass)
fi
# # # # # # # # # # 

endloop=0
 # If an event is choosen the only effects one certificate the endloop
 # will be the certificate amount and will so end the round because the  
 # script sums it with ac at the end of the loop 
for (( ac=0; ac<${#newcert[@]}; ac++ ))
do


    echo "" 
    echo ------------------------
    echo CERT: ${newcert[ac]}
    echo ------------------------
    echo "" 
    # Loop through certs
    newcert[$ac]="${newcert[$ac]}.$domain"
    eappass=`create_password`

    if [[ $cmd != "transall" ]]; then

        log "-> Use Certificate: '${newcert[$ac]}'" 0 "${mdir}"
        # # # # # # # # # # 


        # # # # # # # # # # 
        # Check if cert exists

        # # Save the subject and revoke the cert
        chk=0 
        i=0	
        certnum=99

        # Checks if the while loop even runs
        while read file
        do

            # Check if cert exists
            cert="${file##*:}"
            cert="${cert%%.*}"
            if [ $cert == ${newcert[$ac]} ]; then

                # # # # # # # # # # 
                # find certnumber
                log -n "Find certnumber " 0 "${mdir}"
                while read file
                do
                    cert="${file##*:}"
                    cert="${cert%%.*}"
                    if [ $cert == ${newcert[$ac]} ]; then
                        certnum=$i
                        log "Cert Number..." 0 "${mdir}"
                        log "Number of current certificate: $certnum" 0 "${mdir}"
                        break
                    fi	
                    (( i++ ))
                    echo -n "."
                done < <(sed -n "/^cert:/p" ${hdir}configs/certs.pass)

                # # # # # # # # # # 
                # find subject
                i=0	
                while read file
                do
                    cert="${file#*subj: }"
                    if [ $i == $certnum ]; then
                        cert_subject="$cert"
                    fi	
                    (( i++ ))
                done < <(sed -n "/^subj:/p" ${hdir}configs/certs.pass)

                if [ $cmd != "recreate" ] && [ $cmd != "trans" ] && [ $cmd != "renew" ]; then
                    read -p "Certificate exists! [r]evoke/[e]xit/[Enter]use it: " decision </dev/tty

                elif [ $cmd == "trans" ]; then
                    decision="t"
                    break
                else
                    decision="r"

                fi

                if [[ $decision == "r" ]]; then
                    bash ${hdir}.revokeCert "${newcert[$ac]}"
                    break
                elif [ "$decision" == "e" ]; then
                    exit 1
                else
                    log "Not revoked!" 0 "${mdir}"
                    decision="norev"
                fi

            else
                decision="new"
            fi
            chk=1
        done < <(sed -n "/^cert:/p" ${hdir}configs/certs.pass)

        if [ $chk == 0 ] && [ -z $decision ]; then
            decision="new"
        fi
        # # # # # # # # # # 


        # # # # #
        # Create a certificate 
        if [[ $cmd != "recreate" ]] && [[ $cmd != "trans" ]] && [[ $cmd != "renew" ]]; then
            read -p "You can either transfer or save the certs, or do all together? ($(if [[ $cexistens == true ]]; then echo "re"; fi)[c]reate|[t]ransfer|[p]12|[m]ail|[a]ll): " trans
            endloop=${#newcert[@]}

        elif [[ $cmd == "trans" ]]; then
            trans="t"
        else
            trans="recreate"
        fi


        # # #
        # Create a subject for a certificate
        if [[ $decision == "new" ]] && [[ $trans != "p" ]] && [[ $trans != "t" ]] && [[ $trans != "m" ]]; then

            function readconf() {
                val=$(cat ${hdir}openssl.cnf | grep "$1")
                echo ${val##*= } 
            }
           
            if [[ $cmd != "renew" ]]; then 
                read -e -p "Country: " -i "$(readconf 'countryName_default')" cnf_country
                read -e -p "State: " -i "$(readconf 'stateOrProvinceName_default')" cnf_state
                read -e -p "Location: " -i "$(readconf 'localityName_default')" cnf_location
                read -e -p "Company: " -i "$(readconf '0.organizationName_default')" cnf_company
                read -e -p "Organisation Unit: Server/Client - (Name): " -i "" cnf_ou
                read -e -p "Common Name CN (user.domain.local): " -i "" cnf_cn
                if [[ $sendto != "unknown" ]]; then
                    echo "E-Mail cert owner: $sendto"
                    cert_owner=$sendto
                else
                    read -e -p "E-Mail cert owner: " -i "rene@rothirsch.tech" cert_owner
                fi
                cert_subject="/C=$cnf_country/ST=$cnf_state/L=$cnf_location/O=$cnf_company/OU=$cnf_ou/CN=$cnf_cn" 

                if [[ $cmd == "recreate" ]]; then 
                    if grep "${newcert[$ac]}" ${hdir}configs/usr.list &>/dev/null; then
                        firstOne=1
                        bash ${hdir}.revokeCert "${newcert[$ac]}"
                    fi
                fi

                if grep -rl "${newcert[$ac]%%.*};" ${hdir}configs/usr.list &> /dev/null; then
                    sed -i "s/${newcert[$ac]%%.*};.*;/${newcert[$ac]%%.*};$cert_owner;$eappass;/g" ${hdir}configs/usr.list
                else
                    echo "${newcert[$ac]%%.*};$cert_owner;$eappass;" >> ${hdir}configs/usr.list
                fi
            else

                # # #
                # Get subject and revoke existing cert
                cont=$(sed '/^--'"${newcert[ac]}"'--$/,/^--'"${newcert[ac]}"'--$/{//!b};d'  ${hdir}configs/certs.pass)
                cert_subject=$(echo $cont | grep -o -P '(?<=subj: ).*(?= cert:)')
                bash ${hdir}.revokeCert "${newcert[$ac]}"
            fi

            echo
        fi
        # # # # # # # # # # 

        # # #
        # Create certificate
        if [[ "$trans" == "c" ]] || [[ "$trans" == "a" ]] || [[ "$cmd" == "recreate" ]] || [[ $cmd == "renew" ]]; then

            log "Create new request..." 1 "${mdir}"

            # # #
            # Create new password
            if [[ $cmd == "test" ]]; then
                newpass="test"
            else
                newpass=`create_password`
            fi
            export password="$newpass"
            # # # # # # # # # # 

            # # #
            # Change subjectAltName to Common name of client certificate
            # https://wiki.strongswan.org/projects/strongswan/wiki/Win7CertReq
            sed -i "s/^subjectAltName=DNS:.*$/subjectAltName=DNS:$cnf_cn/g" ${hdir}openssl.cnf

            openssl req \
                    -new \
                    -config openssl.cnf \
                    -passout pass:$newpass \
                    -subj "$cert_subject" \
                    -keyout ${hdir}newkey.pem \
                    -out ${hdir}newreq.pem

            log "" 0 "${mdir}"
            log "Sign new key..." 1 "${mdir}"
            capassword=`sed -n '/ca_pass:/p' ${hdir}configs/certs.pass`
            export password=${capassword##*ca_pass: }
            perl ${hdir}CA.pl -sign

            log "" 0 "${mdir}"
            log "Move keys and certs to folder..." 1 "${mdir}"
            mv ${hdir}newcert.pem $certs/${newcert[$ac]}.$mainca.cert.pem
            mv ${hdir}newkey.pem $keys/${newcert[$ac]}.$mainca.key.pem

            log "" 0 "${mdir}"
            log "Generate crl..." 1 "${mdir}"
            openssl ca -gencrl -passin pass:"$password" -crldays 30 -out ${hdir}demoCA/crl/crl.pem &>/dev/null

        fi
    else
        trans="t"
    fi
    # # # # # # # # # # 

    # # # # #
    # Transfer to given Servers
    if [[ $trans == "t" ]] || [[ $trans = "a" ]] ; then

        if [[ $cmd == "trans" ]] || [[ $cmd == "transall" ]]; then
            #0xtransall

            log "Start transfer..." 1 "${mdir}"

            if [[ $sendto != "unknown" ]]; then
                ca_ip=$sendto
            else
                read -p "Servername from ${HOME}/.ssh/config (1. host): " ca_ip
                echo $ca_ip
            fi
            isgw="y"
            if [[ "$gwcert" == "${newcert[$ac]}.$mainca.cert.pem" ]] || [[ $cmd == "transall" ]]; then
                priKey="y"
                chaPass="y"
            else
                priKey="N"
                chaPass="N"
            fi
            issecser="N"
            server=0
            isgateway="N"

        else
            read -p "Servername from ${HOME}/.ssh/config (1. host): " ca_ip
            read -p "Should the cacert and crl been transfered? (yN): " isgw
            read -p "Should the private key been transfered? (yN): " priKey
            read -p "Change Password on Server? (yN): " chaPass
            read -p "Is there a 2. host? (yN): " issecser
            if [[ $issecser == "y" ]] ; then
                read -p "IP 2. host: " server
                read -p "Do the 2. server need the cacert and the crl? (yN): " isgateway
            fi
        fi

        log "-> transfer over ssh..." 1 "${mdir}"
        # 1. Server

        if [[ "$gwcert" == "${newcert[ac]}.${mainca}.cert.pem" ]]; then

            if ssh -q root@$ca_ip exit; then

                if [[ $priKey == "y" ]] ; then

                    rsync -a $keys/${newcert[$ac]}.$mainca.key.pem root@$ca_ip:/etc/ipsec.d/private/

                    if [[ $chaPass == "y" ]]; then

                        newpass=`chk_pass $newpass`
                        log "Get ipsec.secrets..." 0 "${mdir}"
                        rsync -a root@${ca_ip}:/etc/ipsec.secrets ${tdir}${runId}.ipsec.secrets
                        log "Change ${newcert[$ac]}.${mainca}.key.pem in ipsec.secrets..." 0 "${mdir}"

                        if grep -r "${newcert[$ac]}.${mainca}.key.pem" ${tdir}${runId}.ipsec.secrets &>/dev/null; then
                            sed -i "s|: RSA ${newcert[$ac]}.${mainca}.key.pem.*|: RSA ${newcert[$ac]}.${mainca}.key.pem \"$newpass\"|g"  ${tdir}${runId}.ipsec.secrets
                        else
                            echo ': RSA '${newcert[$ac]}'.'${mainca}'.key.pem "'$newpass'"' >> ${tdir}${runId}.ipsec.secrets
                        fi

                        log "Upload ipsec.secrets..." 0 "${mdir}"
                        rsync -a ${tdir}${runId}.ipsec.secrets root@${ca_ip}:/etc/ipsec.secrets
                        log "Remove local ipsec.secrets..." 1 "${mdir}"
                        rm -f ${tdir}${runId}.ipsec.secrets

                    else
                        log "Password not changed" 1 "${mdir}"
                    fi
                fi
                if [[ $isgw == "y" ]] ; then
                    rsync -a ${hdir}demoCA/cacert.pem root@$ca_ip:/etc/ipsec.d/cacerts/$mainca.cacert.${domain}.pem
                    rsync -a ${hdir}demoCA/crl/crl.pem root@$ca_ip:/etc/ipsec.d/crls/$mainca.crl.${domain}.pem
                fi

                if [[ $issecser == "y" ]] ; then
                    # 2. Server
                    rsync -a $certs/${newcert[$ac]}.$mainca.cert.pem root@$server:/etc/ipsec.d/certs/
                    if [[ $isgateway == "y" ]] ; then
                        rsync -a ${hdir}demoCA/cacert.pem root@$server:/etc/ipsec.d/cacerts/$mainca.cacert.${domain}.pem
                        rsync -a ${hdir}demoCA/crl/crl.pem root@$server:/etc/ipsec.d/crls/$mainca.crl.${domain}.pem
                    fi
                fi
            fi
        fi
    fi
    # # # # #

    # Show subject and delete request
    if [[ $trans == "p" ]] || [[ $trans == "a" ]] || [[ $cmd == "recreate" ]] || [[ $cmd == "renew" ]]; then

        log "show subject of cert..." 1 "${mdir}"
        subject=`openssl x509 -in ${hdir}certs.keys/certs/${newcert[$ac]}.$mainca.cert.pem -noout -subject`
        rm -f newreq.pem


        if [[ $gwcert != ${newcert[ac]}.${mainca}.cert.pem ]]; then

            log "p12 convertion..." 1 "${mdir}"
            windows=0

            if [[ $trans == "a" ]]; then
                read -p "Shall the cert been converted into a p12 cert for windows users (1/0): " windows
            fi

            if [[ $windows == "1" ]] || [[ $trans == "p" ]] || [[ $cmd == "recreate" ]] || [[ $cmd == "renew" ]]; then

                if [[ "$newpass" == "No certificate" ]]; then
                    i=0
                    while read file
                    do
                        if [[ "$i" == "$certnum" ]]; then
                            newpass=${file##*pass: }
                        fi
                        ((i++))
                    done < <(sed -n "/^pass:/p" ${hdir}configs/certs.pass)
                fi

                if [[ $cmd == "test" ]]; then
                    win_pass="test"
                else
                    win_pass=`create_password`
                fi

                i=0

                openssl pkcs12 -export -passout pass:"$win_pass" -passin pass:"$newpass"  -in ${hdir}certs.keys/certs/${newcert[$ac]}.$mainca.cert.pem -inkey ${hdir}certs.keys/private/${newcert[$ac]}.$mainca.key.pem -certfile demoCA/cacert.pem -out certs.keys/p12/${newcert[$ac]}.$mainca.p12

                while read file
                do
                    if [[ "$i" == "$certnum" ]]; then
                        wp=${file##*p12PW: }
                        sed -i "s/p12PW: $wp/p12PW: $win_pass/g" ${hdir}configs/certs.pass
                    fi
                    ((i++))
                done < <(sed -n "/^p12PW:/p" ${hdir}configs/certs.pass)

            fi
        fi
    fi
    # # # # #

    if [[ $trans == "a" ]] || [[ $cmd == "recreate" ]] || [[ $trans == "c" ]] || [[ $cmd == "renew" ]]; then

        create_client "${newcert[$ac]}" "$newpass" "$win_pass" "$cert_subject" "${newcert[$ac]}.${mainca}.cert.pem" "${newcert[$ac]}.${mainca}.key.pem" "${hdir}" "$snd_to_cmp" "$gwcert" "$eappass"

        if [ $(grep "main: 1" ${hdir}configs/certs.pass | wc -l) -gt 1 ]; then
            sed -i 's/main: 1/main: 0/g' ${hdir}configs/certs.pass
            echo "There were more then one main certificates configure."
            echo "The script reseted all main certs"
            echo 'Please recreate the main cert first with: ./manageCerts "recreate" "certs@domain.at" "certname" "main"'
            echo 'The parameter "main" at the end of the line inidicates the choosen certificate as main'
            exit 1
        fi

    fi

    if [[ $trans == "m" ]] || [[ $trans == "a" ]] || [[ $cmd == "trans" ]] || [[ $cmd == "transall" ]] ; then
                    
        i=0
        while read file
        do
            if [[ "$i" == "$certnum" ]]; then
                win_pass=${file##*p12PW: }
            fi
            ((i++))
        done < <(sed -n "/^p12PW:/p" ${hdir}configs/certs.pass)
        
        # # #
        # Transfer cert to the server
        echo "Transfering: ${newcert[$ac]}.${mainca}.cert.pem"
        rsync -a $certs/${newcert[$ac]}.${mainca}.cert.pem root@$ca_ip:/etc/ipsec.d/certs/

        # # #
        # Share with owncloud
        if rsync -a ${hdir}certs.keys/packages/${newcert[$ac]}.zip root@$ca_ip:${ocdata}; then

            if [[ ${newcert[$ac]}.${mainca}.cert.pem != $gwcert ]]; then

                rsync -a ${mdir}central/templates/README.md             root@$ca_ip:${ocdata}
                ssh root@$ca_ip chown -R www-data: ${ocdata}
                ssh root@$ca_ip "cd $ocroot; sudo -u www-data php occ files:scan --all"

                # # #
                # Create mail content
                rsync -a ${mdir}central/templates/transmail ${tdir}transmail
                sed -i 's/#!ca0x/'"$mainca"'/g'             ${tdir}transmail
                sed -i 's|#!ownCloud|'"$ocinstance"'|g'     ${tdir}transmail

                # # #
                # Send info mail to user
                usermail=$(awk -F ";" '{print $2}' <<< $(cat ${hdir}configs/usr.list | grep ${newcert[$ac]%%.*}))

                # # #
                # Changing EAP password
                rsync -a root@$ca_ip:/etc/ipsec.secrets ${tdir}ipsec.secrets
                user=${usermail%@*}

                eappass=$(awk -F ";" '{print $3}' <<< $(cat ${hdir}configs/usr.list | grep ${newcert[$ac]%%.*}))
                if cat ${tdir}ipsec.secrets | grep "$user : EAP" &>/dev/null; then
                    sed -i 's/'"${user}"' : EAP.*$/'"${user}"' : EAP "'"$eappass"'"/g' ${tdir}ipsec.secrets
                else
                    echo ''"${user}"' : EAP "'"$eappass"'"' >> ${tdir}ipsec.secrets
                fi
                rsync -a ${tdir}ipsec.secrets root@$ca_ip:/etc/ipsec.secrets
                


                echo "Sending mail to user..."
                cat ${tdir}transmail | mail -s "Transferred certificates for ${newcert[$ac]} ($(date +%d.%m.%y))" -a "From: $mainemail" $usermail
                rm -f ${tdir}transmail
            fi

        else
            echo ""
            echo "The directory you set in your defaults.sh or config doesn't exists"
            exit 0
        fi

    elif [[ $cmd == "recreate" ]] || [[ $cmd == "renew" ]]; then

        rm -rf  ${tdir}newcert/*
        mkdir -p ${tdir}newcert/certs
        mkdir -p ${tdir}newcert/private
        mkdir -p ${tdir}newcert/p12
        mkdir -p ${tdir}newcert/cacerts

        rsync -a ${hdir}certs.keys/certs/${gwcert}                          ${tdir}newcert/certs/
        rsync -a ${hdir}certs.keys/certs/${newcert[$ac]}.$mainca.cert.pem   ${tdir}newcert/certs/
        rsync -a ${hdir}certs.keys/private/${newcert[$ac]}.$mainca.key.pem  ${tdir}newcert/private/
        if [[ $gwcert != ${newcert[ac]}.${mainca}.cert.pem ]]; then
            rsync -a ${hdir}certs.keys/p12/${newcert[$ac]}.$mainca.p12          ${tdir}newcert/p12/
        fi
        rsync -a ${hdir}demoCA/cacert.pem                                   ${tdir}newcert/cacerts/$mainca.ca.pem

        # Create linux installer
        cp ${mdir}central/scripts/installer/install_lnx.sh                  ${tdir}newcert/
        cp ${mdir}central/templates/ipsec.conf                              ${tdir}newcert/
        # Create windows installer
        cp ${mdir}central/scripts/installer/windows_install_cert.bat        ${tdir}newcert/


        # # #
        # Create an ipsec.conf
        srv=`sed -n "/^subjectAltName/p" "openssl.cnf"`
        if [[ $srv == *"DNS:"* ]]; then
            right=${srv##subjectAltName=DNS:}
        else
            right=${srv##subjectAltName=IP:}
        fi

        sed -i 's/!#Right0x/'"$right"'/g'                              	        ${tdir}newcert/ipsec.conf
        sed -i 's/!#LeftCert0x/'"${newcert[$ac]}"'.'"${mainca}"'.cert.pem/g' 	${tdir}newcert/ipsec.conf
        sed -i 's\!#LeftID0x\'"${cert_subject}"'\g'                   	        ${tdir}newcert/ipsec.conf
        sed -i 's\!#RightID0x\'"${subjgw}"'\g'                         	        ${tdir}newcert/ipsec.conf
        # # #

        sed -i "s/!!Password!!/$win_pass/g"                                 ${tdir}newcert/windows_install_cert.bat
        sed -i 's/!!Certificate!!/'"${newcert[$ac]}"'.'"${mainca}"'.p12/g'  ${tdir}newcert/windows_install_cert.bat

        sed "/--${newcert[$ac]}--/,/--${newcert[$ac]}--/!d" ${hdir}configs/certs.pass >${tdir}newcert/client_info.md

        zippass=`create_password`
        cd ${tdir}
        zip -P $zippass -r ../${newcert[$ac]}.zip newcert/* > /dev/null
        cd ..
        echo "Zip Password: $zippass"

        if [[ $cmd == "renew" ]]; then

            # Get E-Mail from User
            # # #
            # Send info mail to user
            usermail=$(awk -F ";" '{print $2}' <<< $(cat ${hdir}configs/usr.list | grep ${newcert[$ac]%%.*}))

        elif [[ $sendto == "unknown" ]]; then

            read -p "Mailaddress: " -i "certs@domain.at" usermail
        else

            usermail=$sendto
        fi

        eapold=$(awk -F ";" '{print $3}' <<< $(cat ${hdir}configs/usr.list | grep ${newcert[$ac]%%.*}))
        sed -i 's/'"${newcert[ac]%%.*}"';'"$usermail"';'"$eapold"';/'"${newcert[ac]%%.*}"';'"$usermail"';'"$eappass"';/g' ${hdir}configs/usr.list 

        # # #
        # Store newcert
        rsync -a --delete ${tdir}newcert/ ${hdir}certs.keys/packages/${newcert[ac]}/
        mv ${newcert[$ac]}.zip ${hdir}certs.keys/packages/
        echo "$zippass" > ${hdir}certs.keys/packages/${newcert[ac]}.pass

        # # #
        # Create mail content
        rsync -a ${mdir}central/templates/pwmail    ${tdir}pwmail
        sed -i 's/#!ca0x/'"$mainca"'/g'             ${tdir}pwmail
        sed -i 's/#!zipPass/'"$zippass"'/g'         ${tdir}pwmail

        if [[ ${newcert[$ac]}.${mainca}.cert.pem != $gwcert ]]; then
            # # #
            # Send info mail to user
            echo "Sending mail to user..."
            echo mail -s "New password for Client ${newcert[$ac]} ($(date +%d.%m.%y))" -a "From: $mainemail" $usermail
            cat ${tdir}pwmail
            cat ${tdir}pwmail | mail -s "New password for Client ${newcert[$ac]} ($(date +%d.%m.%y))" -a "From: $mainemail" $usermail
            rm -f ${tdir}pwmail
        fi

    fi

    # Ends the loop if necessary
    ac=$(($ac + $endloop))

done


if [[ $cmd == "trans" ]] || [[ $cmd == "transall" ]] ; then
   ssh root@${ca_ip} ipsec restart
   log "Restart ipsec on root@${ca_ip}..." 1 "${mdir}"
fi

log "" 0 "${mdir}"
log "Request successful" 1 "${mdir}"
