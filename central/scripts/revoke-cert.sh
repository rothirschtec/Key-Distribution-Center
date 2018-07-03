#!/bin/bash
#
# Revoke a certificate

cd $(dirname $0)
hdir=$PWD/
cd ../../../
mdir=$PWD/
cd $hdir

# # # # # # # # # # 
# Functions
maillog=false
function log {
    if [ $maillog == true ]; then
        echo $1 >> ${hdir}exchange.log
        if [ -z $2 ]; then
            if [[ $2 -eq 1 ]]; then
                echo ""  >> ${hdir}exchange.log
            fi
        fi
    else
        echo $1
        if [ -z $2 ]; then
            if [[ $2 -eq 1 ]]; then
                echo "" 
            fi
        fi
    fi
}


log "" 1
log " --- REVOKE CERT --- " 0

rev_cert="n"
decision=0
if [ -z $1 ]; then
    rev_cert="n"
    certnorm="n"
else
    rev_cert=$1
    certnorm=$1
    log $rev_cert 0
fi
cho_cert="n"
num_cert="n"
execute=1
#
# Program executions
read_report=false
cert_revoked=false
cert_existens=false
crl_updated=false
revoke_state="n"


# # #
# Change default openssl.cnf
export OPENSSL\_CONF=${hdir}openssl.cnf


if [ $execute -eq 1 ]; then
# # # # # # # # # #
# SHOW CERTS
# # # # # # # #
    log "-- Current certlist --" 0
    i=0
    while read file
    do
        cert="${file%.*}"
        hui="${cert%.*}"
        cert="${hui%.*}"
        hui="${cert##*: }"
        log "[$i]..$hui" 0
        cho_cert[(($i))]=${file##*: }
        if [ $hui == $rev_cert ]; then
            log "Found: $rev_cert" 0
            rev_cert=${cho_cert[$i]}
            break
        fi
        ((i++))
    done < <(sed -n "/^cert:/p" configs/certs.pass)
    log "-- Current certlist --" 0
# # # # # # # # # #
fi


if [ $execute -eq 1 ]; then
# # # # # # # # # #
# CHOOSE CERT
    if [ $rev_cert == "n" ]; then
        read -p "What certificiate are you willing to delete? [n]: " decision
        rev_cert="${cho_cert[$decision]}"
        cert="${rev_cert%.*}"
        hui="${cert%.*}"
        cert="${hui%.*}"
        confname="${cert##*: }"
        cert_num=$decision
        read -p "Do you really wanna revoke the client: ${rev_cert%%.*}? (yN): " decision
        if [[ $decision == "y" ]]; then
            log "Will be revoked and deleted" 0
        else
            exit 0
        fi
    else
        confname="$certnorm"
    fi
# # # # # # # # # #
fi


if [ $execute -eq 1 ]; then
    log "REVOKE: $rev_cert" 0
    cert_existens=false
    # # # # # # # # # #
    # CHECK EXISTENS
    openssl x509 -in "${hdir}certs.keys/certs/$rev_cert" -text -noout > /dev/null
    if [ $? -eq 0 ]; then
        cert_existens=true
        log "Cert exists" 0
    fi
    # # # # # # # # # #
fi


if [ $execute -eq 1 ]; then
# # # # # # # # # #
# PASS2ROOT
    log "Get ca password..." 0
    ca_pass=`sed -n "/^ca_pass:/p" ${hdir}configs/certs.pass`
    ca_pass=${ca_pass#*: }
# # # # # # # # # #
fi


if [ $execute -eq 1 ]; then
# # # # # # # # # #
# REVOKE CERT
    log "" 0
    if [ $rev_cert != "n" ]; then

        if [ $cert_existens == true ]; then

            openssl ca -passin pass:"$ca_pass" -keyfile ${hdir}demoCA/private/cakey.pem -cert ${hdir}demoCA/cacert.pem -revoke ${hdir}certs.keys/certs/$rev_cert
            if [ $? -eq 0 ]; then
                cert_revoked=true
            else
                cert_revoked=false
                echo "Revoke didn't work"
            fi
        fi
    fi
# # # # # # # # # #
fi

if [ $execute -eq 1 ] && [ $cert_revoked == true ]; then
# # # # # # # # # #
# UPDATING CRL
    log "" 0
    log "Updating crl..." 0
    openssl ca -passin pass:"$ca_pass" -keyfile ${hdir}demoCA/private/cakey.pem -cert ${hdir}demoCA/cacert.pem \
    -gencrl -out ${hdir}demoCA/crl/crl.pem
    if [ $? -eq 0 ]; then
        crl_updated=true
    else
        crl_updated=$?
    fi
# # # # # # # #
fi

if [ $execute -eq 1 ]; then
# # # # # # # # # #
# DELETE CERT
    log "" 0
    if [ $cert_revoked == true ]; then
        log "Deleting files..." 0 
        rm certs.keys/certs/$confname*
                log "certs.keys/certs/$confname [deleted]" 0
        rm certs.keys/private/$confname*
                log "certs.keys/private/$confname [deleted]" 0
        rm -f certs.keys/p12/$confname*
                log "certs.keys/p12/$confname [deleted]" 0
        log "Deleting from config..." 0
        echo "" >> configs/certs.revoked
        echo `date` >> configs/certs.revoked
        sed -n "/--$confname/,/--$confname/p" configs/certs.pass >> configs/certs.revoked
        sed "/--$confname/,/--$confname/d" configs/certs.pass >tmp
        mv tmp configs/certs.pass
    elif [ $cert_revoked == false ] && [ $cert_existens == true ]; then
        log "Deleting certs in folder because the CA doesn't now them" 0
        rm certs.keys/certs/$confname*
                log "certs.keys/certs/$confname [deleted]" 0
        rm certs.keys/certs/$confname*
                log "certs.keys/private/$confname [deleted]" 0
        log "Deleting from config..." 0
        echo "" >> configs/certs.revoked
        echo `date` >> configs/certs.revoked
        sed -n "/--$confname/,/--$confname/p" configs/certs.pass >> configs/certs.revoked
        sed "/--$confname/,/--$confname/d" configs/certs.pass >tmp
        mv tmp configs/certs.pass
    else
        log "Client: $confname could not been deleted. Reason: The revoke didn't work!" 0
    fi
    for x in configs/certs.pass
    do
        sed '/^$/d' $x >tmp
        mv tmp $x
    done
# # # # # # # #
fi

exit 0

log " --- REVOKE CERT ENDS --- " 1
log "" 0
