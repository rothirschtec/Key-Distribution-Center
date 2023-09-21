#!/bin/bash

# # #
# Create directories and get templates
cd $(dirname $0)
hdir="$PWD/"

for x in STORE/certs/*
do 
    if [[ $(./cert-info $x | grep 'not after') =~ 'expired' ]]; then

        # Revoke
        ./cert-revoke-remove $x

        # Recreate
        configs=${x##*/}
        configs=${configs%*.pem}
        ./cert-create CONFIGS/${configs}.configs

        # Transfer
        ./cert-transfer $x

    fi
done
