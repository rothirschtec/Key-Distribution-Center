#!/bin/bash

# # #
# Create directories and get templates
cd $(dirname $0)
hdir="$PWD/"

if [ -z $1 ]; then

    echo "Please provide a filename with path..."
    echo "For example: STORE/certs/test.domain.local.pem"
    exit 1

else

    # Revoke
    ./cert-revoke-remove $1

    # Recreate
    configs=${1##*/}
    configs=${configs%*.pem}
    ./cert-create CONFIGS/${configs}.configs

    # Transfer
    ./cert-transfer $1

    exit 0

fi
