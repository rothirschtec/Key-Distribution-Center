#!/bin/bash

if [ -z $1 ]; then
    read -p "Password: " password
else
    password=$1
fi
file="!0p12keyfile"

password=$(sed 's:/:\\/:g' <<< $password)

cp $file /etc/ipsec.d/private/

if ! cat /etc/ipsec.secrets | grep ": P12 ${file##*/}" &> /dev/null; then
    echo "Add new key to ipsec.secrets"
    echo ": P12 ${file##*/} '$password'" >> /etc/ipsec.secrets
else
    echo "Modify key inside ipsec.secrets"
    sed -i "s/: P12 ${file##*/}.*/: P12 ${file##*/} '${password}'/g" /etc/ipsec.secrets
fi


echo '

# Add this configuration to /etc/ipsec.conf

conn rt.conn
    # Client (left)
    leftid="!0SubjectLeft"
    left=%defaultroute
    leftsourceip=%config
    leftfirewall=yes
    rightid="!0SubjectRight"
    right=!0GatewayServer
    rightsubnet=0.0.0.0/0
    auto=add

    '
