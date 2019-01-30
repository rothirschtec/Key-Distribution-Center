#!/bin/bash

cd $(dirname 0)
home="$PWD/"
secrets="/etc/ipsec.secrets"
ipsecdi="/etc/ipsec.d/"

rsync -a ${home}certs/ ${ipsecdi}certs/
rsync -a ${home}private/ ${ipsecdi}private/
rsync -a ${home}cacerts/ ${ipsecdi}cacerts/

key=$(cat ${home}client_info.md |grep "ckey")
key=${key#ckey: *}

npw=$(cat ${home}client_info.md |grep "pass")
npw=${npw#pass: *}

echo ""
if [ $(cat /etc/ipsec.secrets |grep $key | wc -l) -gt 0 ];then

    opw=$(cat /etc/ipsec.secrets |grep $key)
    opw=$(echo $opw | grep -o '"[^"]*' | grep -o '[^"]*$')

    if [[ $opw == $npw ]]; then
        echo "Nothing to change"
        echo "New Password is the same as the old one"
    else
        echo "Change Password old: $opw to new: $npw ..."
        sed -i 's/'$opw'/'$npw'/g' $secrets 
    fi

else

    echo "New key found! Add to ipsec.secrets..."
    echo ': RSA '"$key"' "'"$npw"'"' >> /etc/ipsec.secrets

fi

subj=$(cat ${home}client_info.md |grep "subj")
subj=${subj#subj: *}

if [ $(cat /etc/ipsec.conf |grep "$subj" | wc -l) -eq 0 ];then

   echo "It looks like that there is no configuration for your subject in /etc/ipsec.conf"
   if [ $(cat /etc/ipsec.conf |grep "conn rt.conn" | wc -l) -eq 0 ];then
      echo "Adding configuration to /etc/ipsec.conf"
      echo "" >> /etc/ipsec.conf
      echo "# Rothirsch Tech. connection" >> /etc/ipsec.conf
      sed -n '/conn rt.conn/,$p' ${home}ipsec.conf >> /etc/ipsec.conf
      ipsec restart
      ipsec up rt.conn
   else
      echo "But there is an existing old connection, would you like to overwrite the whole /etc/ipsec.conf?"
      read -p "If you are not connected with an other strongswan Gateway you can use y (yN): " overwrite
      if [[ $overwrite == [yY] ]]; then
         read -p "Complete /etc/ipsec.conf will be overwritten by merge. Ok? (yN): " overwrite
         if [[ $overwrite == [yY] ]]; then
            mv ${home}ipsec.conf /etc/ipsec.conf
            ipsec restart
            ipsec up rt.conn
         fi
      fi
   fi
       
   
else 
    ipsec restart
fi

exit 0

