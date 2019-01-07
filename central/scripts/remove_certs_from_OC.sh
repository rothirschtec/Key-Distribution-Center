#/bin/bash
# 
# Deletes the ca_transfer directory from the owncloud server
# This prevents hackers from stealing data
# Author: René Zingerle
# Date: 07.01.2018 
# Version: v0.1
# Is meant to use it as cron job

cd $(dirname $0)
hdir=$PWD/
cd ../../
mdir=$PWD/
cd $hdir

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

if [ -z $1 ]; then
   i=0
   while read ssh_hosts
   do
      ssh_host[i]="${ssh_hosts#Host *}"
      echo [$i] ${ssh_host[i]}
      ((i++))
   done < <(cat ~/.ssh/config |grep ^'Host ')

   read -p "Choose one of the servers from within the ~/.ssh/config file: " ssh_host_number
   oc_host=${ssh_host[ssh_host_number]}
else 
   oc_host=$1
   if ! cat ~/.ssh/config |grep $oc_host; then
      echo "Sorry you have to configure your given host: $oc_host in your ~/.ssh/config file"
      exit 2
   fi
fi


ssh $oc_host rm -rf $ocdata
ssh $oc_host "cd $ocroot; sudo -u www-data php occ files:scan --all"
