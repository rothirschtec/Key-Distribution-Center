#!/bin/bash
#
# Revoke a certificat
rev_cert="n"
cho_cert="n"
num_cert="n"

# # # # # # # # # #
# SHOW CERTS
# # # # # # # #
echo "-- Current certlist --"
i=0
while read file
do
   ((i++))
   cert="${file%.*}"
   hui="${cert%.*}"
   cert="${hui%.*}"
   hui="${cert##*: }"
   echo "[$i]..$hui"
   cho_cert[(($i-1))]=${file##*: }
done < <(sed -n "/^cert:/p" configs/certs.pass)
echo "-- Current certlist --"
# # # # # # # # # #


# # # # # # # # # #
# CHOOSE CERT
echo ""
read -p "What certificiate are you willing to check? [n]: " decision
rev_cert="${cho_cert[$decision-1]}"
echo "The client: ${rev_cert%%.*} will be checked!"
# # # # # # # # # #


# # # # # # # # # #
# CHECK CERT
openssl x509 -in certs.keys/certs/$rev_cert -text -noout
# # # # # # # # # #
