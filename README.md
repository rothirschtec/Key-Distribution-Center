# Certificate Authority

## Installation

1. Simply download the git repository

2. Copy the file central/templates/defaults.sh to def_locl.sh. The def_locl will not be overwritten by a git pull and is ignored in the .gitignore file

    cp central/templates/defaults.sh def_locl.sh

3. Create a new certificate authority

    bash new-ca.sh

4. Create, revoke, transfer, renew,.... 
Change into newly created directory in the directory companies/_youcompany_/_yourca_/

    bash request-new-cert.sh

## Blog
Find further instructions on [https://blog.rothirsch.tech](https://blog.rothirsch.tech/server_farm/configurations/strongswan/)
