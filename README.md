# Certificate Authority

This project helps you to manage your certifcates created by the _ipsec pki_. The idea is, that you install a separated server that serves as a Certificate Authority. This server will be your highly confitential location. All certificates created are then send to an IPSEC Gateway. On this gateway is also a owncloud instance installed for _Out of Band_ key distribution.

## Dependencies

First you have to build the latest strongswan version on both devices. [https://blog.rothirsch.tech/strongswan/](https://blog.rothirsch.tech/server_farm/configurations/strongswan/#!install).

If you want to setup the ipsec gateway you have also to install owncloud. [https://blog.rothirsch.tech/owncloud/](https://blog.rothirsch.tech/server_farm/configurations/owncloud/#!install)

### Other packages

    apt install openssh-server rsync pwgen

And you should allow the CA to login to the IPSEC gateway via SSH without password. [https://blog.rothirsch.tech/security/#!secure-ssh](https://blog.rothirsch.tech/security/#!secure-ssh)


## Installation

1. Simply download the git repository

2. Copy the file central/templates/defaults.sh to _config_. The _config_ will not be overwritten by a git pull and is ignored in the .gitignore file

    cp central/templates/defaults.sh config

3. Create a new certificate authority

    ./createCA

4. Create, revoke, transfer, renew,.... 
Change into newly created directory in the directory companies/_youcompany_/_yourca_/

    ./manageCerts

