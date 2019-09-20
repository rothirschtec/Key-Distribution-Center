# Certificate Authority

This project helps you to manage your x509 certificates created by the _ipsec pki_. The idea is, that you install a separated server that serves as a Certificate Authority. This server will be your highly confidential location. All certificates created are then send to an IPSEC Gateway. On this gateway is also a owncloud instance installed for _Out of Band_ key distribution.

## Dependencies

First you have to build the latest strongswan version on both devices. [https://blog.rothirsch.tech/strongswan/](https://blog.rothirsch.tech/server_farm/configurations/strongswan/#!install).

If you want to setup the ipsec gateway you have also to install owncloud. [https://blog.rothirsch.tech/owncloud/](https://blog.rothirsch.tech/server_farm/configurations/owncloud/#!install)

### Other packages

    apt install openssh-server rsync pwgen

And you should allow the CA to login to the IPSEC gateway via SSH without password. [https://blog.rothirsch.tech/security/#!secure-ssh](https://blog.rothirsch.tech/security/#!secure-ssh)


## Installation

1. Simply clone the git repository

2. Start the initialisation
   
    ./createCA 


3. Change into newly created directory  ***CAs/yourDomain/yourCA/*** and start

### Create

    # Create certificate
    ./cert-create
    # or with config
    ./cert-create CONFIGS/your.config.configs
    
### Revoke

    ./cert-revoke STORE/certs/your.cert.pem

### Transfer

    ./cert-transfer STORE/certs/your.cert.pem

### Show info

    ./cert-info STORE/certs/your.cert.pem

The scripts are all selfexplaining an create configuration files inside CONFIGS
