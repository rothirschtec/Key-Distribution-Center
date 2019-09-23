# Key management
_Using strongswan ipsec pki, ssh, rsync, owncloud,..._

This project helps you to manage your x.509 certificates created by the _ipsec pki_. The idea is, that you install a separated server that serves as a Certificate Authority. This server will be your highly confidential site. All certificates created are then send to an IPSEC Gateway. On this gateway is also an owncloud instance installed for _Out of Band_ key distribution. We use a combination of 2 [armbian](https://www.armbian.com/) devices but you can also use it on other linux distributions.


![Explanation](https://github.com/rothirschtec/RT-Blog-CA/blob/master/central/images/RT-Blog-CA-explained_linkedIn.png)


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

## Big thanks to

- https://www.danballard.com/references/strongswan/www.zeitgeist.se/2013/11/22/strongswan-howto-create-your-own-vpn/index.html
- https://www.armbian.com
- https://strongswan.org
- and all other free and opensource software used for this project
