---
title: "Key Distribution Center"
domains: [hithlum]
functions: [security, certificate-management]
technologies: [strongswan, ipsec, python, docker, ssh]
status: active
maintainer: r9
last_updated: 2025-01-05
---

# Key distribution center

_Using strongswan ipsec pki, ssh, rsync, owncloud,..._

This project helps you manage your x.509 certificates created by the _ipsec pki_. The idea is that you install a separate server that serves as a Certificate Authority (CA). This server will be your highly confidential site. All created certificates are then sent to an IPSEC Gateway. There is also an owncloud instance installed for _Out of Band_ key distribution on this gateway. We use a combination of 2 [armbian](https://www.armbian.com/) devices but you can also use it with other linux distributions.

![Explanation](https://github.com/rothirschtec/RT-Blog-CA/blob/master/central/images/RT-Blog-CA-explained_linkedIn.png)

## Dependencies

First you have to build the latest strongswan version on both devices. [https://blog.rothirsch.tech/strongswan/](https://blog.rothirsch.tech/server_farm/configurations/strongswan/#!install).

If you want to set up the ipsec gateway you also have to install owncloud. [https://blog.rothirsch.tech/owncloud/](https://blog.rothirsch.tech/server_farm/configurations/owncloud/#!install)

### Other packages

    apt install openssh-server rsync pwgen

And you should allow the CA to login to the IPSEC gateway via SSH without password. [https://blog.rothirsch.tech/security/#!secure-ssh](https://blog.rothirsch.tech/security/#!secure-ssh)

## Installation

1. Simply clone the git repository

2. Initialise the environment using the Python tool

    ```bash
    python3 central/scripts/kdc.py create-ca --name myca --domain example.com --company "Example Ltd"
    ```

3. Issue certificates using the same tool

    ```bash
    python3 central/scripts/kdc.py create-cert myhost.example.com --ca-name myca --domain example.com --company "Example Ltd"
    ```

4. Inspect a certificate

    ```bash
    python3 central/scripts/kdc.py info STORE/certs/myhost.example.com.pem
    ```

The legacy shell scripts remain in `central/scripts` but the preferred entry
point is now the Python-based `kdc.py` utility.

## Python key manager (experimental)

An initial Python wrapper is available at `central/scripts/key_manager.py`.
It provides a small command line interface to create certificates and show
certificate information using the familiar `ipsec pki` backend.

Usage example:

```bash
python3 central/scripts/key_manager.py create myhost.example.com
python3 central/scripts/key_manager.py info STORE/certs/myhost.example.com.pem
```

## Docker

A `Dockerfile` is provided to run the certificate management tools in a container.

Build the image:

```bash
docker build -t kdc .
```

Run the CLI with persistent storage:

```bash
docker run --rm -it -v $(pwd)/data:/app/central/scripts/STORE kdc --help
```

## Big thanks to

- https://www.danballard.com/references/strongswan/www.zeitgeist.se/2013/11/22/strongswan-howto-create-your-own-vpn/index.html

- https://www.armbian.com

- https://strongswan.org

- and all other free and opensource software used for this project
