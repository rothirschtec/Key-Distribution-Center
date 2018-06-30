# New certificate

Attached you can find a _.zip_archive which includes a new certificate for the VPN connection of your company.

## Install certificate

Please use the *windows_install_cert.bat* for the installation of the certificate

## First configuration

If you are a Windows user and you have no connection configured at the moment please open the _Network and Sharing Center_

    Win + R
    control.exe /name Microsoft.NetworkandSharingCenter

https://wiki.strongswan.org/projects/strongswan/wiki/Win7Config

## Increase security with AES-256-CBC and MODP2048

    Win + R
    regedit

Add following DWORD and set its value to 2

    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Rasman\Parameters\NegotiateDH2048_AES256

The values that can be used are 0, 1 or 2. The table tells you what the values mean.

value       | meaning
------------|--------------------------------------------------
0 (default) | disable AES-256-CBC and MODP-2048
1           | Enable AES-256-CBC and MODP-2048
2           | Enforce the usage of AES-256-CBC and MODP-2048 


