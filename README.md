# export-OpenVPN-userconf
Export a .ovpn configuration file

For modern Endian versions that use Python 3, use `export_userprofile_py3.py` instead of the original script. It requires Python 3.8 or later and PyYAML:

`python3 export_userprofile_py3.py --remote <VPN_PUBLIC_IP_OR_DNS>`

The original script remains unchanged. Its usage is shown below.

Copy the script on you Endian Appliance with scp (check Endian KB for this) and run it with

`python export_userprofile.py`

below an example:

```
root@EndianUTM:~ # python export_userprofile.py
1
Remark: X509+PSK
Instance name: UDP-1194
Listening on: *:1194
Protocol : udp
Network : bridged - GREEN
Device type : tap
Authentication : PSK

Select the instance ID 1
exporting client configuration, copy the output below

<ca>
-----BEGIN CERTIFICATE-----
MIIDajCCAlKgAwIBAgIJAM/KGO76ClUyMA0GCSqGSIb3DQEBCwUAMCwxCzAJBgNV
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
RmbSZ9L8PQjgJV4pMdk=
-----END CERTIFICATE-----
</ca>
client
nobind
persist-key
persist-tun
verb 2
ns-cert-type server
comp-lzo
resolv-retry infinite
auth-user-pass
remote 1.1.1.1
port 1194
dev tap
proto udp

```
