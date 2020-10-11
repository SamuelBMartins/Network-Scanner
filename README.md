# Network-Scanner
A network scanner written in python with data exfiltration

## General Info
The software gathers: hostname, UDP ports and TCP ports of the network and sends this information to a remote server. This server can be either a sftp server or a machine who's running `server.py`. The latter is better because the data is send through TCP on the port 443, that is used to avoid most firewalls.

**Note:** The software requires admin permissions because it creates smtp sockets.

## Setup

Run on the root of the project the following command in order to install dependecies:

```sh
pip install -r requirements.txt
```

## Usage

```sh
$ sudo python netScan.py -p <address 1>-<address 2> <ipserver>
```
* `<address 1>-<address 2>`: range ip (i.e. 192.168.1.1-192.168.1.255)
* `<ipserver>`: ip of the machine who is running `server.py` or the sftp server


## Features

  - ping scan
  - retrive hostname
  - TCP and UDP scan
  - send report through sftp server
  - send report through `server.py`


## Dependencies
This software utilizes the following dependencies:
* paramiko 2.7.1
* ping3 2.6.1

This software was tested with `python 3.8`, I can't guarantee the correct for other versions.

License
----

MPL-2.0 © Samuel Martins
