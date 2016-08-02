Ciphers2CSV
===============

**Ciphers2CSV** is a simple Python script to parse Nessus output files in XML format and extract supported SSL cipher suites from the raw output of SSL plugins to a single CSV spreadsheet which summarizes all supported ciphers and the affected hosts.

## Usage

Pass the XML Nessus output via a specified file. The resulted CSV spreadsheet is saved to a file (default is pssl-[timestamp].csv) and also displayed on the console.

### Options
```
$ python ciphers2csv.py -h
usage: ciphers2csv.py [-h] -i INPUT [-p PREFIX]

  ___ _      _               ___ ___ _____   __
 / __(_)_ __| |_  ___ _ _ __|_  ) __/ __\ \ / /
| (__| | '_ \ ' \/ -_) '_(_-</ / (__\__ \\ V /
 \___|_| .__/_||_\___|_| /__/___\___|___/ \_/
       |_|

      Parse SSL cipher from Nessus output

optional arguments:
  -h, --help  show this help message and exit
  -i INPUT    Nessus output file
  -p PREFIX   prefix for output file names (default pssl)
```

### Example output
```
Host,Port,Protocol,Key,Ciphers
example.com;3820;TLSv12;168;EDH-RSA-DES-CBC3-SHA,DES-CBC3-SHA,ECDHE-RSA-DES-CBC3-SHA
example.com;443;TLSv1;40;EXP-RC2-CBC-MD5,EXP-RC4-MD5
example.com;443;SSLv3;128;RC4-SHA,RC4-MD5
```
| Host        |  Port | Protocol |  Key  | Ciphers                           |
| ------------|:-----:|:--------:|:-----:|-----------------------------------|
| example.com |  443  |  TLSv12  |  168  | EDH-RSA-DES-CBC3-SHA,DES-CBC3-SHA |
| example.com |  443  |   TLSv1  |   40  | EXP-RC2-CBC-MD5,EXP-RC4-MD5       |
| example.com |  443  |   SSLv3  |  128  | RC4-SHA,RC4-MD5                   |

## License
This project is licensed under the terms of the MIT license.
