#!/usr/bin/env python

"""
Ciphers2CSV is a simple Python script to parse Nessus output files in XML
format and extract supported SSL cipher suites from the raw output of SSL
plugins to a single CSV spreadsheet which summarizes all supported ciphers
and affected hosts.
"""

__description__ = 'Parse supported SSL cipher suites from Nessus output'
__author__ = 'Gabor Seljan'
__version__ = '0.1.1'
__date__ = '2016/11/02'

import re
import os
import time
import textwrap
import collections
import xml.etree.ElementTree as ET

from argparse import *
from nested_dict import nested_dict

banner = ("""
       ___ _      _               ___ ___ _____   __
      / __(_)_ __| |_  ___ _ _ __|_  ) __/ __\ \ / /
     | (__| | '_ \ ' \/ -_) '_(_-</ / (__\__ \\\\ V /
      \___|_| .__/_||_\___|_| /__/___\___|___/ \_/
            |_|

           Parse SSL cipher from Nessus output
""")

print(banner)

parser = ArgumentParser(
    formatter_class=RawDescriptionHelpFormatter,
    description=__doc__
)

parser.add_argument('-i', metavar='INPUT',
                    help='Nessus output file', required=True)
parser.add_argument('-p', metavar='PREFIX', default='pssl',
                    help='prefix for output file names (default pssl)')

args = parser.parse_args()

results = collections.defaultdict(nested_dict)

if not os.path.isfile(args.i) or not args.i.endswith('.nessus'):
    parser.print_help()
    print('\n[!] Nessus output file required...')
    exit(1)

root = ET.parse(args.i).getroot()
report = root.find('Report')
for host in report.findall('ReportHost'):
    name = host.get('name')
    for item in host.findall('ReportItem'):
        port = item.get('port')
        fname = item.find('fname').text
        if 'ssl' in fname and item.find('plugin_output') is not None:
            text = item.find('plugin_output').text
            for i in re.compile('^SSL Version : ', re.M).split(text):
                i = re.sub(' +', ' ', i.strip())

                match = re.search('(TLS|SSL)v\d{1,2}', i)
                if match:
                    protocol = match.group()

                for j in re.compile('\n').split(i):
                    key = ''
                    cipher = ''

                    match = re.search('(.*) Kx', j)
                    if match:
                        cipher = match.group(1)

                    match = re.search('\((\d*)\)\s*Mac', j)
                    if match:
                        key = match.group(1)

                    if key.strip() and cipher.strip():
                        if key not in results[name][port][protocol]:
                            results[name][port][protocol][key] = set()
                        results[name][port][protocol][key].update([cipher.strip()])

if results:
    timestamp = time.strftime("%Y%m%dT%H%M%S")
    filename = '{}-{}.csv'.format(args.p, timestamp)
    with open(filename, 'w') as f:
        header = ';'.join(['Host', 'Port', 'Protocol', 'Key', 'Ciphers'])
        f.write(header + '\n')
        print(header)
        for name, ports in results.items():
            for port, protocols in ports.items():
                for protocol, keys in protocols.items():
                    for key, ciphers in keys.items():
                        ciphers = ','.join(ciphers)
                        row = ';'.join([name, port, protocol, key, ciphers])
                        f.write(row + '\n')
                        print(row)
    print('[+] Results saved to {}'.format(f.name))
