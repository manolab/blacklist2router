#!/usr/bin/python3
# bl2r.py

from urllib.request import Request, urlopen
from urllib.error import URLError

import napalm
import sys
import os

from napalm import get_network_driver
ios_driver = get_network_driver('ios')
iosxr_driver = get_network_driver('iosxr')

iplist = []
iplistnew = []

#leggi il file riga per riga e appendi
if len(sys.argv) > 1:
    fn = str(sys.argv[1])
    try:
        fp = open(fn, 'r')
    except OSError:
        print("Could not open/read file: ", fn)
        sys.exit()
    else:
        for line in fp:
            iplist.append(line.strip('\n').strip('\r'))
    finally:    
        fp.close()

req = [ Request('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt'), Request('https://www.spamhaus.org/drop/drop.txt') ]

for y in req:
    try:
        response = urlopen(y)
    except URLError as e:
        if hasattr(e, 'reason'):
            print('We failed to reach a server.')
            print('Reason: ', e.reason)
        elif hasattr(e, 'code'):
            print('The server couldn\'t fulfill the request.')
            print('Error code: ', e.code)
    else:
        # everything is fine
        for z in response.read().decode('ascii').splitlines():
            if not (z.startswith('#') or z.startswith(';')):
                pv = z.find(';')
                if pv > 0:
                    iplist.append(z[:pv - 1])
                else:
                    iplist.append(z)

# print (iplist)
# metto wildcard
wc = { '8': '0.255.255.255',
        '9': '0.127.255.255',
        '10': '0.63.255.255',
        '11': '0.31.255.255',
        '12': '0.15.255.255',
        '13': '0.7.255.255',
        '14': '0.3.255.255',
        '15': '0.1.255.255',
        '16': '0.0.255.255',
        '17': '0.0.127.255',
        '18': '0.0.63.255',
        '19': '0.0.31.255',
        '20': '0.0.15.255',
        '21': '0.0.7.255',
        '22': '0.0.3.255',
        '23': '0.0.1.255',
        '24': '0.0.0.255',
        '25': '0.0.0.127',
        '26': '0.0.0.63',
        '27': '0.0.0.31',
        '28': '0.0.0.15',
        '29': '0.0.0.7',
        '30': '0.0.0.3' }
for z in iplist:
    slash = z.find('/')
    if slash > 0:
        temp = z[:slash] + ' ' + wc[ z[slash+1:] ]
        iplistnew.append(temp)
    else:
        iplistnew.append('host '+z)



candidata = 'ip access-list standard BLOCKLIST\n'
for z in iplistnew:
    candidata = candidata + 'deny ' + z + '\n'
candidata = candidata + 'permit any'

print(candidata)
sys.exit()

optional_args = {'transport': 'ssh'}
device = ios_driver(
    hostname='192.168.1.1',
    username='napalm',
    password='grandeguerra')
device.open()
#
device.load_replace_candidate(config=candidata)
device.compare_config()
device.discard_config()
#
device.close()
