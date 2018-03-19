#!/usr/bin/env python2.7
# -*- coding: utf-8 -*- 

__AUTHOR__ = 'Josh Burgess'
__VERSION__ = '0.1.1'

import requests
from bs4 import BeautifulSoup
import configparser
import json
import sys
import argparse
import traceback


VENDORS = ['McAfee', 'Microsoft', 'Malwarebytes', 'Symantec', 'BitDefender',
           'Kaspersky', 'Avast', 'ESET-NOD32', 'Webroot']

VT_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'


def VT_INFO(hash):

    params = {'apikey': VT_PUBLIC_API_KEY, 'resource': hash}
    
    """
    headers = {
         "Accept-Encoding": "gzip, deflate",
         "User-Agent" : "gzip,  My Python requests library example client or username"
        }
    """
    response = requests.get(VT_REPORT_URL, params=params).json()
    scans = response.get("scans")
    for vendor in VENDORS:
        if vendor in scans:
            print '{0} classifies this as malacious.\n'.format(vendor)
            print json.dumps(scans.get(vendor), indent=4) 
        else:
            pass

parser = argparse.ArgumentParser(description='Hello, World!')
parser.add_argument('-i', help='Specifies the .ini config file for our API keys', default='malsearch.ini')
args = parser.parse_args()


config = configparser.ConfigParser()
try:
    config.read(args.i) 
    VT_PUBLIC_API_KEY = str(config['DEFAULT']['VT_PUBLIC_API'])
except Exception as e:
    traceback.print_exc()
    print("[E] Config file '%s' not found" % args.i)

u_input = str(raw_input('Enter hash:\t'))
print VT_INFO(u_input)
