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
import hashlib
import os

BLUE, RED, WHITE, YELLOW, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[32m', '\033[0m'

# Banner here

# Sets our arguments 
parser = argparse.ArgumentParser()
parser.add_argument('-i', help='Specifies the config file for our API keys')
parser.add_argument('-f', help='The file for our search')
parser.add_argument('--csv', help='Writes to CSV')
args = parser.parse_args()

try:
    config = configparser.ConfigParser()
    config.read(args.i)
    VT_PUBLIC_API_KEY = config['DEFAULT']['VT_PUBLIC_API_KEY']
except Exception as e:
    traceback.print_exc()
    print("[?] Config file '%s' not found" % args.i)


# Virus Total Report URL
VT_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'

# Get hash from file
def getHash(fname):
    with open(fname, "rb") as fn:
        sha256 = hashlib.sha256()
        while True:
            data = fn.read(8192)
            if not data:
                break
            sha256.update(data)
        return sha256.hexdigest()

def get_vt_info(hash):
    file_info = {
        'hash':         hash, # hash we have used for scanning
        'file_name':     '-', # filename of scanned file
        'other_names':    [], # Other filenames used in wild etc.
        'file_type':     '-', # pdf or exe?
        'submit_date':   '-', # date of VT submission
        'md5':           '-', 
        'sha1':          '-',
        'sha256':        '-',
        'vendors':        {},
        'permalink':      '',
        'error':          False

    }
    
    params = {'apikey': VT_PUBLIC_API_KEY, 'resource': hash}
    vt_response = requests.get(VT_REPORT_URL, params=params)
    vt_status_code = vt_response.status_code
    vt_response_json = vt_response.json()

    # Check to see if hash has already been scanned.
    if vt_response_json.get("verbose_msg").startswith('Invalid'):
        file_info['error'] = True
        os.close(0)
    
    elif vt_status_code == 403:
        return "Permission denied. Do you have an valid API key?."
        
    elif vt_status_code == 200:
        file_info['md5']          = str(vt_response_json.get('md5'))
        file_info['sha1']         = str(vt_response_json.get('sha1'))
        file_info['sha256']       = str(vt_response_json.get('sha256'))
        file_info['submit_date']  = str(vt_response_json.get('scan_date'))
        file_info['permalink']    = str(vt_response_json.get('permalink'))
        file_info['file_name']    = args.f
        file_info['vendors']      = {str(vend_name):str(result.get('result')) for vend_name, result  in vt_response_json['scans'].items()}

        # Parse permalink for more info.
        info = parsePermalink(file_info['permalink'])
        file_info.update(info)
        return file_info

def parsePermalink(permalink):
    additional_info = {
        'other_names':   [],
        'file_type':     '',
        'comments':      [], 
    }
    
    header = {'User-Agent': 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; en-US; rv:1.9.1b3) Gecko/20090305 Firefox/3.1b3 GTB5',
               'Referrer':   'https://www.virustotal.com/en/' }

    try:
        response = requests.get(permalink, headers=header)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Get file type
        elements = soup.find_all('div')
        for i in elements:
            string = i.text.strip()
            if string.startswith('File type'):
                additional_info['file_type'] = str(string[10:])

        # Get other names
        elements = soup.find_all('td')
        for i, row in enumerate(elements):
            text = row.text.strip()
            if text == "File names":
                file_names = elements[i + 1].text.strip().split("\n")
                additional_info['other_names'] = filter(None, map(lambda file: file.strip(), file_names))

    except Exception as e:
        traceback.print_exc()

    finally:
        return additional_info
    
def parseResults():

    fhash = getHash(args.f)
    vt_result = get_vt_info(fhash)

    print "[+] Getting hash..."
    print "Hash:{}".format(fhash)
    print "[+] Checking Virus Total..."

    if not vt_result['error']:
        print "[+] Sample has been reported, displaying results..."
        

        print """
        *--------------------------------------------------------------------------------
        * Hashes
        *--------------------------------------------------------------------------------
        * MD5:    {0}
        * SHA1:   {1}
        * SHA256: {2}
        *--------------------------------------------------------------------------------
        *

        """.format(vt_result['md5'], vt_result['sha1'], vt_result['sha256'])

    else:
        print "[-] Can't find anything on Virus Total; proceed with caution." 
        os.close(0)
    
print parseResults()


