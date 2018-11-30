#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# malcheck.py

__AUTHOR__ = "Josh Burgess"
__VERSION__ = "BETA"

import requests
from bs4 import BeautifulSoup
import configparser
import json
import sys
import argparse
import traceback
import hashlib
import os

BLUE, RED, WHITE, YELLOW, GREEN, END = "\33[94m", "\033[91m", "\33[97m", "\33[93m", "\033[32m", "\033[0m"

sys.stdout.write(RED + """

 ███▄ ▄███▓ ▄▄▄       ██▓     ▄████▄   ██░ ██ ▓█████  ▄████▄   ██ ▄█▀
▓██▒▀█▀ ██▒▒████▄    ▓██▒    ▒██▀ ▀█  ▓██░ ██▒▓█   ▀ ▒██▀ ▀█   ██▄█▒
▓██    ▓██░▒██  ▀█▄  ▒██░    ▒▓█    ▄ ▒██▀▀██░▒███   ▒▓█    ▄ ▓███▄░
▒██    ▒██ ░██▄▄▄▄██ ▒██░    ▒▓▓▄ ▄██▒░▓█ ░██ ▒▓█  ▄ ▒▓▓▄ ▄██▒▓██ █▄
▒██▒   ░██▒ ▓█   ▓██▒░██████▒▒ ▓███▀ ░░▓█▒░██▓░▒████▒▒ ▓███▀ ░▒██▒ █▄
░ ▒░   ░  ░ ▒▒   ▓▒█░░ ▒░▓  ░░ ░▒ ▒  ░ ▒ ░░▒░▒░░ ▒░ ░░ ░▒ ▒  ░▒ ▒▒ ▓▒
░  ░      ░  ▒   ▒▒ ░░ ░ ▒  ░  ░  ▒    ▒ ░▒░ ░ ░ ░  ░  ░  ▒   ░ ░▒ ▒░
░      ░     ░   ▒     ░ ░   ░         ░  ░░ ░   ░   ░        ░ ░░ ░
       ░         ░  ░    ░  ░░ ░       ░  ░  ░   ░  ░░ ░      ░  ░
                             ░                       ░
    """ + END)


parser = argparse.ArgumentParser()
parser.add_argument("-i", help="Specifies The Config File For Our API Keys")
parser.add_argument("-f", help="The File For Our Search")
args = parser.parse_args()

try:
    config = configparser.ConfigParser()
    config.read(args.i)
    VT_PUBLIC_API_KEY = config["DEFAULT"]["VT_PUBLIC_API_KEY"]
except Exception as e:
    traceback.print_exc()
    print("[?] Config file {} not found".format(args.i))

VT_REPORT_URL = "https://www.virustotal.com/vtapi/v2/file/report"

# Generates a SHA256 hash of the file.
def generate_hash(fname):
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
        "hash":         hash,
        "file_name":     "-",
        "other_names":    [],
        "file_type":     "-",
        "submit_date":   "-",
        "md5":           "-",
        "sha1":          "-",
        "sha256":        "-",
        "vendors":        {},
        "permalink":      "",
        "error":          False,
        "positives":      0,
        "total_score":    0,
        "harmful":        False,
        "rating":         GREEN + "Unknown" + END
    }

    try:
        vt_params = {"apikey": VT_PUBLIC_API_KEY, "resource": hash}
        vt_fetch_page = requests.get(VT_REPORT_URL, params=vt_params, timeout=5)
        vt_status_code = vt_fetch_page.status_code
        vt_fetch_page_json = vt_fetch_page.json()

        if vt_fetch_page_json.get("verbose_msg").startswith("Invalid"):
            file_info["error"] = True
            os.close(1)

        elif vt_status_code == 403:
            return "Permission denied. Do you have an valid API key?."

        elif vt_status_code == 200:
            file_info["md5"]          = str(vt_fetch_page_json.get("md5"))
            file_info["sha1"]         = str(vt_fetch_page_json.get("sha1"))
            file_info["sha256"]       = str(vt_fetch_page_json.get("sha256"))
            file_info["submit_date"]  = str(vt_fetch_page_json.get("scan_date"))
            file_info["permalink"]    = str(vt_fetch_page_json.get("permalink"))
            file_info["file_name"]    = args.f
            file_info["positives"]    = int(vt_fetch_page_json.get("positives"))
            file_info["total_score"]  = int(vt_fetch_page_json.get("total"))
            file_info["vendors"]      = {str(vend_name):str(result.get("result"))for vend_name, result in vt_fetch_page_json["scans"].items()}
            for vend_name, result in file_info["vendors"].items():
                if result == "None":
                    file_info["vendors"][vend_name] = "Unknown"
                else:
                    file_info["vendors"][vend_name] = str(result)

            if file_info["positives"] <= 5:
                file_info["rating"] = RED + "Suspicious" + END
                file_info["harmful"] = True

            elif file_info["positives"] > 5:
                file_info["rating"] = RED + "Malicious" + END
                file_info["harmful"] = True

            info = parsePermalink(file_info["permalink"])
            file_info.update(info)

            return file_info

        else:
            os.close(1)

    except requests.ConnectionError as e:
        print("OOPS!! Connection Error. Make sure you are connected to Internet. \
               Technical Details given below.\n")
        print(str(e))

    except requests.Timeout as e:
        print("OOPS!! Timeout Error")
        print(str(e))

    except requests.RequestException as e:
        print("OOPS!! General Error")
        print(str(e))


def parsePermalink(permalink):

    additional_info = {
        "other_names":   [],
        "file_type":     "",
        "comments":      [],
    }

    header = {"User-Agent": "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; en-US; rv:1.9.1b3) Gecko/20090305 Firefox/3.1b3 GTB5",
               "Referrer":   "https://www.virustotal.com/en/" }

    try:
        fetch_page = requests.get(permalink, headers=header, timeout=5)
        soup = BeautifulSoup(fetch_page.text, "html.parser")

        elements = soup.find_all("div")
        for i in elements:
            string = i.text.strip()
            if string.startswith("File type"):
                additional_info["file_type"] = str(string[10:])

        elements = soup.find_all("td")
        for i, row in enumerate(elements):
            text = row.text.strip()
            if text == "File names":
                file_names = elements[i + 1].text.strip().split("\n")
                additional_info["other_names"] = filter(None, map(lambda file:file.strip(), file_names))

    except requests.ConnectionError as e:
        print("OOPS!! Connection Error. Make sure you are connected to Internet. \
               Technical Details given below.\n")
        print(str(e))

    except requests.Timeout as e:
        print("OOPS!! Timeout Error")
        print(str(e))

    except requests.RequestException as e:
        print("OOPS!! General Error")
        print(str(e))


    finally:
        return additional_info

def parseResults():

    file_hash = generate_hash(args.f)
    vt_result = get_vt_info(file_hash)
    print("\n[+] Getting hash...")
    print("Hash: {}".format(file_hash))
    print("[+] Checking Virus Total...")

    if not vt_result["error"]:
        sys.stdout.write("""
[+] Sample has been reported, displaying results.
*--------------------------------------------------------------------------------*
* [{rating}]
*--------------------------------------------------------------------------------*
* Hashes
*--------------------------------------------------------------------------------*
* MD5:    {md5}
* SHA1:   {sha1}
* SHA256: {sha256}
*--------------------------------------------------------------------------------*
* Meta Data
*--------------------------------------------------------------------------------*
* File name: {file_name}
* Other names: {other_names}
*
* File type: {file_type}\n
* Submitted on:{submit_date}
*--------------------------------------------------------------------------------*
* Vendor Summary
*--------------------------------------------------------------------------------*
    """.format(**vt_result))
        if "Malicious" or "Suspicious" in vt_result["rating"]:
            for vendor_name, label in vt_result["vendors"].items():
                if label == "Unknown":
                    continue
                else:
                    sys.stdout.write("{0} : {1}".format(vendor_name, label))

    else:
        print("[-] Can't find anything on Virus Total; proceed with caution.")
        os.close(1)

if __name__ == "__main__":
    parseResults()
