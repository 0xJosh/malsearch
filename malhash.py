#!/usr/bin/env python2.7

__AUTHOR__ = 'Josh Burgess' 
__VERSION__ = '0.1.1'

import os
import hashlib
import traceback

def genHash(filename):
    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        md5.update(filename)
        sha1.update(filename)
        sha256.update(filename)
        hashes = {'md5': md5.hexdigest(), 'sha1': sha1.hexdigest(), 'sha256':
                   sha256.hexdigest()} 
    except Exception as e:
        traceback.print_exc()
    finally:
        return hashes



for file in os.listdir("./vault"):
    if file.endswith(".exe"):
        list_of_hashes = genHash(file)
        print "\n+" + "-" * 85
        print "\n{0}\n".format(file)
        for key, value in list_of_hashes.items():
            print "{0} : {1}\n".format(key, value)
