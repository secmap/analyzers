#!/usr/bin/env python

import pefile
import sys
import json
import hashlib
#sys.path.append('/root')
from filetype import *

result = {}
if len(sys.argv) < 2:
    result["stat"] = "error"
    result["messagetype"] = "string"
    result["message"] = "Usage: ./header.py INPUT_FILE"
    print json.dumps(result)
    exit(1)

for idx, name in enumerate(sys.argv):
    if idx == 0:
        continue
    #print 'File:',name
    try:
        f = File(name)
        if not f.is_pe():
            raise Exception("Not Pe file")
        if f.is_upx():
            raise Exception("Upx packed")

        pe = pefile.PE(name, fast_load=True)
        pe.parse_data_directories()
        array = [0]*256

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                array[(int(hashlib.md5(str((entry.dll, imp.name))).hexdigest(), 16)%256)] += 1
        result["stat"] = "success"
        result["messagetype"] = "list"
        result["message"] = array
    except Exception as e:
        result["stat"] = "error"
        result["messagetype"] = "string"
        result["message"] = e.message
    finally:
        print json.dumps(result)
