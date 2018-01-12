#!/usr/bin/env python

import pefile
import sys
import json
import subprocess
import numpy as np
import math
#sys.path.append('/root')
from filetype import *

result = {}
if len(sys.argv) < 2:
    result["stat"] = "error"
    result["messagetype"] = "string"
    result["message"] = "Usage: ./header.py INPUT_FILE"
    print json.dumps(result)
    exit(1)

Bin = [ x*10 for x in range(64)]
Bin.append(100000)
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

        strings = subprocess.check_output(["strings", name])
        l = [len(s) for s in strings.split('\n')[:-1]]
        hist, bins = np.histogram(l, bins=32)
        result["stat"] = "success"
        result["messagetype"] = "list"
        result["message"] = [ x for x in hist.astype(int) ]
    except Exception as e:
        result["stat"] = "error"
        result["messagetype"] = "string"
        result["message"] = e.message
    finally:
        print json.dumps(result)
