#!/usr/bin/env python

import sys

#sys.path.append('/root')

from filetype import *
import numpy as np
import math, string
import json
from operator import add

def range_bytes (): return range(256)
def H(data, iterator=range_bytes):
    if not data:
        return 0
    entropy = 0
    for x in iterator():
        p_x = float(data.count(chr(x)))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy

result = {}
bins = ([i*(8.0/16.0) for i in range(17)], [i*(256.0/16.0) for i in range(17)])

if len(sys.argv) < 2:
    result["stat"] = "error"
    result["messagetype"] = "string"
    result["message"] = "Usage: ./entropy.py INPUT_FILE"
    print json.dumps(result)
    exit(1)

for idx, name in enumerate(sys.argv):
    if idx == 0:
        continue
    try:
        f = File(name)
        if not f.is_pe():
            raise Exception("Not Pe file")
        if f.is_upx():
            raise Exception("Upx packed")

        with open(name, 'r') as fd:
            data = fd.read()
        start = 0
        end = 1024
        hist_arr = [0]*256
        while end < len(data):
            l = []
            tmp = []
            window = data[start:end]
            en = H(window)
            for c in window:
                l.append(ord(c))
                tmp.append(en)
            start += 256
            end += 256
            hist, xbin, ybin = np.histogram2d(tmp, l, bins=bins)
            hist_arr = map(add, [x for sublist in hist.astype(int) for x in sublist], hist_arr)
        result["stat"] = "success"
        result["messagetype"] = "list"
        result["message"] = hist_arr
    except Exception as e:
        result["stat"] = "error"
        result["messagetype"] = "string"
        result["message"] = e.message
    finally:
        print json.dumps(result)
