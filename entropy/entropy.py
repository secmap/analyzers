#!/usr/bin/env python

import sys
import os
import re

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
        filename, extension = os.path.splitext(name)
        if extension != '.bytes':
            raise Exception('Not .bytes file')
        
        with open(name, 'r') as fd:
            lines = fd.readlines()
        data = ''
        for line in lines:
            nums = re.findall('[0-9a-fA-F]+', line)[1:]
            data += ''.join([chr(int(x, 16)) if x != '??' else '\x00' for x in nums])
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
