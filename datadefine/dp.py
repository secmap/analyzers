#!/usr/bin/env python

import pefile
import sys
import os
import json
import subprocess

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
    try:
        filename, extension = os.path.splitext(name)
        if extension != '.asm':
            raise Exception('Not .asm file')

        with open(name, 'r') as fd:
            data = fd.read()

        symbol = [' db ', ' dw ', ' dd ']
        array = [0]*3
        for idx, s in enumerate(symbol):
            array[idx] += data.count(s)

        result["stat"] = "success"
        result["messagetype"] = "list"
        result["message"] = array
    except Exception as e:
        result["stat"] = "error"
        result["messagetype"] = "string"
        result["message"] = e.message
    finally:
        print json.dumps(result)
