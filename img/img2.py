#!/usr/bin/env python2

import mahotas
import mahotas.features
from mahotas.features.lbp import lbp
from math import log
import numpy as np
import sys
import numpy
import os
import json


def byte_image2(byte_code):
    img = byte_make_image(byte_code)
    spoints = lbp(img,10,10,ignore_zeros=False)
    return spoints.tolist()


def byte_make_image(byte_code):
    img_array=[]
    for row in byte_code:
        xx=row.split()
        if len(xx)!=17:
            continue
        img_array.append([int(i,16) if i!='??' else 0 for i in xx[1:] ])
    img_array = np.array(img_array)
    
    if img_array.shape[1]!=16:
        assert(False)
    b=int((img_array.shape[0]*16)**(0.5))
    b=2**(int(log(b)/log(2))+1)
    a=int(img_array.shape[0]*16/b)
    img_array=img_array[:a*b/16,:]
    img_array=np.reshape(img_array,(a,b))
    #img_array = np.uint8(img_array)
    #im = Image.fromarray(img_array)
    return img_array

if __name__ == '__main__':
    filepath = sys.argv[1]
    _, ext = os.path.splitext(filepath)
    if ext != '.bytes':
        result = {"stat": "error",
                "messagetype": "string",
                "message": 'Input file should be an .bytes file.'}
        print(json.dumps(result))
        sys.exit(-1)

    lines = open(filepath).readlines()
    features = byte_image2(lines)

    result = {"stat": "success",
          "messagetype": "list",
          "message": features}
    print(json.dumps(result))
