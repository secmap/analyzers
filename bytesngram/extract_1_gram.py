#!/usr/bin/env python2
import json
from pe_parser import build_ngrams
import sys
import os


filename = sys.argv[1]
_, ext= os.path.splitext(filename)

if ext != '.bytes':
    result = {"stat": "error",
              "messagetype": "string",
              "message": 'Input file should be an .bytes file.'}
    print(json.dumps(result))
    sys.exit(-1)

if __name__ == '__main__':
    lines = open(filename).readlines()
    bytes_ = []
    for line in lines:
        items = line.split()[1:]
        for item in items:
            if item != '??':
                bytes_.append(int(item, 16))

    ngram = build_ngrams([bytes_], 1)
    features = [0] * 256
    for gram in ngram:
        key = gram[0]
        count = gram[1]
        features[key] = count

    result = {"stat": "success",
              "messagetype": "list",
              "message": features}

    print(json.dumps(result))
