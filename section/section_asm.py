#!/usr/bin/env python3

import re
import sys
import os
import json

filename = sys.argv[1]
_, ext = os.path.splitext(filename)

if ext != '.asm':
    result = {"stat": "error",
              "messagetype": "string",
              "message": 'Input file should be an .asm file.'}
    print(json.dumps(result))
    sys.exit(-1)


content = open(filename, 'r', encoding='utf-8', errors='ignore').readlines()
content = [l.rstrip() for l in content]

sections = {}

all_sec_size = 0

prev_sec = None
prev_addr = None
sec_start_addr = None
for line in content:
    idx = line.find(':')
    if idx == -1:
        continue
    address = int(line.split()[0].split(':')[1], 16)

    sec_name = line[: idx].lower().lstrip('.')
    if sec_name == 'header':
        continue

    if sec_name in sections:
        sections[sec_name]['lines'].append(line)
    else:
        sections[sec_name] = {'size': None, 'lines': []}
        sections[sec_name]['lines'].append(line)

    if 'Virtual size' in line:  # IDA Pro knows the section size
        sec_size = int(re.findall(
            r"Virtual size.*:.*\(\D*(\d+)\D*\)", line)[0])
        sections[sec_name]['size'] = sec_size
        all_sec_size += sec_size

    if sec_name != prev_sec:  # IDA Pro don't know the section size
        if sec_start_addr is not None and sections[prev_sec]['size'] is None:
            sec_size = prev_addr - sec_start_addr
            sections[prev_sec]['size'] = sec_size
            all_sec_size += sec_size
        sec_start_addr = address

    prev_addr = address
    prev_sec = sec_name

# For the last section
if sec_start_addr is not None and sections[sec_name]['size'] is None:
    sec_size = address - sec_start_addr
    sections[sec_name]['size'] = sec_size
    all_sec_size += sec_size

sec_name_linenum_ord = ['bss', 'data', 'edata',
                        'idata', 'rdata', 'rsrc', 'text', 'tls', 'reloc']
sec_name_por_ord = [None] * 15 + ['text', 'data', 'bss',
                                  'rdata', 'edata', 'idata', 'rsrc', 'tls', 'reloc']

features = [0] * 24
num_know_sec = 0
num_unknow_sec = 0
num_know_sec_line = 0
num_unknow_sec_line = 0
know_sec_size = 0
unknow_sec_size = 0
is_upx = 0

for sec_name, section in sections.items():
    # print(section.Name, hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRawData)
    if sec_name == 'header':
        continue
    elif sec_name in ['UPX0', 'UPX1', 'UPX2', 'UPX!', '.UPX0', '.UPX1', '.UPX2']:
        is_upx = 1

    is_unknow_sec = False
    # print(sec_name + ':' + str(section['size']) + ':' + str(len(section['lines'])))

    try:
        sec_linenum_ord = sec_name_linenum_ord.index(sec_name)
        sec_por_ord = sec_name_por_ord.index(sec_name)
    except ValueError:
        is_unknow_sec = True

    if is_unknow_sec:
        unknow_sec_size += section['size']
        num_unknow_sec_line += len(section['lines'])
        num_unknow_sec += 1
    else:
        num_of_line = len(section['lines'])
        features[sec_linenum_ord] = num_of_line
        features[sec_por_ord] = section['size'] / all_sec_size
        know_sec_size += section['size']
        num_know_sec += 1
        num_know_sec_line += len(section['lines'])

features[9] = num_know_sec + num_unknow_sec
features[10] = num_unknow_sec
features[11] = num_unknow_sec_line
features[12] = know_sec_size / (know_sec_size + unknow_sec_size)
features[13] = unknow_sec_size / (know_sec_size + unknow_sec_size)
features[14] = num_unknow_sec_line / (num_unknow_sec_line + num_know_sec_line)
features[15] = is_upx

result = {"stat": "success",
          "messagetype": "list",
          "message": features}

print(json.dumps(result))
