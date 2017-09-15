#!/usr/bin/env python3

import pefile
import json
from subprocess import call
from capstone import *
import subprocess
import re
import sys
import os

filename = sys.argv[1]

try:
    pe = pefile.PE(filename)
except:
    result = {"stat": "error",
              "messagetype": "string",
              "message": "Not a PE file."}
    print(json.dumps(result))
    sys.exit(-1)
        

filesize = os.path.getsize(filename)

machine_types = dict([reversed(t) for t in pefile.machine_types])

if machine_types[pe.FILE_HEADER.Machine] == 'IMAGE_FILE_MACHINE_I386':
    md = Cs(CS_ARCH_X86, CS_MODE_32)
elif machine_types[pe.FILE_HEADER.Machine] == 'IMAGE_FILE_MACHINE_AMD64':
    md = Cs(CS_ARCH_X86, CS_MODE_64)
else:
    result = {"stat": "error",
              "messagetype": "string",
              "message": 'Unknow or unsupport architecture!'}
    print(json.dumps(result))
    sys.exit(-1)

sec_name_linenum_ord = ['bss', 'data', 'edata', 'idata', 'rdata', 'rsrc', 'text', 'tls', 'reloc']
sec_name_por_ord = [None] * 15 + ['text', 'data', 'bss', 'rdata', 'edata', 'idata', 'rsrc', 'tls', 'reloc']

features = [0] * 24
num_know_sec = 0
num_unknow_sec = 0
num_know_sec_line = 0
unknow_sec_disasm = []
know_sec_size = 0
unknow_sec_size = 0

for section in pe.sections:
    # print(section.Name, hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRawData)
    is_unknow_sec = False
    try:
        sec_name = section.Name.partition(b"\x00")[0].decode('utf-8')
        sec_linenum_ord = sec_name_linenum_ord.index(sec_name)
        sec_por_ord = sec_name_por_ord.index(sec_name)
    except ValueError:
        is_unknow_sec = True

    sec_data = section.get_data()

    if is_unknow_sec:
        for i in md.disasm(sec_data, pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress):
            unknow_sec_disasm.append("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        unknow_sec_size += section.SizeOfRawData
        num_unknow_sec += 1
    else:
        disasm = []
        for i in md.disasm(sec_data, pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress):
            disasm.append("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        num_of_line = len(disasm)
        features[sec_linenum_ord] = num_of_line
        features[sec_por_ord] = section.SizeOfRawData / filesize
        know_sec_size += section.SizeOfRawData
        num_know_sec += 1
        num_know_sec_line += len(disasm)

if len(unknow_sec_disasm) + num_know_sec_line == 0:
    result = {"stat": "error",
              "messagetype": "string",
              "message": 'Captone was unable to disassemble section content. Maybe it is a corrupted PE file.'}
    print(json.dumps(result))
    sys.exit(-1)

features[9] = num_know_sec + num_unknow_sec
features[10] = num_unknow_sec
features[11] = len(unknow_sec_disasm)
features[12] = know_sec_size / (know_sec_size + unknow_sec_size)
features[13] = unknow_sec_size / (know_sec_size + unknow_sec_size)
features[14] = len(unknow_sec_disasm) / (len(unknow_sec_disasm) + num_know_sec_line)

result = {"stat": "success",
          "messagetype": "list",
          "message": features}

print(json.dumps(result))
