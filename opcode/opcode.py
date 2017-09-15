#!/usr/bin/python

import re
import sys
import json
from itertools import takewhile, repeat
import subprocess
from subprocess import PIPE
import os
from os.path import realpath, dirname, join 

HOME_DIR = dirname(realpath(__file__))

sys.path.append(HOME_DIR)
from filetype import * 

OPCODE_LIST = join(HOME_DIR, 'opcode_list')
# MODE: 0: objdump, 1: ida
MODE = 1 

# Compose returned messages (in json format)
def json_msg_compose(stat, messagetype, message):
  return_msg = json.dumps({"stat" : stat, "messagetype" : messagetype, "message" : message})
  return return_msg 

# Read opcode list for objdump
def read_opcode_list_objdump():
  try:
    opcode = []
    with open(OPCODE_LIST, 'r') as f:
      for line in f.readlines():
        op = '\x09{0}\x20'.format(line.strip())
        opcode.append(op)
    return opcode
  except IOError as e:
    sys.stderr.write('ERROR: Cannot open file opcode_list')
    sys.exit()

# Read opcode list for ida 
def read_opcode_list_ida():
  try:
    opcode = []
    with open(OPCODE_LIST, 'r') as f:
      for line in f.readlines():
        op = '\x20{0}\x20'.format(line.strip())
        opcode.append(op)
    return opcode
  except IOError as e:
    sys.stderr.write('ERROR: Cannot open file opcode_list')
    sys.exit()


# Disassemble file
def disassemble_shell(exec_file):
  process = subprocess.Popen(['objdump', '-d', exec_file], stdout=PIPE, stderr=PIPE)
  output = process.communicate()
  disassemble_result = output[0]
  return disassemble_result 

# Count opcode
def count_opcode_objdump(exec_file, opcode_list):
  result = [] 
  try:
    disassemble_result = disassemble_shell(exec_file) 
    for opcode in opcode_list:
      count = disassemble_result.count(opcode)
      result.append(count)
    return result
  except IOError as e:
    sys.stderr.write("Cannot open file exception: {0}".format(e))
    sys.exit()
  except KeyboardInterrupt as e:
    sys.stderr.write("Keyboard Interrupt")
    sys.exit()
  except Exception as e:
    sys.stderr.write("Exception: {0}".format(e))
    sys.exit()


# Count opcode
def count_opcode_ida(asm_file, opcode_list):
  result = [] 
  try:
    for opcode in opcode_list:
      with open(asm_file, 'r') as f:
        count = 0
        for line in f.readlines():
          line = line.split(';')[0]
          count += line.count(opcode)
        result.append(count)
    return result
  except IOError as e:
    sys.stderr.write("Cannot open file exception: {0}".format(e))
    sys.exit()
  except KeyboardInterrupt as e:
    sys.stderr.write("Keyboard Interrupt")
    sys.exit()
  except Exception as e:
    sys.stderr.write("Exception: {0}".format(e))
    sys.exit()

if __name__ == '__main__':
  if len(sys.argv) != 2:
    sys.stderr.write("Wrong format for arguments")
    sys.exit()
  f = File(sys.argv[1])
  if MODE == 0: # objdump
    if not f.is_pe():
      sys.stdout.write(json_msg_compose("error", "string", "Not executable file"))
      sys.exit() 
    opcode_list = read_opcode_list_objdump()
    result = count_opcode_objdump(sys.argv[1], opcode_list)
    final_msg = json_msg_compose("success", "list", result)
    sys.stdout.write(final_msg)
  elif MODE == 1: # ida 
    if not f.is_asm():
      sys.stdout.write(json_msg_compose("error", "string", "Not asm file"))
      sys.exit() 
    opcode_list = read_opcode_list_ida()
    result = count_opcode_ida(sys.argv[1], opcode_list)
    final_msg = json_msg_compose("success", "list", result)
    sys.stdout.write(final_msg)
