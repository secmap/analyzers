#!/usr/bin/python

import re
import sys
import json
import os
from os.path import realpath, dirname, join
import subprocess
from subprocess import PIPE


HOME_DIR = dirname(realpath(__file__))

sys.path.append(HOME_DIR)
from filetype import * 

# mode 0: obj, 1: ida
MODE = 0

REGISTER_OBJ = join(HOME_DIR, 'register_obj')
REGISTER_IDA = join(HOME_DIR, 'register_ida')

def json_msg_compose(stat, messagetype, message):
  return_msg = json.dumps({"stat" : stat, "messagetype" : messagetype, "message" : message})
  return return_msg 


def read_register_obj():
  try:
    register = []
    with open(REGISTER_OBJ, 'r') as f:
      for line in f.readlines():
        register.append(line.strip())
    return register
  except IOError as e:
    sys.stderr.write('ERROR: Cannot open file register_list')

def read_register_ida():
  try:
    register = []
    with open(REGISTER_IDA, 'r') as f:
      for line in f.readlines():
        register.append('\x20{0}'.format(line.strip()))
    return register
  except IOError as e:
    sys.stderr.write('ERROR: Cannot open file register_list')

# Disassemble file
def disassemble_shell(exec_file):
  process = subprocess.Popen(['objdump', '-d', exec_file], stdout=PIPE, stderr=PIPE)
  output = process.communicate()
  disassemble_result = output[0]
  return disassemble_result 

# Count register (objdump) 
def count_register_objdump(exec_file, register_list):
  result = [] 
  try:
    disassemble_result = disassemble_shell(exec_file) 
    for register in register_list:
      count = disassemble_result.count(register)
      result.append(count)
    return result
  except IOError as e:
    sys.stderr.write("Cannot open file exception: {0}".format(e))
    sys.exit()
  except KeyboardInterrupt as e:
    sys.stderr.write("Keyboard Interrupt")
  except Exception as e:
    sys.stderr.write("Exception: {0}".format(e))

# Count register (ida) 
def count_register_ida(asm_file, register_list):
  result = [] 
  try:
    for register in register_list:
      count = 0
      with open(asm_file, 'r') as f:
        for line in f.readlines():
          line = line.split(';')[0]
          count += line.count(register)
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


def main_obj(f):
  if not f.is_pe32():
    sys.stdout.write(json_msg_compose("error", "string", "Not executable file"))
    sys.exit()
  register_list = read_register_obj()
  result = count_register_objdump(f.get_path(), register_list)
  final_msg = json_msg_compose("success", "list", result)
  sys.stdout.write(final_msg)
 
def main_ida(f):
  if not f.is_asm():
    sys.stdout.write(json_msg_compose("error", "string", "Not asm file"))
    sys.exit() 
  register_list = read_register_ida()
  result = count_register_ida(f.get_path(), register_list)
  final_msg = json_msg_compose("success", "list", result)
  sys.stdout.write(final_msg)
    

if __name__ == '__main__':
  if len(sys.argv) != 2:
    sys.stderr.write("Wrong format for arguments")
    sys.exit()
  f = File(sys.argv[1])
  if MODE == 0: # objdump mode
    main_obj(f)
  elif MODE == 1:
    main_ida(f)
