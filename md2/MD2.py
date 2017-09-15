#!/usr/bin/python

import re
import sys
import json
import os
from os.path import realpath, dirname, join
from itertools import (takewhile, repeat)

HOME_DIR = dirname(realpath(__file__))

sys.path.append(HOME_DIR)
from filetype import * 

# Compose returned messages (in json format)
def json_msg_compose(stat, messagetype, message):
  return_msg = json.dumps({"stat" : stat, "messagetype" : messagetype, "message" : message})
  return return_msg 

# Count the number of lines in file 
def get_line_number(filename):
  try:
    with open(filename, 'rb') as f:
      bufgen = takewhile(lambda x: x, (f.read(1024*1024) for _ in repeat(None)))
      return sum(buf.count(b'\n') for buf in bufgen)
  except IOError as e:
    sys.stderr.write("Cannot open file exception: {0}".format(e))
    sys.exit()
  except KeyboardInterrupt as e:
    sys.stderr.write("Keyboard Interrupt")
    sys.exit()

if __name__ == '__main__':
  if len(sys.argv) != 2:
    sys.stderr.write("Wrong format for arguments")
    sys.exit()
  f = File(sys.argv[1])
  if not f.is_asm():
    sys.stdout.write(json_msg_compose("error", "string", "Not asm file"))
    sys.exit() 
  line_number = get_line_number(f.get_path())
  final_msg = json_msg_compose("success", "list", [f.size(), line_number])
  sys.stdout.write(final_msg)
