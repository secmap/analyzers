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
def get_address(filename):
  try:
    with open(filename, 'rb') as f:
      first_line = f.readline()
      match_address = re.match(r'[0-9a-fA-F]{8,}', first_line)
      if not match_address:
        return -1
      address = int(match_address.group(0), 16)
      return address
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
  if not f.is_hexdump():
    sys.stdout.write(json_msg_compose("error", "string", "Not hexdump file"))
    sys.exit() 
  address = get_address(f.get_path())
  if address == -1:
    sys.stdout.write(json_msg_compose("error", "string", "Wrong format for hexdump"))
    sys.exit() 
  final_msg = json_msg_compose("success", "list", [f.size(), address])
  sys.stdout.write(final_msg)
