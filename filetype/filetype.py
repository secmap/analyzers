#!/usr/bin/env python
# pip install filemagic
import magic
import re
import os

class File:
  def __init__(self, path):
    self.path = path

  def get_path(self):
    return self.path  

  def mime_type(self):
    with magic.Magic(flags=magic.MAGIC_MIME_TYPE) as m:
      return m.id_filename(self.path)

  def type_info(self, short=True):
    with magic.Magic() as m:
      if short:
        s = m.id_filename(self.path)
        l = re.findall('[a-zA-Z0-9]+', s)
        return l[0]
      else:
        return m.id_filename(self.path)

  def is_pe(self):
    if "PE" in self.type_info():
      return True
    else:
      return False
  
  def is_pe32(self):
    if "PE32" in self.type_info():
      return True
    else:
      return False

  def is_pe64(self):
    if "PE64" in self.type_info():
      return True
    else:
      return False

  def is_upx(self):
    if "UPX compressed" in self.type_info(short=False):
      return True
    else:
      return False

  def is_asm(self):
    if re.search(r'.*\.asm$', self.path):
      return True
    else:
      return False

  def is_hexdump(self):
    if re.search(r'.*\.bytes', self.path):
      return True
    else:
      return False

  def size(self):
    return os.path.getsize(self.path)
