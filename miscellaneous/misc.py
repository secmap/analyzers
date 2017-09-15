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

keys = [" dd ",".data:",".dll",".exe",".idata:",".rdata:",".rsrc:",
    ".text:",".unisec","__cdecl","__clrcall","__ctype","__cxx",
    "__dllonexit","__fastcall","__imp_","__msg_","__stdcall",
    "__thiscall","add","address","align","alloc","arg_","astatus_",
    "attributes","bool","bp-based","byte","call","call    ds:",
    "callback","calloc","certfreecrlcontext","close","cmp","code",
    "code xref","collapsed","const","create","createtraceinstanceid",
    "critical","data xref","dec","descriptor","desired","destroy",
    "dll","dllentrypoint","ds:","ds:getpriorityclass","dwflags",
    "dword","dword_","dwprovtype","eax","ebp","ebx","ecx",
    "ehcookiexoroffset","endp","endtime","environment","error","esi",
    "esp","exception","extrn","failed","ffreep","file","finally",
    "flush","fmode","font","format","frame","free","fstp",
    "function chunk","gdi","global","gscookieoffset","handler","heap",
    "henhmetafile","hheap","hkey","hmodule","hwnd","icm","icode:",
    "idiv","import","imul","inc","init","insd","instancename","jle",
    "jmp","jnz","jumptable","jz","kernel","large","lea","load","loc_",
    "lpmem","lpvoid","lstrcata","malloc","memcpy","memory","meta",
    "microsoft","module","move","movsx","movzx","mutex","near","off_",
    "offset","operator new","outsd","pop","press ","private","proc",
    "properties","protected","ptr","public","push","push    ds:",
    "querytracew","qword","realloc","reg","rep","resource","retn",
    "rva","s u b r o u t i n e","sampletecriterface","scoperecord",
    "secur32.dll","security","short","size_t","sleep","software",
    "sp-analysis","src","starttime","status","std","std:","stosd",
    "strlen","struct","sub","sub_","switch","sysexit","system",
    "system32","szcontainer","szprovider","test","thread","throw",
    "tls","trace","user","var_","vftable","virtual","vlc_plugin_set",
    "void *","windows","winmain","xml"]
for idx, name in enumerate(sys.argv):
    if idx == 0:
        continue
    try:
        filename, extension = os.path.splitext(name)
        if extension != '.asm':
            raise Exception('Not .asm file')

        with open(name, 'r') as fd:
            data = fd.read()

        array = [0]*len(keys)
        for idx, s in enumerate(keys):
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
