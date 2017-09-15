#!/bin/sh

./mba/x86_64-softmmu/qemu-system-x86_64 -m 2048 \
 -hda win10.qcow2 \
 -k en-us -monitor stdio -usb  \
 -net nic,model=rtl8139 -net user \
 -L ./mba \
 -loadvm ready 
