#!/usr/bin/python3

import mmap
import os
import sys
import telnetlib
import time

#
# MikroTik Cloud Hosted Router Universal Unpatchable Jailbreak
#   By Pedro Ribeiro (@pedrib1337 | pedrib@gmail.com)
#   From Agile Information Security
#
# - What it does:
#   1) Uses virsh to save a running MikroTik Cloud Hosted Router (CHR) virtual machine to disk
#   2) Finds a specific reference to /nova/bin/login (MikroTik's restricted shell, which is what you 
#   get when you login via telnet or SSH) and replaces it with our own binary that invokes /bin/sh
#
# - Tested on:
#   Cloud Hosted Router 6.47.10
#   Cloud Hosted Router 7.3.1
#
# - Prerequisites:
#   1) MikroTik CHR running on KVM (with virsh command line)
#       1.1) VM has to be booted, and you have had to go through initial setup
#   2) The following statically built binaries for x86:
#       2.1) "exec" (see below for source code) in /rw/disk/exec
#       2.2) "busybox" in /rw/disk/busybox, with your favourite symlinks (ls, id, etc)
#
# - Uploading /rw/disk/exec:
#   1) gcc -m32 -o exec -static exec.c
#   2) sudo guestmount -a chr-6.47.10.img -m /dev/sda1 /mnt/misc/
#       2.1) NOTE: on 7.x versions, use /dev/sda2 instead
#   3) cp exec /mnt/misc/rw/disk/exec
#   4) chmod +x /mnt/misc/rw/disk/exec && sudo umount /mnt/misc
#   5) Repeat the steps above for busybox (and don't forget those symlinks!)
#
# - A few notes:
#   Step 4) in the instructions above (making it executable) is the reason the upload cannot be done with the Web UI. 
#   Web UI uploads do not make the file executable...
#   Since we are patching /nova/bin/login in memory, the new executable name cannot have more than 14 characters. 
#   It can have less, but has to be padded to 14 chars to work.
#
#   THIS IS NOT A PERMANENT ROOT! You have to run it every time you reboot your VM. 
# 
# - "exec" file:
#include <unistd.h>
#int main() {
#  char* argv[] = { "sh", 0 };
#  execve("/rw/disk/busybox", argv, 0);
#}
# 
# - Typical run:
# mikrotik > ./mikrotik_jailbreak.py MikroTik_CHR_7.3.1 10.9.8.12 PASSWORD
# [*] Logging in 10.9.8.12 via telnet to prep patch
# [*] Saving VM
#
# Domain 'MikroTik_CHR_7.3.1' saved to mikrotik.save
#
# [*] Running sudo to chmod 777 memory file so we can patch it
# [+] Found patch target at location 0x3063847
# [+] Patch successful!
# [*] Restoring VM
# Domain restored from mikrotik.save
#
# [+] Finished, enjoy Shelly!
# Trying 10.9.8.12...
# Connected to 10.9.8.12.
# Escape character is '^]'.
# / # export PATH=$PATH:/rw/disk/
# / # id
# uid=0 gid=0
# / # uname -a
# Linux MikroTik 5.6.3-64 #1 SMP Thu Jun 9 09:18:50 UTC 2022 x86_64 GNU/Linux
# / #  
#
#
# Enjoy your shell!

SAVEFILE = "mikrotik.save"

def telnet_prep(host, admin_pass):
    tn = telnetlib.Telnet(host)
    tn.read_until(b"Login: ")
    tn.write("admin".encode('ascii') + b"\n")
    tn.read_until(b"Password: ")
    if admin_pass != '':
        tn.write(admin_pass.encode('ascii') + b"\n")
    else:
        tn.write(b"\n")
    time.sleep(1)
    tn.write("quit".encode('ascii') + b"\n")

def patch_mem():
    with open(SAVEFILE, 'r+b') as file, \
            mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
            loc = mm.find(b"(/nova/bin/login")
            if loc != -1:
                print("[+] Found patch target at location %s" % (hex(loc)))
                mm.seek(loc)
                mm.write(b"(/rw/disk/exec\x00\x00")
                print("[+] Patch successful!")
            else:
                print("[-] Patch failed, couldn't find (/nova/bin/login")

print("MikroTik Cloud Hosted Router Universal Unpatchable Jailbreak")
print("  By Pedro Ribeiro (@pedrib1337 | pedrib@gmail.com) from Agile Information Security")
print("")
print("Usage: ./mikrotik_jailbreak.py <VIRSH_DOMAIN> <HOST> <ADMIN_PASS>")
print("  Check script code for information on prerequisites")
print("")

if len(sys.argv) < 4:
    sys.exit()
else:
    domain = sys.argv[1]
    host = sys.argv[2]
    admin_pass = sys.argv[3]

print("[*] Logging in %s via telnet to prep patch" % (host))
telnet_prep(host, admin_pass)

print("[*] Saving VM")
os.system("virsh save --domain %s %s" % (domain, SAVEFILE))
time.sleep(1)
print("[*] Running sudo to chmod 777 memory file so we can patch it")
os.system("sudo chmod 777 %s" % (SAVEFILE))
patch_mem()

print("[*] Restoring VM")
os.system("virsh restore --file %s" % (SAVEFILE))
time.sleep(1)
os.unlink(SAVEFILE)

time.sleep(5)
print("[+] Finished, enjoy Shelly!")
os.system("telnet %s" % (host))
