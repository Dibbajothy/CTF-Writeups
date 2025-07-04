#!/usr/bin/env python3
from pwn import ELF

# load the on-disk binary; pwntools will map VAs for us
elf  = ELF('./link')
# base = 0x404060
base = 0x404190

suffix = b''
# we know there are 14 more characters at +8, +0x18, +0x28, …, +0xd8
for i in range(25):
    addr = base + 8 + i*0x10
    print(f"addr: {hex(addr)}")
    # ELF.read() takes a virtual address, and returns the bytes
    suffix += elf.read(addr, 1)

print(suffix.decode())
