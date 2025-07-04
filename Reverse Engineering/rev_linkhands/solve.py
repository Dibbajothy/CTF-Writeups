#!/usr/bin/env python3
from pwn import ELF, u64

# load the binary for its .data contents
e    = ELF('./link')
base = 0x404190

flag = b''
ptr  = base
while ptr != 0:
    # read the 8‐byte next pointer
    nxt = u64(e.read(ptr, 8))
    # read the flag‐character at offset +8
    flag += e.read(ptr + 8, 1)
    # advance
    ptr = nxt

print(flag.decode())
