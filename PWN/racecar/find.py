from get_position import get_position
import time

def collect_flag():
    flag_parts = []
    
    # Try positions 12-19 which should cover the flag
    for i in range(12, 23):
        print(f"\nTrying position {i}...")
        part = get_position(i)
        if part:
            flag_parts.append(part)
        time.sleep(1)  # Add a delay between requests
    
    # Combine all parts
    flag = ''.join(flag_parts)
    print(f"\nCollected flag parts: {flag_parts}")
    print(f"Reconstructed flag: {flag}")

if __name__ == '__main__':
    collect_flag()