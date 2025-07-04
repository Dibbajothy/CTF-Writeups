from pwn import *

io = remote("94.237.121.185", 31580)

io.sendline(b"0xEr3n")
io.sendline(b"register_keyboard_notifier")
io.sendline(b"keycode_to_string")
io.sendline(b"/sys/kernel/debug/spyyy/keys")
io.sendline(b"6w00tw00t\n")

io.interactive()