---
layout: post  
title: "Academy: Hack The Box Walkthrough"
date: 2021-02-28 08:49:11 +0000
last_modified_at: 2021-02-28 08:49:11 +0000
category: Walkthrough
tags: ["Hack The Box", Academy, retired, Linux, Easy]
comments: true
protect: false
image:
  feature: academy-htb-walkthrough.png
---

This post documents the complete walkthrough of Academy, a retired vulnerable [VM][1] created by [egre55][2] and [mrb3n][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Academy is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.215 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-11-13 07:37:27 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.215
Discovered open port 22/tcp on 10.10.10.215
Discovered open port 33060/tcp on 10.10.10.215
```

`33060/tcp` looks interesting. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80,33060 -A --reason 10.10.10.215 -oN nmap.txt
...
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 c0:90:a3:d8:35:25:6f:fa:33:06:cf:80:13:a0:a5:53 (RSA)
|   256 2a:d5:4b:d0:46:f0:ed:c9:3c:8d:f6:5d:ab:ae:77:96 (ECDSA)
|_  256 e1:64:14:c3:cc:51:b2:3b:a6:28:a7:b1:ae:5f:45:35 (ED25519)
80/tcp    open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://academy.htb/
33060/tcp open  mysqlx? syn-ack ttl 63
| fingerprint-strings:
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp:
|     Invalid message"
|_    HY000
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.91%I=7%D=11/13%Time=5FAE3D9F%P=x86_64-pc-linux-gnu%r(
SF:NULL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\x0b
SF:\x08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(HTTPO
SF:ptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RTSPRequest,9,"\x05\0\0\0\x0
SF:b\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSVer
SF:sionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSStatusRequestTCP,
SF:2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0f
SF:Invalid\x20message\"\x05HY000")%r(Help,9,"\x05\0\0\0\x0b\x08\x05\x1a\0"
SF:)%r(SSLSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x0
SF:1\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(TerminalServerCooki
SF:e,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TLSSessionReq,2B,"\x05\0\0\0\x0b\
SF:x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\
SF:"\x05HY000")%r(Kerberos,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SMBProgNeg,
SF:9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(X11Probe,2B,"\x05\0\0\0\x0b\x08\x05
SF:\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY
SF:000")%r(FourOhFourRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LPDString
SF:,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LDAPSearchReq,2B,"\x05\0\0\0\x0b\x
SF:08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"
SF:\x05HY000")%r(LDAPBindReq,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SIPOption
SF:s,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LANDesk-RC,9,"\x05\0\0\0\x0b\x08\
SF:x05\x1a\0")%r(TerminalServer,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NCP,9,
SF:"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRPC,2B,"\x05\0\0\0\x0b\x08\x05\x
SF:1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY00
SF:0")%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(WMSRequest,9,"\x05\0\
SF:0\0\x0b\x08\x05\x1a\0")%r(oracle-tns,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%
SF:r(ms-sql-s,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(afp,2B,"\x05\0\0\0\x0b\x
SF:08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"
SF:\x05HY000")%r(giop,9,"\x05\0\0\0\x0b\x08\x05\x1a\0");
```

Even `nmap` doesn't know for sure what 33060/tcp is! Anyway, let's put `academy.htb` into `/etc/hosts` and this is what the site looks like.

{% include image.html image_alt="e94e81ca.png" image_src="/12dcb370-8a2f-4b87-808a-0a9507221578/e94e81ca.png" %}

### Who am I?

I notice in the registration page there's a hidden field `roleid` with a value of `0`.

{% include image.html image_alt="38a5fc66.png" image_src="/12dcb370-8a2f-4b87-808a-0a9507221578/38a5fc66.png" %}

Suppose I change it to `1` like so I wonder what will happen?

{% include image.html image_alt="04e72953.png" image_src="/12dcb370-8a2f-4b87-808a-0a9507221578/04e72953.png" %}

Prior to this, I've already established that an Admin page exists at `/admin.php` with `wfuzz`.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 20 --hc 404 http://academy.htb/FUZZ
********************************************************
* Wfuzz 3.0.1 - The Web Fuzzer                         *
********************************************************

Target: http://academy.htb/FUZZ
Total requests: 4660

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000010:   403        9 L      28 W     276 Ch      ".hta"
000000496:   200        141 L    227 W    2633 Ch     "admin.php"
000000012:   403        9 L      28 W     276 Ch      ".htpasswd"
000000011:   403        9 L      28 W     276 Ch      ".htaccess"
000002129:   301        9 L      28 W     311 Ch      "images"
000002157:   200        76 L     131 W    2117 Ch     "index.php"
000003662:   403        9 L      28 W     276 Ch      "server-status"

Total time: 9.527834
Processed Requests: 4660
Filtered Requests: 4653
Requests/sec.: 489.0933
```

### Academy Launch Planner

Using the credentials (`dipshit:dipshit123`) I was able to log in to `/admin.php`.

{% include image.html image_alt="82e11c82.png" image_src="/12dcb370-8a2f-4b87-808a-0a9507221578/82e11c82.png" %}

Looks like we have ourselves a new virtual host to explore!

### What a mess!

This sure looks messy!

{% include image.html image_alt="7e4a67a9.png" image_src="/12dcb370-8a2f-4b87-808a-0a9507221578/7e4a67a9.png" %}

Scrolling down "**Environment & details**" we see `APP_KEY` for Laravel.

{% include image.html image_alt="96abec1e.png" image_src="/12dcb370-8a2f-4b87-808a-0a9507221578/96abec1e.png" %}

Armed with the `APP_KEY` we might be able to launch a Metasploit attack on the PHP Laravel Framework because that's what it looks like.

### PHP Laravel Framework - Token Unserialize Remote Command Execution

{% include image.html image_alt="d2de5603.png" image_src="/12dcb370-8a2f-4b87-808a-0a9507221578/d2de5603.png" %}

Bombs away...

## Foothold

And we have shell!

{% include image.html image_alt="5d7da8fa.png" image_src="/12dcb370-8a2f-4b87-808a-0a9507221578/5d7da8fa.png" %}

### Getting `user.txt`

During enumeration of `www-data`'s account, I notice the presence of other accounts.

```
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
egre55:x:1000:1000:egre55:/home/egre55:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mrb3n:x:1001:1001::/home/mrb3n:/bin/sh
cry0l1t3:x:1002:1002::/home/cry0l1t3:/bin/sh
mysql:x:112:120:MySQL Server,,,:/nonexistent:/bin/false
21y4d:x:1003:1003::/home/21y4d:/bin/sh
ch4p:x:1004:1004::/home/ch4p:/bin/sh
g0blin:x:1005:1005::/home/g0blin:/bin/sh
```

Surprisingly the file `user.txt` is in `cry0l1t3`'s home directory. I guess the next step is to find `cry0l1t3`'s password since `PasswordAuthentication` is set to `yes` in `/etc/ssh/sshd_config`.

It wasn't long before I found a password in `/var/www/html/academy/.env`.

{% include image.html image_alt="ace5f36d.png" image_src="/12dcb370-8a2f-4b87-808a-0a9507221578/ace5f36d.png" %}

Time to log in with the credentials (`cry0l1t3:mySup3rP4s5w0rd!!`).

{% include image.html image_alt="f6694ede.png" image_src="/12dcb370-8a2f-4b87-808a-0a9507221578/f6694ede.png" %}

Bam. And here's `user.txt`.

{% include image.html image_alt="5dc64365.png" image_src="/12dcb370-8a2f-4b87-808a-0a9507221578/5dc64365.png" %}

## Privilege Escalation

During enumeration of `cry0l1t3`'s account, I notice the account is in the `adm` group.

{% include image.html image_alt="a54fdba9.png" image_src="/12dcb370-8a2f-4b87-808a-0a9507221578/a54fdba9.png" %}

Maybe the next clue lies in the logs that only members of the `adm` group can access?

{% include image.html image_alt="e69ff359.png" image_src="/12dcb370-8a2f-4b87-808a-0a9507221578/e69ff359.png" %}

Hmm. Linux Audit System logs can contain juicy information!

### Linux Audit System

There's a reason why the logs can only be read by members of the `adm` group because `data` is encoded in hexadecimal.

{% include image.html image_alt="0a39ebd5.png" image_src="/12dcb370-8a2f-4b87-808a-0a9507221578/0a39ebd5.png" %}

Looks like we have `mrb3n`'s password. During enumeration of `mrb3n`'s account, I notice that `mrb3n` is able to `sudo` `/usr/bin/composer` as `root`.

{% include image.html image_alt="9a160919.png" image_src="/12dcb370-8a2f-4b87-808a-0a9507221578/9a160919.png" %}

### GTFOBins

Following the instructions on [`composer`](https://gtfobins.github.io/gtfobins/composer/) in GTFOBins, I was able to obtain a `root` shell.

{% include image.html image_alt="7bf94b29.png" image_src="/12dcb370-8a2f-4b87-808a-0a9507221578/7bf94b29.png" %}

### Getting `root.txt`

Getting `root.txt` with a `root` shell is trivial.

{% include image.html image_alt="06687553.png" image_src="/12dcb370-8a2f-4b87-808a-0a9507221578/06687553.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/297
[2]: https://www.hackthebox.eu/home/users/profile/1190
[3]: https://www.hackthebox.eu/home/users/profile/2984
[4]: https://www.hackthebox.eu/
